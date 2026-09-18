package api_test

// §12.7 account erasure: the published-content chooser is explicit, and
// `transfer` actually transfers. Before this, the disposition defaulted to
// "yank", which made the explicit-choice guard dead code — a user deleting
// their account silently pulled their published packages out from under
// everyone who had installed them.

import (
	"context"
	"net/http"
	"testing"
)

// publishUnder creates a public agent in the caller's personal namespace and
// publishes one version, returning nothing but a published fixture.
func (env *testEnv) publishUnder(t *testing.T, sess caller, ns, name string) {
	t.Helper()
	env.doJSON(sess, http.MethodPost, "/api/v1/agents", map[string]any{
		"namespace": ns, "name": name, "modes": []string{"autonomous"}, "visibility": "public",
	}, nil, http.StatusCreated)
	_, pat := env.mintPAT(sess, "pub-"+name, "agent:publish", "agent:read")
	status, body := env.uploadVersionCLI(ns, name, pat, skillFiles(ns, name, "1.0.0", nil))
	if status != http.StatusAccepted {
		t.Fatalf("publish %s: %d %s", name, status, body)
	}
	env.waitStatus(ns, name, "1.0.0", "published")
}

func TestErasureRequiresAnExplicitDisposition(t *testing.T) {
	env := newTestEnv(t)
	user := env.register("era-req")
	env.verifyEmail(user)
	sess := env.login(user)
	env.publishUnder(t, sess, user, "published-thing")

	res := env.do(sess, http.MethodPost, "/api/v1/user/delete", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("erasure with published content and no disposition: got %d want 400", res.StatusCode)
	}

	// The account must still be intact — a refused erasure erases nothing.
	res = env.do(sess, http.MethodGet, "/api/v1/user", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("session after a refused erasure: got %d want 200", res.StatusCode)
	}
}

func TestErasureWithNothingPublishedNeedsNoChoice(t *testing.T) {
	env := newTestEnv(t)
	user := env.register("era-none")
	env.verifyEmail(user)
	sess := env.login(user)
	// No published content: there is nothing to choose between.
	env.doJSON(sess, http.MethodPost, "/api/v1/user/delete", nil, nil, http.StatusNoContent)
}

func TestErasureYankPath(t *testing.T) {
	env := newTestEnv(t)
	user := env.register("era-yank")
	env.verifyEmail(user)
	sess := env.login(user)
	agentName := "yankable-" + env.sfx
	env.publishUnder(t, sess, user, agentName)

	env.doJSON(sess, http.MethodPost, "/api/v1/user/delete?publishedContent=yank", nil, nil, http.StatusNoContent)

	var status, digest string
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT av.status, coalesce(av.archive_digest, '') FROM agent_versions av
		 JOIN agents a ON a.id = av.agent_id WHERE a.name = $1`, agentName).Scan(&status, &digest); err != nil {
		t.Fatal(err)
	}
	if status != "yanked" {
		t.Fatalf("version status = %s, want yanked", status)
	}
	if digest == "" {
		t.Fatal("the digest was cleared — installed copies could no longer verify")
	}
}

func TestErasureTransferPath(t *testing.T) {
	env := newTestEnv(t)
	user := env.register("era-tx")
	env.verifyEmail(user)
	sess := env.login(user)
	orgH := "eraorg" + env.sfx
	orgID := env.createOrg(sess, orgH)
	agentName := "transferable-" + env.sfx
	env.publishUnder(t, sess, user, agentName)

	env.doJSON(sess, http.MethodPost,
		"/api/v1/user/delete?publishedContent=transfer&transferOrg="+orgH, nil, nil, http.StatusNoContent)

	// The agent now lives in the org, and its version is STILL published —
	// that is the whole point of choosing transfer over yank.
	var ns, status string
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT h.handle::text, av.status FROM agents a
		 JOIN handles h ON h.id = a.namespace_id
		 JOIN agent_versions av ON av.agent_id = a.id
		 WHERE a.name = $1`, agentName).Scan(&ns, &status); err != nil {
		t.Fatal(err)
	}
	if ns != orgH {
		t.Fatalf("agent namespace = %s, want %s", ns, orgH)
	}
	if status != "published" {
		t.Fatalf("transferred version status = %s, want published", status)
	}

	// The transfer is audited against the receiving org.
	var n int64
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM audit_events WHERE action = 'agent.transfer' AND org_id = $1`, orgID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("no agent.transfer audit event for the receiving org")
	}

	// And the account is erased regardless of the disposition chosen.
	res := env.do(sess, http.MethodGet, "/api/v1/user", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("session after erasure: got %d want 401", res.StatusCode)
	}
}

func TestErasureTransferTargetIsValidated(t *testing.T) {
	env := newTestEnv(t)
	// The org and its owner.
	orgOwner := env.register("era-oo")
	env.verifyEmail(orgOwner)
	ownerSess := env.login(orgOwner)
	orgH := "eravorg" + env.sfx
	env.createOrg(ownerSess, orgH)

	// A member who does NOT administer it.
	member := env.register("era-mem")
	env.verifyEmail(member)
	env.joinOrg(ownerSess, orgH, member, "member")
	memberSess := env.login(member)
	agentName := "member-thing-" + env.sfx
	env.publishUnder(t, memberSess, member, agentName)

	cases := []struct {
		name, query string
		want        int
	}{
		{"transfer needs a destination", "?publishedContent=transfer", http.StatusBadRequest},
		{"unknown org", "?publishedContent=transfer&transferOrg=nosuchorg" + env.sfx, http.StatusNotFound},
		{"plain membership is not enough", "?publishedContent=transfer&transferOrg=" + orgH, http.StatusForbidden},
	}
	for _, c := range cases {
		res := env.do(memberSess, http.MethodPost, "/api/v1/user/delete"+c.query, nil)
		_ = res.Body.Close()
		if res.StatusCode != c.want {
			t.Fatalf("%s: got %d want %d", c.name, res.StatusCode, c.want)
		}
	}

	// Nothing moved and nothing was erased by any of the refusals.
	var ns string
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT h.handle::text FROM agents a JOIN handles h ON h.id = a.namespace_id WHERE a.name = $1`, agentName,
	).Scan(&ns); err != nil {
		t.Fatal(err)
	}
	if ns != member {
		t.Fatalf("agent moved on a refused transfer: namespace = %s", ns)
	}

	// An admin of the org can transfer into it.
	env.doJSON(ownerSess, http.MethodPut, "/api/v1/orgs/"+orgH+"/members/"+member,
		map[string]any{"role": "admin"}, nil, http.StatusOK) // a role change, not an add
	memberSess = env.login(member)
	env.doJSON(memberSess, http.MethodPost,
		"/api/v1/user/delete?publishedContent=transfer&transferOrg="+orgH, nil, nil, http.StatusNoContent)
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT h.handle::text FROM agents a JOIN handles h ON h.id = a.namespace_id WHERE a.name = $1`, agentName,
	).Scan(&ns); err != nil {
		t.Fatal(err)
	}
	if ns != orgH {
		t.Fatalf("admin transfer did not move the agent: namespace = %s", ns)
	}
}
