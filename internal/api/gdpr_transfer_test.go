package api_test

// Account erasure: the published-content chooser is explicit, and
// `transfer` actually transfers. A disposition that defaulted to "yank"
// would make the explicit-choice guard dead code: a user deleting
// their account would silently pull their published packages out from
// under everyone who had installed them.

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/entitlements"
)

// orgPrivateCap is the core resolver with a cap on the private agents an
// organization may hold.
type orgPrivateCap struct {
	entitlements.Resolver
	max int64
}

func (c orgPrivateCap) Features(ctx context.Context, s entitlements.Subject) (entitlements.Features, error) {
	f, err := c.Resolver.Features(ctx, s)
	if s.Kind == entitlements.NamespaceOrg {
		f.PrivateAgents = entitlements.Cap{Enabled: true, Max: c.max}
	}
	return f, err
}

// namespaceOf answers the handle of the namespace an agent is in.
func (env *testEnv) namespaceOf(agent string) string {
	env.t.Helper()
	var ns string
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT h.handle::text FROM agents a JOIN handles h ON h.id = a.namespace_id WHERE a.name = $1`, agent).Scan(&ns); err != nil {
		env.t.Fatal(err)
	}
	return ns
}

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
	uid := env.selfID(sess)
	// No published content: there is nothing to choose between.
	env.doJSON(sess, http.MethodPost, "/api/v1/user/delete", nil, nil, http.StatusNoContent)
	// With nothing published the default disposition is the one recorded.
	var n int
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM audit_events WHERE action = 'user.delete' AND target_id = $1 AND detail->>'publishedContent' = 'yank' AND detail->>'publishedVersions' = '0' AND detail->>'versionsYanked' = '0'`,
		uid).Scan(&n); err != nil || n != 1 {
		t.Fatalf("user.delete rows recording the default disposition: %d (%v), want 1", n, err)
	}
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
	uid := env.selfID(sess)
	orgH := "eraorg" + env.sfx
	orgID := env.createOrg(sess, orgH)
	agentName := "transferable-" + env.sfx
	env.publishUnder(t, sess, user, agentName)
	// The organization keeps an admin when its founder goes:
	// the erasure is refused until another is in place.
	res0 := env.do(sess, http.MethodPost, "/api/v1/user/delete?publishedContent=transfer&transferOrg="+orgH, nil)
	if code, slug, _ := problemOf(t, res0); code != http.StatusConflict || slug != "last-admin" {
		t.Fatalf("erasing the organization's only admin: %d %s, want 409 last-admin", code, slug)
	}
	successor := env.register("era-succ")
	env.joinOrg(sess, orgH, successor)
	env.doJSON(sess, http.MethodPut, "/api/v1/orgs/"+orgH+"/members/"+successor,
		map[string]any{"role": "admin"}, nil, http.StatusOK)

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
	// The erasure's own row names the organization that received the content.
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM audit_events WHERE action = 'user.delete' AND target_id = $1 AND org_id = $2 AND detail->>'publishedContent' = 'transfer'`, uid, orgID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("user.delete rows naming the receiving org: %d, want 1", n)
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
	env.joinOrg(ownerSess, orgH, member)
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

	// What moves must fit the destination: the organization's private-agent
	// cap holds for a catalogue arriving at once, to the agent, and a refusal
	// erases nothing.
	holder := env.register("era-cap")
	env.verifyEmail(holder)
	env.joinOrg(ownerSess, orgH, holder)
	env.doJSON(ownerSess, http.MethodPut, "/api/v1/orgs/"+orgH+"/members/"+holder,
		map[string]any{"role": "admin"}, nil, http.StatusOK)
	holderSess := env.login(holder)
	var private []string
	for _, n := range []string{"cap-a-", "cap-b-"} {
		private = append(private, n+env.sfx)
		env.doJSON(holderSess, http.MethodPost, "/api/v1/agents", map[string]any{
			"namespace": holder, "name": n + env.sfx, "modes": []string{"autonomous"}, "visibility": "private",
		}, nil, http.StatusCreated)
	}
	// A retired private agent is put away and holds no place under the cap.
	retired := "cap-retired-" + env.sfx
	env.doJSON(holderSess, http.MethodPost, "/api/v1/agents", map[string]any{
		"namespace": holder, "name": retired, "modes": []string{"autonomous"}, "visibility": "private",
	}, nil, http.StatusCreated)
	env.doJSON(holderSess, http.MethodPost, "/api/v1/agents/"+holder+"/"+retired+"/retire", nil, nil, http.StatusOK)
	t.Cleanup(func() { env.setEntitlements(entitlements.NewConfigResolver(config.Default().Limits)) })
	transfer := "/api/v1/user/delete?publishedContent=transfer&transferOrg=" + orgH
	env.setEntitlements(orgPrivateCap{Resolver: entitlements.NewConfigResolver(config.Default().Limits), max: 1})
	if code, slug, _ := problemOf(t, env.do(holderSess, http.MethodPost, transfer, nil)); code != http.StatusUnprocessableEntity || slug != "private-agent-cap" {
		t.Fatalf("two private agents into a cap of one: %d %s, want 422 private-agent-cap", code, slug)
	}
	for _, n := range private {
		if got := env.namespaceOf(n); got != holder {
			t.Fatalf("agent %s moved on a refused transfer: namespace = %s", n, got)
		}
	}
	env.doJSON(holderSess, http.MethodGet, "/api/v1/user", nil, nil, http.StatusOK)
	env.setEntitlements(orgPrivateCap{Resolver: entitlements.NewConfigResolver(config.Default().Limits), max: 2})
	env.doJSON(holderSess, http.MethodPost, transfer, nil, nil, http.StatusNoContent)
	private = append(private, retired)
	for _, n := range private {
		if got := env.namespaceOf(n); got != orgH {
			t.Fatalf("agent %s after a transfer that fits the cap exactly: namespace = %s, want %s", n, got, orgH)
		}
	}
	env.setEntitlements(entitlements.NewConfigResolver(config.Default().Limits))

	// A name the organization already uses is a conflict, and nothing is
	// erased; an agent that was deleted keeps its name in the erased
	// namespace instead of moving.
	clash := env.register("era-clash")
	env.verifyEmail(clash)
	env.joinOrg(ownerSess, orgH, clash)
	env.doJSON(ownerSess, http.MethodPut, "/api/v1/orgs/"+orgH+"/members/"+clash,
		map[string]any{"role": "admin"}, nil, http.StatusOK)
	clashSess := env.login(clash)
	taken := "taken-" + env.sfx
	env.doJSON(ownerSess, http.MethodPost, "/api/v1/agents", map[string]any{
		"namespace": orgH, "name": taken, "modes": []string{"autonomous"}, "visibility": "public",
	}, nil, http.StatusCreated)
	env.doJSON(clashSess, http.MethodPost, "/api/v1/agents", map[string]any{
		"namespace": clash, "name": taken, "modes": []string{"autonomous"}, "visibility": "public",
	}, nil, http.StatusCreated)
	if code, slug, _ := problemOf(t, env.do(clashSess, http.MethodPost, transfer, nil)); code != http.StatusConflict || slug != "conflict" {
		t.Fatalf("a name the organization already uses: %d %s, want 409 conflict", code, slug)
	}
	env.doJSON(clashSess, http.MethodGet, "/api/v1/user", nil, nil, http.StatusOK)
	gone := "gone-" + env.sfx
	env.publishUnder(t, clashSess, clash, gone)
	env.doJSON(clashSess, http.MethodDelete, "/api/v1/agents/"+clash+"/"+gone+"?confirm="+gone, nil, nil, http.StatusNoContent)
	env.doJSON(clashSess, http.MethodDelete, "/api/v1/agents/"+clash+"/"+taken, nil, nil, http.StatusNoContent)
	kept := "kept-" + env.sfx
	env.doJSON(clashSess, http.MethodPost, "/api/v1/agents", map[string]any{
		"namespace": clash, "name": kept, "modes": []string{"autonomous"}, "visibility": "public",
	}, nil, http.StatusCreated)
	env.doJSON(clashSess, http.MethodPost, transfer, nil, nil, http.StatusNoContent)
	if got := env.namespaceOf(kept); got != orgH {
		t.Fatalf("a live agent after the transfer: namespace = %s, want %s", got, orgH)
	}
	if got := env.namespaceOf(gone); got == orgH || !strings.HasPrefix(got, "del-") {
		t.Fatalf("a deleted agent's name after the transfer: namespace = %s, want it held in the erased account's retired namespace, not %s", got, orgH)
	}

	// Nothing moves into an organization in its decommission hold, and the
	// account stays.
	founder := env.register("era-hold-f")
	env.verifyEmail(founder)
	founderSess := env.login(founder)
	heldOrg := "eraheld" + env.sfx
	env.createOrg(founderSess, heldOrg)
	second := env.register("era-hold-s")
	env.verifyEmail(second)
	env.joinOrg(founderSess, heldOrg, second)
	env.doJSON(founderSess, http.MethodPut, "/api/v1/orgs/"+heldOrg+"/members/"+second,
		map[string]any{"role": "admin"}, nil, http.StatusOK)
	secondSess := env.login(second)
	env.publishUnder(t, secondSess, second, "held-"+env.sfx)
	env.doJSON(founderSess, http.MethodPost, "/api/v1/orgs/"+heldOrg+"/decommission", map[string]any{"confirm": heldOrg}, nil, http.StatusOK)
	if code, slug, _ := problemOf(t, env.do(secondSess, http.MethodPost, "/api/v1/user/delete?publishedContent=transfer&transferOrg="+heldOrg, nil)); code != http.StatusConflict || slug != "org-decommissioning" {
		t.Fatalf("a transfer into an organization in its decommission hold: %d %s, want 409 org-decommissioning", code, slug)
	}
	env.doJSON(secondSess, http.MethodGet, "/api/v1/user", nil, nil, http.StatusOK)
	if got := env.namespaceOf("held-" + env.sfx); got != second {
		t.Fatalf("an agent moved into an organization in its hold: namespace = %s", got)
	}
}
