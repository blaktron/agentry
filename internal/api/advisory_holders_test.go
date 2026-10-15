package api_test

// Advisories reach the people who held a QuickAgent: an
// advisory published after the agent went private, was retired or was
// deleted as a tombstone is served by GET /advisories?affecting= to a
// caller whose account install names the agent, and to any caller who
// presents the archive digest of a release of it. Everyone else still gets
// the missing name's 404, and the feed and the permalink stay
// public-only.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestAnAdvisoryReachesWhoeverHeldTheAgentAfterItWentPrivate(t *testing.T) {
	env := newTestEnv(t)
	owner := env.register("advh-own")
	env.verifyEmail(owner)
	sess := env.login(owner)
	installerH := env.register("advh-ins")
	env.verifyEmail(installerH)
	installer := env.login(installerH)
	stranger := env.login(env.register("advh-str"))

	env.publishedAgent(sess, owner, "held")
	env.publishedAgent(sess, owner, "gone")
	env.publishedAgent(sess, owner, "other")
	for _, name := range []string{"held", "gone"} {
		if code, _, prob := env.putInstall(t, installer, owner+"/"+name, map[string]any{"version": "1.0.0", "acceptCapabilities": true}); code != http.StatusOK {
			t.Fatalf("install %s: %d %+v", name, code, prob)
		}
	}
	digestOf := func(name string) string {
		t.Helper()
		var v struct {
			ArchiveDigest string `json:"archiveDigest"`
		}
		env.doJSON(sess, http.MethodGet, "/api/v1/agents/"+owner+"/"+name+"/versions/1.0.0", nil, &v, http.StatusOK)
		if v.ArchiveDigest == "" {
			t.Fatalf("%s@1.0.0 has no archive digest", name)
		}
		return v.ArchiveDigest
	}
	heldDigest, goneDigest, otherDigest := digestOf("held"), digestOf("gone"), digestOf("other")

	advise := func(name, summary string) uuid.UUID {
		t.Helper()
		id := uuid.New()
		if _, err := env.st.Pool().Exec(context.Background(),
			`INSERT INTO advisories (id, agent_id, affected_versions, severity, summary, published_at)
			 SELECT $1, a.id, '<=1.0.0', 'high', $4, now()
			 FROM agents a JOIN handles h ON h.id = a.namespace_id WHERE h.handle = $2 AND a.name = $3`,
			id, owner, name, summary); err != nil {
			t.Fatal(err)
		}
		return id
	}
	type adv struct {
		Id      string `json:"id"`
		Summary string `json:"summary"`
	}
	affecting := func(c caller, name, digest string) (int, []adv) {
		t.Helper()
		path := "/api/v1/advisories?affecting=" + owner + "/" + name
		if digest != "" {
			path += "&digest=" + digest
		}
		res := env.do(c, http.MethodGet, path, nil)
		if res.StatusCode != http.StatusOK {
			_ = res.Body.Close()
			return res.StatusCode, nil
		}
		defer func() { _ = res.Body.Close() }()
		var out []adv
		if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return res.StatusCode, out
	}
	// reaches asserts who learns of the advisory on name and who does not.
	reaches := func(state, name, digest string, id uuid.UUID) {
		t.Helper()
		for _, who := range []struct {
			label  string
			c      caller
			digest string
		}{
			{"the installer's session", installer, ""},
			{"an anonymous holder of the release's digest", anonymous, digest},
			{"a stranger holding the digest", stranger, digest},
		} {
			code, got := affecting(who.c, name, who.digest)
			if code != http.StatusOK || len(got) != 1 || got[0].Id != id.String() {
				t.Fatalf("%s: %s: got %d %+v, want the advisory", state, who.label, code, got)
			}
		}
		for _, who := range []struct {
			label  string
			c      caller
			digest string
		}{
			{"anonymous", anonymous, ""},
			{"a stranger", stranger, ""},
			{"a stranger with another agent's digest", stranger, otherDigest},
			{"anonymous with a digest no release has", anonymous, "sha256:" + strings.Repeat("0", 64)},
		} {
			if code, got := affecting(who.c, name, who.digest); code != http.StatusNotFound {
				t.Fatalf("%s: %s: got %d %+v, want the missing name's 404", state, who.label, code, got)
			}
		}
		// The feed and the permalink name no private agent.
		var feed []struct {
			Id string `json:"id"`
		}
		env.doJSON(anonymous, http.MethodGet, "/api/v1/advisories?limit=100", nil, &feed, http.StatusOK)
		for _, f := range feed {
			if f.Id == id.String() {
				t.Fatalf("%s: the feed lists the advisory", state)
			}
		}
		if code := statusOf(t, env.do(anonymous, http.MethodGet, "/api/v1/advisories/"+id.String(), nil)); code != http.StatusNotFound {
			t.Fatalf("%s: permalink: got %d, want 404", state, code)
		}
	}

	// Made private.
	env.doJSON(sess, http.MethodPatch, "/api/v1/agents/"+owner+"/held", map[string]any{"visibility": "private"}, nil, http.StatusOK)
	first := advise("held", "found after it went private")
	reaches("private", "held", heldDigest, first)

	// A token of the installer's reaches it only when it may read the
	// account's own records, as GET /user/installs needs.
	_, bare := env.mintPAT(installer, "advh-bare", "agent:read")
	if code, _ := affecting(caller{name: "bare", pat: bare}, "held", ""); code != http.StatusNotFound {
		t.Fatalf("a token without user:profile: got %d, want 404", code)
	}
	_, profile := env.mintPAT(installer, "advh-profile", "user:profile")
	if code, got := affecting(caller{name: "profile", pat: profile}, "held", ""); code != http.StatusOK || len(got) != 1 {
		t.Fatalf("a user:profile token: got %d %+v", code, got)
	}

	// Retired (made public again first, so Retire is what hides it).
	env.doJSON(sess, http.MethodPatch, "/api/v1/agents/"+owner+"/held", map[string]any{"visibility": "public"}, nil, http.StatusOK)
	env.doJSON(sess, http.MethodPost, "/api/v1/agents/"+owner+"/held/retire", nil, nil, http.StatusOK)
	if _, err := env.st.Pool().Exec(context.Background(), `DELETE FROM advisories WHERE id = $1`, first); err != nil {
		t.Fatal(err)
	}
	reaches("retired", "held", heldDigest, advise("held", "found after it was retired"))

	// Deleted as a tombstone, then an advisory (staff can still act on it).
	env.doJSON(sess, http.MethodDelete, "/api/v1/agents/"+owner+"/gone?confirm=gone", nil, nil, http.StatusNoContent)
	reaches("deleted", "gone", goneDigest, advise("gone", "found after it was deleted"))

	// The installer's record of one agent proves nothing about another.
	advise("other", "on a public agent")
	env.doJSON(sess, http.MethodPatch, "/api/v1/agents/"+owner+"/other", map[string]any{"visibility": "private"}, nil, http.StatusOK)
	if code, got := affecting(installer, "other", ""); code != http.StatusNotFound {
		t.Fatalf("an agent the installer never installed: got %d %+v, want 404", code, got)
	}
	if code, got := affecting(anonymous, "other", heldDigest); code != http.StatusNotFound {
		t.Fatalf("another agent's digest: got %d %+v, want 404", code, got)
	}

	// A person who removes their install record holds nothing the registry
	// knows of; the digest of the copy they kept still proves it.
	env.doJSON(installer, http.MethodDelete, "/api/v1/user/installs/"+owner+"/held", nil, nil, http.StatusNoContent)
	if code, got := affecting(installer, "held", ""); code != http.StatusNotFound {
		t.Fatalf("after the install was removed: got %d %+v, want 404", code, got)
	}
	if code, got := affecting(installer, "held", heldDigest); code != http.StatusOK || len(got) != 1 {
		t.Fatalf("after the install was removed, with the digest: got %d %+v", code, got)
	}
}

// A holder learns nothing a suspended organization's namespace would not
// tell anyone: the organization's gate answers before the
// holder's door.
func TestASuspendedOrganizationsAgentAnswersHoldersAsAbsent(t *testing.T) {
	env := newTestEnv(t)
	admin := env.register("advh-oadm")
	env.verifyEmail(admin)
	sess := env.login(admin)
	org := "advh-org-" + env.sfx
	orgID := env.createOrg(sess, org)
	installerH := env.register("advh-oins")
	env.verifyEmail(installerH)
	installer := env.login(installerH)

	env.publishedAgent(sess, org, "kept")
	if code, _, prob := env.putInstall(t, installer, org+"/kept", map[string]any{"version": "1.0.0", "acceptCapabilities": true}); code != http.StatusOK {
		t.Fatalf("install: %d %+v", code, prob)
	}
	var v struct {
		ArchiveDigest string `json:"archiveDigest"`
	}
	env.doJSON(sess, http.MethodGet, "/api/v1/agents/"+org+"/kept/versions/1.0.0", nil, &v, http.StatusOK)
	env.doJSON(sess, http.MethodPatch, "/api/v1/agents/"+org+"/kept", map[string]any{"visibility": "private"}, nil, http.StatusOK)
	ctx := context.Background()
	if _, err := env.st.Pool().Exec(ctx,
		`INSERT INTO advisories (id, agent_id, affected_versions, severity, summary, published_at)
		 SELECT $1, a.id, '<=1.0.0', 'high', 'found after it went private', now()
		 FROM agents a WHERE a.namespace_id = $2 AND a.name = 'kept'`, uuid.New(), orgID); err != nil {
		t.Fatal(err)
	}
	get := func(c caller, digest string) int {
		path := "/api/v1/advisories?affecting=" + org + "/kept"
		if digest != "" {
			path += "&digest=" + digest
		}
		return statusOf(t, env.do(c, http.MethodGet, path, nil))
	}
	if get(installer, "") != http.StatusOK || get(anonymous, v.ArchiveDigest) != http.StatusOK {
		t.Fatal("an active organization's holders do not get the advisory")
	}
	if _, err := env.st.Pool().Exec(ctx, `UPDATE orgs SET state = 'suspended' WHERE id = $1`, orgID); err != nil {
		t.Fatal(err)
	}
	if code := get(installer, ""); code != http.StatusNotFound {
		t.Fatalf("installer of a suspended organization's agent: got %d, want 404", code)
	}
	if code := get(anonymous, v.ArchiveDigest); code != http.StatusNotFound {
		t.Fatalf("digest holder of a suspended organization's agent: got %d, want 404", code)
	}
}
