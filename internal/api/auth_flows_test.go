package api_test

// Acceptance flows: the sign-in lifecycle, PAT lifecycle e2e, and audit
// coverage for mutating calls.

import (
	"context"
	"net/http"
	"testing"

	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// TestAuthLifecycle: a sign-in through the deployment's OpenID provider →
// the session works → CSRF enforcement → logout.
func TestAuthLifecycle(t *testing.T) {
	env, idp := newOIDCTestEnv(t, nil)
	sess := env.mintAccount(t, idp, "alice")

	// Session works.
	var me struct {
		Handle string `json:"handle"`
	}
	env.doJSON(sess, http.MethodGet, "/api/v1/user", nil, &me, http.StatusOK)
	if me.Handle != sess.name {
		t.Fatalf("whoami: %q", me.Handle)
	}

	// Mutation without CSRF header → 403.
	noCSRF := sess
	noCSRF.csrf = ""
	res := env.do(noCSRF, http.MethodPatch, "/api/v1/user", map[string]any{"displayName": "X"})
	_ = res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("missing CSRF must 403, got %d", res.StatusCode)
	}

	// Logout revokes the session immediately.
	env.doJSON(sess, http.MethodPost, "/api/v1/auth/logout", nil, nil, http.StatusNoContent)
	res = env.do(sess, http.MethodGet, "/api/v1/user", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked session must 401, got %d", res.StatusCode)
	}
}

// TestTheServerKeepsNoCredentialsOfItsOwn: there is no route that takes a
// password or a second-factor code. Registering, signing in with a
// password and the TOTP enrolment and challenge are not routes at all,
// whatever the deployment's configuration, and none of them reveals an
// account.
func TestTheServerKeepsNoCredentialsOfItsOwn(t *testing.T) {
	env := newTestEnv(t)
	h := env.register("nocreds")
	sess := env.login(h)
	for _, c := range []struct {
		who  caller
		path string
		body map[string]any
	}{
		{anonymous, "/api/v1/auth/register", map[string]any{"handle": "x" + env.sfx, "email": "x" + env.sfx + "@example.test", "password": "hunter2hunter2"}},
		{anonymous, "/api/v1/auth/login", map[string]any{"login": h, "password": "hunter2hunter2"}},
		{sess, "/api/v1/auth/2fa/totp/setup", nil},
		{sess, "/api/v1/auth/2fa/totp/verify", map[string]any{"code": "000000"}},
		{anonymous, "/api/v1/auth/2fa/totp/challenge", map[string]any{"challenge": "x", "code": "000000"}},
	} {
		res := env.do(c.who, http.MethodPost, c.path, c.body)
		_ = res.Body.Close()
		if res.StatusCode != http.StatusNotFound {
			t.Errorf("POST %s: %d, want 404", c.path, res.StatusCode)
		}
	}
	var cols int
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM information_schema.columns
		  WHERE table_name = 'users' AND column_name IN ('password_hash', 'totp_secret_enc')`).Scan(&cols); err != nil {
		t.Fatal(err)
	}
	if cols != 0 {
		t.Fatalf("users still has %d credential columns", cols)
	}
}

// TestPATLifecycle is the acceptance item: mint → use → scope-limit →
// revoke → immediate rejection.
func TestPATLifecycle(t *testing.T) {
	env := newTestEnv(t)
	h := env.register("patty")
	env.verifyEmail(h)
	sess := env.login(h)

	id, token := env.mintPAT(sess, "ci-token", "user:profile")
	if len(token) < 40 || token[:4] != "agy_" {
		t.Fatalf("token shape: %q", token)
	}

	// PAT authenticates.
	patCaller := caller{name: "pat", pat: token}
	var me struct {
		Handle string `json:"handle"`
	}
	env.doJSON(patCaller, http.MethodGet, "/api/v1/user", nil, &me, http.StatusOK)
	if me.Handle != h {
		t.Fatalf("pat whoami: %q", me.Handle)
	}

	// Listing shows metadata but never the secret.
	var list []struct {
		Id     string   `json:"id"`
		Prefix string   `json:"prefix"`
		Scopes []string `json:"scopes"`
	}
	env.doJSON(sess, http.MethodGet, "/api/v1/user/tokens", nil, &list, http.StatusOK)
	if len(list) != 1 || list[0].Id != id || list[0].Prefix != token[:12] {
		t.Fatalf("token list: %+v", list)
	}

	// A PAT cannot mint PATs (session-only).
	res := env.do(patCaller, http.MethodPost, "/api/v1/user/tokens",
		map[string]any{"name": "nested", "scopes": []string{"user:profile"}})
	_ = res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("PAT minting PAT must 403, got %d", res.StatusCode)
	}

	// Scope enforcement: user:profile PAT cannot read org audit.
	orgH := "porg" + env.sfx
	env.doJSON(sess, http.MethodPost, "/api/v1/orgs", map[string]any{"handle": orgH, "displayName": "P"}, nil, http.StatusCreated)
	res = env.do(patCaller, http.MethodGet, "/api/v1/orgs/"+orgH+"/audit", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("scope violation must 403, got %d", res.StatusCode)
	}

	// Revoke → immediate rejection.
	env.doJSON(sess, http.MethodDelete, "/api/v1/user/tokens/"+id, nil, nil, http.StatusNoContent)
	res = env.do(patCaller, http.MethodGet, "/api/v1/user", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked PAT must 401, got %d", res.StatusCode)
	}
}

// TestAuditCoverage asserts audit rows exist for every mutating action
// after driving each flow once, and that audit rows are immutable.
func TestAuditCoverage(t *testing.T) {
	env, idp := newOIDCTestEnv(t, nil)
	sess := env.mintAccount(t, idp, "aud")
	h := sess.name

	// Drive mutations.
	env.doJSON(sess, http.MethodPatch, "/api/v1/user", map[string]any{"displayName": "Audrey"}, nil, http.StatusOK)
	orgH := "aorg" + env.sfx
	env.doJSON(sess, http.MethodPost, "/api/v1/orgs", map[string]any{"handle": orgH, "displayName": "A"}, nil, http.StatusCreated)
	member := env.register("aud2")
	env.joinOrg(sess, orgH, member)
	env.doJSON(sess, http.MethodPost, "/api/v1/orgs/"+orgH+"/teams", map[string]any{"slug": "audit-team"}, nil, http.StatusCreated)
	env.doJSON(sess, http.MethodPut, "/api/v1/orgs/"+orgH+"/teams/audit-team/members/"+member, nil, nil, http.StatusNoContent)
	env.doJSON(sess, http.MethodDelete, "/api/v1/orgs/"+orgH+"/teams/audit-team/members/"+member, nil, nil, http.StatusNoContent)
	env.doJSON(sess, http.MethodDelete, "/api/v1/orgs/"+orgH+"/teams/audit-team", nil, nil, http.StatusNoContent)
	env.doJSON(sess, http.MethodDelete, "/api/v1/orgs/"+orgH+"/members/"+member, nil, nil, http.StatusNoContent)
	tokID, _ := env.mintPAT(sess, "audit-tok", "user:profile")
	env.doJSON(sess, http.MethodDelete, "/api/v1/user/tokens/"+tokID, nil, nil, http.StatusNoContent)
	env.doJSON(sess, http.MethodPost, "/api/v1/auth/logout", nil, nil, http.StatusNoContent)

	// The org audit endpoint shows org-scoped events.
	sess2 := env.login(h)
	var page struct {
		Events []struct {
			Action string `json:"action"`
		} `json:"events"`
	}
	env.doJSON(sess2, http.MethodGet, "/api/v1/orgs/"+orgH+"/audit", nil, &page, http.StatusOK)
	seen := map[string]bool{}
	for _, e := range page.Events {
		seen[e.Action] = true
	}
	for _, want := range []string{"org.create", "org.member_set", "team.create", "team.member_add", "team.member_remove", "team.delete", "org.member_remove"} {
		if !seen[want] {
			t.Errorf("org audit missing action %s (got %v)", want, seen)
		}
	}

	// Global assertions for user-scoped actions via direct store queries.
	q := storegen.New(env.st.Pool())
	for _, action := range []string{"user.social_login", "user.login", "user.update", "user.logout", "pat.create", "pat.revoke"} {
		n, err := q.CountAuditEvents(context.Background(), storegen.CountAuditEventsParams{Action: action})
		if err != nil {
			t.Fatalf("count %s: %v", action, err)
		}
		if n == 0 {
			t.Errorf("no audit rows for %s", action)
		}
	}

	// Append-only: UPDATE/DELETE must be blocked by trigger.
	if _, err := env.st.Pool().Exec(context.Background(),
		`UPDATE audit_events SET action = 'tampered' WHERE action = 'user.login'`); err == nil {
		t.Fatal("audit UPDATE must be rejected")
	}
	if _, err := env.st.Pool().Exec(context.Background(),
		`DELETE FROM audit_events WHERE action = 'user.login'`); err == nil {
		t.Fatal("audit DELETE must be rejected")
	}
}
