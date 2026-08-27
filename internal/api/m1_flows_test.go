package api_test

// M1 acceptance flows (§18.2): full auth lifecycle, PAT lifecycle e2e, and
// audit coverage for mutating calls.

import (
	"context"
	"net/http"
	"testing"

	"github.com/PLACEHOLDER_ORG/agentry/internal/auth"
	storegen "github.com/PLACEHOLDER_ORG/agentry/internal/store/gen"
)

// TestAuthLifecycle: register → login → CSRF enforcement → logout.
func TestAuthLifecycle(t *testing.T) {
	env := newTestEnv(t)
	h := env.register("alice")

	// Duplicate handle → 409.
	env.doJSON(anonymous, http.MethodPost, "/api/v1/auth/register", map[string]any{
		"handle": h, "email": "other" + env.sfx + "@example.test", "password": "hunter2hunter2",
	}, nil, http.StatusConflict)

	// Weak password rejected.
	env.doJSON(anonymous, http.MethodPost, "/api/v1/auth/register", map[string]any{
		"handle": "weak" + env.sfx, "email": "weak" + env.sfx + "@example.test", "password": "short",
	}, nil, http.StatusUnprocessableEntity)

	// Wrong password → 401.
	res := env.do(anonymous, http.MethodPost, "/api/v1/auth/login",
		map[string]any{"login": h, "password": "wrong-password-x"})
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong password: %d", res.StatusCode)
	}

	sess := env.login(h)

	// Session works.
	var me struct {
		Handle string `json:"handle"`
	}
	env.doJSON(sess, http.MethodGet, "/api/v1/user", nil, &me, http.StatusOK)
	if me.Handle != h {
		t.Fatalf("whoami: %q", me.Handle)
	}

	// Mutation without CSRF header → 403.
	noCSRF := sess
	noCSRF.csrf = ""
	res = env.do(noCSRF, http.MethodPatch, "/api/v1/user", map[string]any{"displayName": "X"})
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

// TestPATLifecycle is the M1 acceptance item: mint → use → scope-limit →
// revoke → immediate rejection (§12.3, D-22).
func TestPATLifecycle(t *testing.T) {
	env := newTestEnv(t)
	h := env.register("patty")
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

// TestAuditCoverage asserts audit rows exist for every M1 mutating action
// after driving each flow once, and that audit rows are immutable.
func TestAuditCoverage(t *testing.T) {
	env := newTestEnv(t)
	h := env.register("aud")
	sess := env.login(h)

	// Drive mutations.
	env.doJSON(sess, http.MethodPatch, "/api/v1/user", map[string]any{"displayName": "Audrey"}, nil, http.StatusOK)
	orgH := "aorg" + env.sfx
	env.doJSON(sess, http.MethodPost, "/api/v1/orgs", map[string]any{"handle": orgH, "displayName": "A"}, nil, http.StatusCreated)
	member := env.register("aud2")
	env.doJSON(sess, http.MethodPut, "/api/v1/orgs/"+orgH+"/members/"+member, map[string]any{"role": "member"}, nil, http.StatusOK)
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
	for _, action := range []string{"user.register", "user.login", "user.update", "user.logout", "pat.create", "pat.revoke"} {
		n, err := q.CountAuditEvents(context.Background(), storegen.CountAuditEventsParams{Action: action})
		if err != nil {
			t.Fatalf("count %s: %v", action, err)
		}
		if n == 0 {
			t.Errorf("no audit rows for %s", action)
		}
	}

	// Append-only: UPDATE/DELETE must be blocked by trigger (§4.3).
	if _, err := env.st.Pool().Exec(context.Background(),
		`UPDATE audit_events SET action = 'tampered' WHERE action = 'user.register'`); err == nil {
		t.Fatal("audit UPDATE must be rejected")
	}
	if _, err := env.st.Pool().Exec(context.Background(),
		`DELETE FROM audit_events WHERE action = 'user.register'`); err == nil {
		t.Fatal("audit DELETE must be rejected")
	}
}

// TestTOTPFlow: enroll, verify, then login requires the code.
func TestTOTPFlow(t *testing.T) {
	env := newTestEnv(t)
	h := env.register("totpy")
	sess := env.login(h)

	var setup struct {
		Secret string `json:"secret"`
	}
	env.doJSON(sess, http.MethodPost, "/api/v1/auth/2fa/totp/setup", nil, &setup, http.StatusOK)
	if setup.Secret == "" {
		t.Fatal("no TOTP secret")
	}
	code, err := totpCode(setup.Secret)
	if err != nil {
		t.Fatal(err)
	}
	env.doJSON(sess, http.MethodPost, "/api/v1/auth/2fa/totp/verify", map[string]any{"code": code}, nil, http.StatusNoContent)

	// Password-only login now returns totp-required.
	res := env.do(anonymous, http.MethodPost, "/api/v1/auth/login",
		map[string]any{"login": h, "password": "hunter2hunter2"})
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("TOTP-less login must 401, got %d", res.StatusCode)
	}

	// With code succeeds.
	code2, _ := totpCode(setup.Secret)
	env.doJSON(anonymous, http.MethodPost, "/api/v1/auth/login",
		map[string]any{"login": h, "password": "hunter2hunter2", "totpCode": code2}, nil, http.StatusOK)
}

// totpCode computes a current code for a base32 secret using the same
// library as production (acceptable in tests; validates interop).
func totpCode(secret string) (string, error) {
	return auth.TestTOTPCode(secret)
}
