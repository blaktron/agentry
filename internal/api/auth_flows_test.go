package api_test

// Acceptance flows: the sign-in lifecycle, PAT lifecycle e2e, and audit
// coverage for mutating calls.

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/blaktron/agentry/internal/api"
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

	// Logout revokes the session immediately and expires the cookie.
	res = env.do(sess, http.MethodPost, "/api/v1/auth/logout", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("logout: got %d, want 204", res.StatusCode)
	}
	if !sessionCookieCleared(res) {
		t.Fatal("logout left the browser holding its session cookie")
	}
	res = env.do(sess, http.MethodGet, "/api/v1/user", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked session must 401, got %d", res.StatusCode)
	}
	if n := env.actorAuditRows(t, sess.name, "user.logout"); n != 1 {
		t.Fatalf("user.logout rows by the account that signed out: %d, want 1", n)
	}
}

// actorAuditRows counts the audit rows of an action written with the
// account as actor. The binary's tests share one audit log, so a count of
// the action alone says nothing of this test's own acts.
func (env *testEnv) actorAuditRows(t *testing.T, handle, action string) int {
	t.Helper()
	var n int
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM audit_events a JOIN handles h ON h.id = a.actor_id WHERE h.handle = $1 AND a.action = $2`, handle, action).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
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
		Id         string   `json:"id"`
		Prefix     string   `json:"prefix"`
		Scopes     []string `json:"scopes"`
		LastUsedAt *string  `json:"lastUsedAt"`
	}
	env.doJSON(sess, http.MethodGet, "/api/v1/user/tokens", nil, &list, http.StatusOK)
	if len(list) != 1 || list[0].Id != id || list[0].Prefix != token[:12] {
		t.Fatalf("token list: %+v", list)
	}
	if list[0].LastUsedAt == nil {
		t.Fatal("a token that has just been used lists no last use")
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

	// A token cannot sign its holder out of the browsers either.
	res = env.do(patCaller, http.MethodPost, "/api/v1/auth/logout", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("PAT logout must 403, got %d", res.StatusCode)
	}

	// What a token may be minted with: a name of 1 to 120 characters, at
	// least one known scope, and a lifetime within the year.
	day := 24 * time.Hour
	mint := func(body map[string]any) (int, []api.FieldError) {
		return fieldRefusalOf(t, env.do(sess, http.MethodPost, "/api/v1/user/tokens", body))
	}
	for _, c := range []struct {
		name string
		body map[string]any
		want api.FieldError
	}{
		{"a blank name", map[string]any{"name": "  ", "scopes": []string{"user:profile"}}, api.FieldError{Field: "name", Message: "Must be 1-120 characters."}},
		{"a 121-character name", map[string]any{"name": strings.Repeat("n", 121), "scopes": []string{"user:profile"}}, api.FieldError{Field: "name", Message: "Must be 1-120 characters."}},
		{"no scope", map[string]any{"name": "t", "scopes": []string{}}, api.FieldError{Field: "scopes", Message: "Name at least one scope."}},
		{"an unknown scope", map[string]any{"name": "t", "scopes": []string{"nonsense:all"}}, api.FieldError{Field: "scopes", Message: "Unknown scope nonsense:all."}},
		{"a lifetime past the year", map[string]any{"name": "t", "scopes": []string{"user:profile"}, "expiresAt": time.Now().Add(366 * day)}, api.FieldError{Field: "expiresAt", Message: "Must be within the maximum token lifetime."}},
		{"an expiry in the past", map[string]any{"name": "t", "scopes": []string{"user:profile"}, "expiresAt": time.Now().Add(-time.Minute)}, api.FieldError{Field: "expiresAt", Message: "Must be in the future."}},
	} {
		if code, fields := mint(c.body); code != http.StatusUnprocessableEntity || len(fields) != 1 || fields[0] != c.want {
			t.Errorf("%s: %d %+v, want 422 %+v", c.name, code, fields, c.want)
		}
	}
	var minted struct {
		ExpiresAt time.Time `json:"expiresAt"`
		Name      string    `json:"name"`
	}
	want := time.Now().Add(364 * day)
	env.doJSON(sess, http.MethodPost, "/api/v1/user/tokens", map[string]any{"name": strings.Repeat("n", 120), "scopes": []string{"user:profile"}, "expiresAt": want}, &minted, http.StatusCreated)
	if len(minted.Name) != 120 || minted.ExpiresAt.Sub(want).Abs() > time.Second {
		t.Fatalf("a 120-character name and a lifetime within the year: %d characters, expires %v, want %v", len(minted.Name), minted.ExpiresAt, want)
	}

	// Only the owner revokes a token.
	stranger := env.login(env.register("patty-stranger"))
	res = env.do(stranger, http.MethodDelete, "/api/v1/user/tokens/"+id, nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("revoking another account's token: got %d, want 404", res.StatusCode)
	}
	env.doJSON(patCaller, http.MethodGet, "/api/v1/user", nil, nil, http.StatusOK)

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
	// And for this account's own acts, which the binary's other tests cannot
	// stand in for: one row each, the token's naming its name and scopes.
	for action, want := range map[string]int{"user.social_login": 1, "user.update": 1, "user.logout": 1, "pat.create": 1, "pat.revoke": 1} {
		if n := env.actorAuditRows(t, h, action); n != want {
			t.Errorf("audit rows of %s written by %s: %d, want %d", action, h, n, want)
		}
	}
	var named int
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM audit_events a JOIN handles hd ON hd.id = a.actor_id
		  WHERE hd.handle = $1 AND a.action = 'pat.create' AND a.target_id = $2::uuid AND a.detail->>'name' = 'audit-tok' AND a.detail->'scopes' = '["user:profile"]'::jsonb`, h, tokID).Scan(&named); err != nil || named != 1 {
		t.Errorf("pat.create rows naming the token and its scopes: %d (%v), want 1", named, err)
	}
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM audit_events a JOIN handles hd ON hd.id = a.actor_id
		  WHERE hd.handle = $1 AND a.action = 'pat.revoke' AND a.target_id = $2::uuid`, h, tokID).Scan(&named); err != nil || named != 1 {
		t.Errorf("pat.revoke rows naming the token: %d (%v), want 1", named, err)
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
