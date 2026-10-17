package api_test

// The account's one control over remembered browsers a directory keeps
// through the sign-in hook: a count the site shows, and a clear that revokes
// every one of the caller's, this browser's included.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/testidp"
)

// TestClearTrustedDevices follows the session routes' rule: a token reads
// 0 and cannot clear; a clear revokes the caller's live records and nobody
// else's, and a directory's next use of a cleared browser is refused.
func TestClearTrustedDevices(t *testing.T) {
	var srv *api.Server
	var mu sync.Mutex
	minted := map[string][]string{} // subject → tokens
	env, idp := newOIDCTestEnv(t, func(c *config.Config) { c.Auth.TrustedDeviceTTL = deviceTTL }, func(s *api.Server) {
		srv = s
		s.SetDirectory(&fakeDirectory{})
		s.AddSignInHook(func(_ context.Context, in api.SignIn) {
			tok, _, err := in.RememberBrowser(map[string]any{"via": "test-directory"})
			if err != nil {
				t.Errorf("mint: %v", err)
				return
			}
			mu.Lock()
			minted[in.Subject] = append(minted[in.Subject], tok)
			mu.Unlock()
		})
	})
	ctx := context.Background()
	person := func(name string) testidp.Person {
		h := name + env.sfx
		return testidp.Person{Subject: "sub-" + h, Email: h + "@example.test", EmailVerified: true, Username: h,
			AMR: []string{"pwd", "mfa"}, AuthTime: time.Now()}
	}

	// Two remembered browsers for this person, one for someone else.
	me := person("clearer")
	first := env.signInOIDC(t, idp, "oidc", me)
	me.AuthTime = time.Now()
	env.signInOIDC(t, idp, "oidc", me)
	other := env.signInOIDC(t, idp, "oidc", person("bystander"))
	mySubject, otherSubject := "oidc:"+me.Subject, "oidc:sub-bystander"+env.sfx
	if first.status != http.StatusOK || len(minted[mySubject]) != 2 || len(minted[otherSubject]) != 1 {
		t.Fatalf("sign-ins: %d, minted %v", first.status, minted)
	}
	caller := first.caller

	// An expired record of this person's: inert, so neither counted nor
	// reported as cleared.
	if _, err := env.st.Pool().Exec(ctx,
		`INSERT INTO trusted_devices (id, user_id, token_sha256, expires_at)
		 VALUES (gen_random_uuid(), $1::uuid, sha256(random()::text::bytea), now() - interval '1 hour')`, first.userID); err != nil {
		t.Fatal(err)
	}

	var count struct {
		Count *int `json:"count"`
	}
	env.doJSON(caller, http.MethodGet, "/api/v1/user/trusted-devices", nil, &count, http.StatusOK)
	if count.Count == nil || *count.Count != 2 {
		t.Fatalf("count = %s, want 2", intOrNil(count.Count))
	}

	// A token: no inventory, and no clear.
	_, pat := env.mintPAT(caller, "clear-check", "user:profile")
	tokenCaller := caller
	tokenCaller.session, tokenCaller.csrf, tokenCaller.pat = "", "", pat
	env.doJSON(tokenCaller, http.MethodGet, "/api/v1/user/trusted-devices", nil, &count, http.StatusOK)
	if count.Count == nil || *count.Count != 0 {
		t.Fatalf("a token read count = %s, want 0", intOrNil(count.Count))
	}
	env.doJSON(tokenCaller, http.MethodDelete, "/api/v1/user/trusted-devices", nil, nil, http.StatusForbidden)

	// A browser request without the CSRF header is refused, as every
	// cookie-authenticated mutation is.
	noCSRF := caller
	noCSRF.csrf = ""
	env.doJSON(noCSRF, http.MethodDelete, "/api/v1/user/trusted-devices", nil, nil, http.StatusForbidden)

	// The clear.
	res := env.do(caller, http.MethodDelete, "/api/v1/user/trusted-devices", nil)
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("clear: status %d", res.StatusCode)
	}
	var cleared struct {
		Cleared *int `json:"cleared"`
	}
	if err := json.NewDecoder(res.Body).Decode(&cleared); err != nil || cleared.Cleared == nil || *cleared.Cleared != 2 {
		t.Fatalf("cleared = %s (%v), want 2", intOrNil(cleared.Cleared), err)
	}
	// The cookie is the directory's: the clear sets none of its own.
	requireNoCookie(t, res.Cookies(), trustedDeviceCookie)

	env.doJSON(caller, http.MethodGet, "/api/v1/user/trusted-devices", nil, &count, http.StatusOK)
	if count.Count == nil || *count.Count != 0 {
		t.Fatalf("count after the clear = %s, want 0", intOrNil(count.Count))
	}
	// Cleared means the directory's next use of each is refused, and
	// someone else's browser is still remembered.
	r := httptest.NewRequest(http.MethodPost, "/internal/x/test/check", nil)
	for i, tok := range minted[mySubject] {
		if ok, err := srv.UseRememberedBrowser(r, uuid.MustParse(first.userID), tok, nil); err != nil || ok {
			t.Fatalf("cleared browser %d: %v %v, want false", i+1, ok, err)
		}
	}
	if ok, err := srv.UseRememberedBrowser(r, uuid.MustParse(other.userID), minted[otherSubject][0], nil); err != nil || !ok {
		t.Fatalf("another account's browser after the clear: %v %v, want true", ok, err)
	}

	var audited int
	if err := env.st.Pool().QueryRow(ctx,
		`SELECT count(*) FROM audit_events WHERE action = 'user.trusted_device_revoke' AND actor_id = $1::uuid AND detail->>'scope' = 'all' AND (detail->>'count')::int = 2`, first.userID).Scan(&audited); err != nil || audited != 1 {
		t.Fatalf("%d user.trusted_device_revoke rows for the clear, want 1 (%v)", audited, err)
	}

	// Nothing left: a second clear answers 0 and writes no audit row.
	env.doJSON(caller, http.MethodDelete, "/api/v1/user/trusted-devices", nil, &cleared, http.StatusOK)
	if cleared.Cleared == nil || *cleared.Cleared != 0 {
		t.Fatalf("a second clear = %s, want 0", intOrNil(cleared.Cleared))
	}
	if err := env.st.Pool().QueryRow(ctx,
		`SELECT count(*) FROM audit_events WHERE action = 'user.trusted_device_revoke' AND actor_id = $1::uuid AND detail->>'scope' = 'all'`, first.userID).Scan(&audited); err != nil || audited != 1 {
		t.Fatalf("%d clear audit rows after a clear with nothing to clear, want still 1 (%v)", audited, err)
	}
}

func intOrNil(p *int) string {
	if p == nil {
		return "absent"
	}
	return strconv.Itoa(*p)
}
