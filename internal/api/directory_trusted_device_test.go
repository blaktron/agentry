package api_test

// Remembered browsers on the directory's sign-in.
//
// A deployment that signs in through the directory shows the "Remember this
// device for 30 days" box on the directory's code page. The directory passes the
// choice to the registry as the ID-token claim agentry_remember_device, and
// the registry mints the trusted-device record on the callback. These tests pin the
// rule that decides the mint: only the directory's claim, only beside an
// `amr` that names a second factor, only while the directory path is on.

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/config"
)

const (
	directoryTrustToken = "directory-trust-check-token-0123456789abcdef"
	// flowExecutorPath is where authentik's flow executor lives: the only
	// place the browser should present the cookie.
	flowExecutorPath = "/api/v3/flows/executor/"
)

// newRememberEnv serves one fake IdP as both the directory and Google, so
// a test can compare the two providers against the same token. The
// registry's public origin is registryBase ("" for the listener's address).
func newRememberEnv(t *testing.T, idp *fakeOIDC, on bool, registryBase ...string) *testEnv {
	t.Helper()
	base := "http://127.0.0.1"
	if len(registryBase) > 0 {
		base = registryBase[0]
	}
	return newTestEnvCfg(t, func(cfg *config.Config) {
		cfg.BaseURL = base
		cfg.Auth.TrustedDeviceTTL = deviceTTL
		cfg.Social.Authentik = config.SocialProvider{ClientID: idp.clientID, ClientSecret: "s", Issuer: idp.origin()}
		cfg.Social.Google = config.SocialProvider{ClientID: idp.clientID, ClientSecret: "s", Issuer: idp.origin()}
		if on {
			cfg.Auth.IdPTrustCheckToken = directoryTrustToken
		}
	}, func(s *api.Server) { s.SetOIDCHTTPClient(idp.hostClient()) })
}

// fresh is an auth_time of a sign-in that just happened.
func fresh() int64 { return time.Now().Unix() }

// directorySignIn runs start → the IdP → callback in API mode and returns
// the callback's response and the signed-in user's id.
func directorySignIn(t *testing.T, env *testEnv, idp *fakeOIDC, provider string) (*http.Response, string) {
	t.Helper()
	authURL, state, cookie := env.socialStart(t, provider)
	visit, err := idp.hostClient().Get(authURL.String())
	if err != nil {
		t.Fatal(err)
	}
	_ = visit.Body.Close()
	res := env.socialCallback(t, provider, state, cookie)
	t.Cleanup(func() { _ = res.Body.Close() })
	if res.StatusCode != http.StatusOK {
		t.Fatalf("callback: got %d want 200", res.StatusCode)
	}
	var out struct {
		User struct {
			Id string `json:"id"`
		} `json:"user"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return res, out.User.Id
}

func trustedDeviceRows(t *testing.T, env *testEnv, userID string) int {
	t.Helper()
	var n int
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM trusted_devices WHERE user_id = $1::uuid`, userID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestDirectoryIsAskedForTheAgentryScope: the directory's claim answers to
// the agentry scope, and no other provider is asked for it.
func TestDirectoryIsAskedForTheAgentryScope(t *testing.T) {
	idp := newFakeOIDC(t)
	env := newRememberEnv(t, idp, true)
	for provider, want := range map[string]bool{"authentik": true, "google": false} {
		authURL, _, _ := env.socialStart(t, provider)
		got := slices.Contains(strings.Fields(authURL.Query().Get("scope")), "agentry")
		if got != want {
			t.Errorf("%s: asked for the agentry scope = %v, want %v (scope %q)", provider, got, want, authURL.Query().Get("scope"))
		}
	}
}

// TestDirectoryRemembersOnlyOnItsClaimAndASecondFactor is the mint's truth
// table. The claim asks; `amr` proves the factor was answered in this very
// sign-in. Neither alone mints, nor does another provider asserting the
// claim, nor the directory while the path is off.
func TestDirectoryRemembersOnlyOnItsClaimAndASecondFactor(t *testing.T) {
	mfa := []string{"pwd", "mfa"}
	for _, tc := range []struct {
		name     string
		provider string
		on       bool
		claim    any // nil: absent
		amr      []string
		authTime int64 // 0: absent
		want     bool
	}{
		{"ticked, and the code was answered", "authentik", true, true, mfa, fresh(), true},
		{"ticked, but the factor was skipped", "authentik", true, true, []string{"pwd"}, fresh(), false},
		{"ticked, and no amr at all", "authentik", true, true, nil, fresh(), false},
		{"not ticked", "authentik", true, false, mfa, fresh(), false},
		{"no claim", "authentik", true, nil, mfa, fresh(), false},
		{"another provider asserting it", "google", true, true, mfa, fresh(), false},
		{"the directory path off", "authentik", false, true, mfa, fresh(), false},
		// A live directory session answers a later authorize silently, with
		// the claim and the amr of the sign-in that started it: only its
		// auth_time says it is old. Minting from it would renew trust with
		// no code answered.
		{"a directory session an hour old", "authentik", true, true, mfa, time.Now().Add(-time.Hour).Unix(), false},
		{"no auth_time", "authentik", true, true, mfa, 0, false},
		{"an auth_time from the future", "authentik", true, true, mfa, time.Now().Add(time.Hour).Unix(), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			idp := newFakeOIDC(t)
			idp.amr = tc.amr
			idp.extra = map[string]any{}
			if tc.claim != nil {
				idp.extra["agentry_remember_device"] = tc.claim
			}
			if tc.authTime != 0 {
				idp.extra["auth_time"] = tc.authTime
			}
			env := newRememberEnv(t, idp, tc.on)
			res, userID := directorySignIn(t, env, idp, tc.provider)
			rows := trustedDeviceRows(t, env, userID)
			if !tc.want {
				requireNoCookie(t, res.Cookies(), trustedDeviceCookie)
				if rows != 0 {
					t.Fatalf("%d records minted, want none", rows)
				}
				// A sign-in whose factor was skipped is no evidence of one
				// for the publish gate either.
				if len(tc.amr) == 1 {
					var stamped bool
					if err := env.st.Pool().QueryRow(context.Background(),
						`SELECT idp_mfa_at IS NOT NULL FROM users WHERE id = $1::uuid`, userID).Scan(&stamped); err != nil || stamped {
						t.Fatalf("a skipped factor stamped idp_mfa_at (%v, %v)", stamped, err)
					}
				}
				return
			}
			c := requireSetCookieAt(t, res.Cookies(), trustedDeviceCookie, flowExecutorPath, "", int(deviceTTL.Seconds()), false)
			if !strings.HasPrefix(c.Value, "agyd_") {
				t.Fatalf("cookie %q is not an agyd_ token", c.Value)
			}
			if rows != 1 {
				t.Fatalf("%d records minted, want 1", rows)
			}
			// The record is the cookie's, its owner's, and absolute: 30 days
			// from now, not from some later use.
			var owned bool
			var expires time.Time
			if err := env.st.Pool().QueryRow(context.Background(),
				`SELECT user_id = $2::uuid, expires_at FROM trusted_devices WHERE token_sha256 = $1`,
				auth.HashToken(c.Value), userID).Scan(&owned, &expires); err != nil {
				t.Fatalf("no record for the cookie's token: %v", err)
			}
			if !owned {
				t.Fatal("the record belongs to someone else")
			}
			if d := time.Until(expires) - deviceTTL; d > time.Minute || d < -time.Minute {
				t.Fatalf("expires in %v, want %v", time.Until(expires), deviceTTL)
			}
			var audited int
			if err := env.st.Pool().QueryRow(context.Background(),
				`SELECT count(*) FROM audit_events WHERE action = 'user.trusted_device_add' AND actor_id = $1::uuid AND detail->>'via' = 'directory'`,
				userID).Scan(&audited); err != nil {
				t.Fatal(err)
			}
			if audited != 1 {
				t.Fatalf("%d user.trusted_device_add rows marked via directory, want 1", audited)
			}
		})
	}
}

// checkTrust asks the check route as the directory's policy does: bearer
// secret, {token, sub}. It returns the status and, on a 200, the answer.
func checkTrust(t *testing.T, env *testEnv, secret string, body any) (int, bool) {
	t.Helper()
	return checkTrustWith(t, env, secret, body, nil)
}

// checkTrustWith is checkTrust with extra request headers.
func checkTrustWith(t *testing.T, env *testEnv, secret string, body any, headers map[string]string) (int, bool) {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, env.srv.URL+"/internal/directory/trusted-device", strings.NewReader(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return res.StatusCode, false
	}
	var out struct {
		Trusted *bool `json:"trusted"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil || out.Trusted == nil {
		t.Fatalf("a 200 without a boolean trusted: %v", err)
	}
	return res.StatusCode, *out.Trusted
}

// rememberedBrowser signs a fresh directory user in with the box ticked and
// the code answered, and returns the environment, the directory's subject
// for that user, the user's id and the cookie's token.
func rememberedBrowser(t *testing.T) (*testEnv, *fakeOIDC, string, string) {
	t.Helper()
	idp := newFakeOIDC(t)
	idp.amr = []string{"pwd", "mfa"}
	idp.extra = map[string]any{"agentry_remember_device": true, "auth_time": fresh()}
	env := newRememberEnv(t, idp, true)
	res, userID := directorySignIn(t, env, idp, "authentik")
	c := requireSetCookieAt(t, res.Cookies(), trustedDeviceCookie, flowExecutorPath, "", int(deviceTTL.Seconds()), false)
	return env, idp, userID, c.Value
}

// TestDirectoryTrustCheck is the route the directory's MFA-stage policy
// calls before asking for the code. It answers trusted:true for exactly a
// live record owned by the directory user named, and false for everything
// else, and it answers only the directory.
func TestDirectoryTrustCheck(t *testing.T) {
	env, idp, userID, token := rememberedBrowser(t)
	ctx := context.Background()
	sub := idp.sub

	if st, ok := checkTrust(t, env, directoryTrustToken, map[string]string{"token": token, "sub": sub}); st != http.StatusOK || !ok {
		t.Fatalf("the remembered browser: %d trusted=%v, want 200 true", st, ok)
	}
	var seen bool
	if err := env.st.Pool().QueryRow(ctx,
		`SELECT last_seen_at IS NOT NULL FROM trusted_devices WHERE user_id = $1::uuid`, userID).Scan(&seen); err != nil || !seen {
		t.Fatalf("a trusted answer did not record the use (last_seen_at set = %v, %v)", seen, err)
	}
	var used int
	if err := env.st.Pool().QueryRow(ctx,
		`SELECT count(*) FROM audit_events WHERE action = 'user.trusted_device_use' AND actor_id = $1::uuid AND detail->>'via' = 'directory'`,
		userID).Scan(&used); err != nil || used != 1 {
		t.Fatalf("%d user.trusted_device_use rows, want 1 (%v)", used, err)
	}

	// Another directory user, signed in through the same directory without
	// remembering: the fake IdP now asserts a different subject.
	otherSub := "other-" + randSuffix()
	idp.sub, idp.email, idp.extra = otherSub, "other-"+randSuffix()+"@example.test", nil
	_, _ = directorySignIn(t, env, idp, "authentik")

	for _, tc := range []struct {
		name   string
		secret string
		body   any
		status int
	}{
		{"no secret", "", map[string]string{"token": token, "sub": sub}, http.StatusUnauthorized},
		{"the wrong secret", directoryTrustToken + "x", map[string]string{"token": token, "sub": sub}, http.StatusUnauthorized},
		{"no token", directoryTrustToken, map[string]string{"sub": sub}, http.StatusBadRequest},
		{"no subject", directoryTrustToken, map[string]string{"token": token}, http.StatusBadRequest},
		{"not JSON", directoryTrustToken, "not an object", http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if st, _ := checkTrust(t, env, tc.secret, tc.body); st != tc.status {
				t.Fatalf("got %d, want %d", st, tc.status)
			}
		})
	}

	for _, tc := range []struct {
		name string
		body map[string]string
	}{
		{"another user's browser", map[string]string{"token": token, "sub": otherSub}},
		{"a subject the registry does not know", map[string]string{"token": token, "sub": "nobody-" + randSuffix()}},
		{"a token nobody was issued", map[string]string{"token": "agyd_not-a-real-token", "sub": sub}},
	} {
		t.Run("untrusted: "+tc.name, func(t *testing.T) {
			if st, ok := checkTrust(t, env, directoryTrustToken, tc.body); st != http.StatusOK || ok {
				t.Fatalf("got %d trusted=%v, want 200 false", st, ok)
			}
		})
	}

	// The directory calls the registry directly on the private network. A
	// request that came through a proxy, which is what an ingress in front
	// of the api adds, is answered as though the route did not exist, even
	// with the right secret.
	for _, h := range []string{"X-Forwarded-For", "Forwarded"} {
		t.Run("through a proxy: "+h, func(t *testing.T) {
			if st, _ := checkTrustWith(t, env, directoryTrustToken, map[string]string{"token": token, "sub": sub}, map[string]string{h: "for=203.0.113.9"}); st != http.StatusNotFound {
				t.Fatalf("got %d, want 404", st)
			}
		})
	}

	// The record's own state: each change is undone before the next.
	for _, tc := range []struct{ name, set, undo string }{
		{"a revoked record", `UPDATE trusted_devices SET revoked_at = now() WHERE user_id = $1::uuid`, `UPDATE trusted_devices SET revoked_at = NULL WHERE user_id = $1::uuid`},
		{"an expired record", `UPDATE trusted_devices SET expires_at = now() - interval '1 second' WHERE user_id = $1::uuid`, `UPDATE trusted_devices SET expires_at = now() + interval '1 day' WHERE user_id = $1::uuid`},
		{"a suspended account", `UPDATE users SET state = 'suspended' WHERE id = $1::uuid`, `UPDATE users SET state = 'active' WHERE id = $1::uuid`},
	} {
		t.Run("untrusted: "+tc.name, func(t *testing.T) {
			if _, err := env.st.Pool().Exec(ctx, tc.set, userID); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _, _ = env.st.Pool().Exec(ctx, tc.undo, userID) })
			if st, ok := checkTrust(t, env, directoryTrustToken, map[string]string{"token": token, "sub": sub}); st != http.StatusOK || ok {
				t.Fatalf("got %d trusted=%v, want 200 false", st, ok)
			}
		})
	}
	// Every change above was undone: the browser is trusted again, which
	// proves the refusals were the record's state and not a broken fixture.
	if st, ok := checkTrust(t, env, directoryTrustToken, map[string]string{"token": token, "sub": sub}); st != http.StatusOK || !ok {
		t.Fatalf("after undoing every change: %d trusted=%v, want 200 true", st, ok)
	}
}

// TestDirectoryTrustCheckFailsClosed: a store the check cannot read answers
// an error, never a yes, and the directory's policy turns anything but an
// explicit yes into "ask for the code". The table is renamed out from under
// the lookup, as the native path's own test does.
func TestDirectoryTrustCheckFailsClosed(t *testing.T) {
	env, idp, _, token := rememberedBrowser(t)
	ctx := context.Background()
	if _, err := env.st.Pool().Exec(ctx, `ALTER TABLE trusted_devices RENAME TO trusted_devices_hidden`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := env.st.Pool().Exec(ctx, `ALTER TABLE trusted_devices_hidden RENAME TO trusted_devices`); err != nil {
			t.Fatalf("restore the table: %v", err)
		}
	})
	if st, ok := checkTrust(t, env, directoryTrustToken, map[string]string{"token": token, "sub": idp.sub}); st != http.StatusServiceUnavailable || ok {
		t.Fatalf("an unreadable store: %d trusted=%v, want 503", st, ok)
	}
}

// TestDirectoryTrustCheckIsAbsentWhenOff: without the secret the directory
// path does not exist, so the route answers as if it never had.
func TestDirectoryTrustCheckIsAbsentWhenOff(t *testing.T) {
	idp := newFakeOIDC(t)
	env := newRememberEnv(t, idp, false)
	if st, _ := checkTrust(t, env, directoryTrustToken, map[string]string{"token": "agyd_x", "sub": idp.sub}); st != http.StatusNotFound {
		t.Fatalf("got %d, want 404", st)
	}
}

// TestDirectoryRememberCookieCoversTheDirectorysHost is the shape of a
// hosted deployment: the registry at a host, the directory on a subdomain of it.
// The cookie is set for the registry's host so the browser sends it to the
// directory's flow executor (that domain also covers the
// registry's other subdomains).
func TestDirectoryRememberCookieCoversTheDirectorysHost(t *testing.T) {
	idp := newFakeOIDC(t)
	idp.base = "http://auth.registry.test:" + idp.srv.URL[strings.LastIndex(idp.srv.URL, ":")+1:]
	idp.amr = []string{"pwd", "mfa"}
	idp.extra = map[string]any{"agentry_remember_device": true, "auth_time": fresh()}
	env := newRememberEnv(t, idp, true, "http://registry.test")
	res, _ := directorySignIn(t, env, idp, "authentik")
	requireSetCookieAt(t, res.Cookies(), trustedDeviceCookie, flowExecutorPath, "registry.test", int(deviceTTL.Seconds()), false)
}

// signInCaller is directorySignIn for a test that goes on to call the API as
// that browser: the session cookie it was given and the CSRF token the
// callback's body carries.
func signInCaller(t *testing.T, env *testEnv, idp *fakeOIDC) (caller, *http.Response) {
	t.Helper()
	authURL, state, cookie := env.socialStart(t, "authentik")
	visit, err := idp.hostClient().Get(authURL.String())
	if err != nil {
		t.Fatal(err)
	}
	_ = visit.Body.Close()
	res := env.socialCallback(t, "authentik", state, cookie)
	t.Cleanup(func() { _ = res.Body.Close() })
	if res.StatusCode != http.StatusOK {
		t.Fatalf("callback: got %d want 200", res.StatusCode)
	}
	var out struct {
		CsrfToken string `json:"csrfToken"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	c := caller{name: "directory user", csrf: out.CsrfToken}
	for _, ck := range res.Cookies() {
		if ck.Name == "agentry_session" {
			c.session = ck.Value
		}
	}
	if c.session == "" || c.csrf == "" {
		t.Fatal("the callback gave no session or no CSRF token")
	}
	return c, res
}

// TestClearTrustedDevices is the account's one control over remembered
// browsers: a count the site shows, and a clear that
// revokes every one of the caller's, this browser's included. It follows the
// session routes' rule: a token reads 0 and cannot clear.
func TestClearTrustedDevices(t *testing.T) {
	idp := newFakeOIDC(t)
	idp.amr = []string{"pwd", "mfa"}
	idp.extra = map[string]any{"agentry_remember_device": true, "auth_time": fresh()}
	env := newRememberEnv(t, idp, true)
	ctx := context.Background()

	// Two remembered browsers for this person.
	me, first := signInCaller(t, env, idp)
	firstToken := requireSetCookieAt(t, first.Cookies(), trustedDeviceCookie, flowExecutorPath, "", int(deviceTTL.Seconds()), false).Value
	idp.extra["auth_time"] = fresh()
	_, second := signInCaller(t, env, idp)
	secondToken := requireSetCookieAt(t, second.Cookies(), trustedDeviceCookie, flowExecutorPath, "", int(deviceTTL.Seconds()), false).Value
	sub := idp.sub

	// Someone else, remembered too, whose record a clear must not touch.
	idp.sub, idp.email = "other-"+randSuffix(), "other-"+randSuffix()+"@example.test"
	idp.extra["auth_time"] = fresh()
	_, otherRes := signInCaller(t, env, idp)
	otherToken := requireSetCookieAt(t, otherRes.Cookies(), trustedDeviceCookie, flowExecutorPath, "", int(deviceTTL.Seconds()), false).Value
	otherSub := idp.sub

	// An expired record of this person's: inert, so neither counted nor
	// reported as cleared.
	if _, err := env.st.Pool().Exec(ctx,
		`INSERT INTO trusted_devices (id, user_id, token_sha256, expires_at)
		 SELECT gen_random_uuid(), user_id, sha256(random()::text::bytea), now() - interval '1 hour'
		 FROM identities WHERE subject = $1`, "authentik:"+sub); err != nil {
		t.Fatal(err)
	}

	var count struct {
		Count *int `json:"count"`
	}
	env.doJSON(me, http.MethodGet, "/api/v1/user/trusted-devices", nil, &count, http.StatusOK)
	if count.Count == nil || *count.Count != 2 {
		t.Fatalf("count = %s, want 2", intOrNil(count.Count))
	}

	// A token: no inventory, and no clear.
	_, pat := env.mintPAT(me, "clear-check", "user:profile")
	tokenCaller := caller{name: "pat", pat: pat}
	env.doJSON(tokenCaller, http.MethodGet, "/api/v1/user/trusted-devices", nil, &count, http.StatusOK)
	if count.Count == nil || *count.Count != 0 {
		t.Fatalf("a token read count = %s, want 0", intOrNil(count.Count))
	}
	env.doJSON(tokenCaller, http.MethodDelete, "/api/v1/user/trusted-devices", nil, nil, http.StatusForbidden)

	// A browser request without the CSRF header is refused, as every
	// cookie-authenticated mutation is.
	noCSRF := me
	noCSRF.csrf = ""
	env.doJSON(noCSRF, http.MethodDelete, "/api/v1/user/trusted-devices", nil, nil, http.StatusForbidden)

	// The clear.
	res := env.do(me, http.MethodDelete, "/api/v1/user/trusted-devices", nil)
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
	// This browser's cookie is cleared wherever this server may have set it:
	// the directory path's and the native path's.
	requireClearedCookieAt(t, res.Cookies(), trustedDeviceCookie, flowExecutorPath, "", false)
	requireClearedCookieAt(t, res.Cookies(), trustedDeviceCookie, "/", "", false)

	env.doJSON(me, http.MethodGet, "/api/v1/user/trusted-devices", nil, &count, http.StatusOK)
	if count.Count == nil || *count.Count != 0 {
		t.Fatalf("count after the clear = %s, want 0", intOrNil(count.Count))
	}
	// Cleared means the directory's next check says no for each of them:
	// the code is asked.
	for i, tok := range []string{firstToken, secondToken} {
		if st, ok := checkTrust(t, env, directoryTrustToken, map[string]string{"token": tok, "sub": sub}); st != http.StatusOK || ok {
			t.Fatalf("cleared browser %d: %d trusted=%v, want 200 false", i+1, st, ok)
		}
	}
	// And someone else's browser is still remembered.
	if st, ok := checkTrust(t, env, directoryTrustToken, map[string]string{"token": otherToken, "sub": otherSub}); st != http.StatusOK || !ok {
		t.Fatalf("another account's browser after the clear: %d trusted=%v, want 200 true", st, ok)
	}

	// The audit trail is this account's: the test database is shared, so
	// every audit query is scoped to the person, found by their identity.
	var myID string
	if err := env.st.Pool().QueryRow(ctx,
		`SELECT user_id::text FROM identities WHERE subject = $1`, "authentik:"+sub).Scan(&myID); err != nil {
		t.Fatal(err)
	}
	var audited int
	if err := env.st.Pool().QueryRow(ctx,
		`SELECT count(*) FROM audit_events WHERE action = 'user.trusted_device_revoke' AND actor_id = $1::uuid AND detail->>'scope' = 'all' AND (detail->>'count')::int = 2`, myID).Scan(&audited); err != nil || audited != 1 {
		t.Fatalf("%d user.trusted_device_revoke rows for the clear, want 1 (%v)", audited, err)
	}

	// Nothing left: a second clear answers 0 and writes no audit row.
	env.doJSON(me, http.MethodDelete, "/api/v1/user/trusted-devices", nil, &cleared, http.StatusOK)
	if cleared.Cleared == nil || *cleared.Cleared != 0 {
		t.Fatalf("a second clear = %s, want 0", intOrNil(cleared.Cleared))
	}
	if err := env.st.Pool().QueryRow(ctx,
		`SELECT count(*) FROM audit_events WHERE action = 'user.trusted_device_revoke' AND actor_id = $1::uuid AND detail->>'scope' = 'all'`, myID).Scan(&audited); err != nil || audited != 1 {
		t.Fatalf("%d clear audit rows after a clear with nothing to clear, want still 1 (%v)", audited, err)
	}
}

func intOrNil(p *int) string {
	if p == nil {
		return "absent"
	}
	return strconv.Itoa(*p)
}

// TestDirectoryRememberedBrowserSurvivesLogout: signing out of
// the registry leaves a browser remembered through the directory's sign-in,
// and the directory's next check still says yes. The directory's own sign-out
// (the agentry-invalidation flow) ends the directory's session and calls
// nothing of the registry's, so it cannot touch the record at all.
func TestDirectoryRememberedBrowserSurvivesLogout(t *testing.T) {
	idp := newFakeOIDC(t)
	idp.amr = []string{"pwd", "mfa"}
	idp.extra = map[string]any{"agentry_remember_device": true, "auth_time": fresh()}
	env := newRememberEnv(t, idp, true)
	me, res := signInCaller(t, env, idp)
	token := requireSetCookieAt(t, res.Cookies(), trustedDeviceCookie, flowExecutorPath, "", int(deviceTTL.Seconds()), false).Value
	out := env.do(me, http.MethodPost, "/api/v1/auth/logout", nil)
	_ = out.Body.Close()
	if out.StatusCode != http.StatusNoContent {
		t.Fatalf("logout: %d", out.StatusCode)
	}
	requireNoCookie(t, out.Cookies(), trustedDeviceCookie)
	if st, ok := checkTrust(t, env, directoryTrustToken, map[string]string{"token": token, "sub": idp.sub}); st != http.StatusOK || !ok {
		t.Fatalf("after logout: %d trusted=%v, want 200 true", st, ok)
	}
}
