package api_test

// Sign-in for individual accounts through the deployment's OpenID
// provider. The provider is in-process and signs real ID tokens, so the
// handler chain — state cookie, code exchange, identity linking, session
// issue — runs exactly as in production.

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/coreos/go-oidc/v3/oidc/oidctest"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/config"
)

func writeTestJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// ---- driving the two-leg flow ----

// socialStart hits the start endpoint and returns the provider authorization
// URL the browser would follow, the state parameter, and the sealed cookie.
func (env *testEnv) socialStart(t *testing.T, provider string) (authURL *url.URL, state string, cookie *http.Cookie) {
	t.Helper()
	client := *env.srv.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res, err := client.Get(env.srv.URL + "/api/v1/auth/oidc/" + provider + "/start")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("start %s: got %d want 302", provider, res.StatusCode)
	}
	authURL, err = url.Parse(res.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	state = authURL.Query().Get("state")
	if state == "" {
		t.Fatalf("start %s: authorization URL carries no state", provider)
	}
	for _, c := range res.Cookies() {
		if c.Name == "agentry_social_state" {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatalf("start %s: no sealed state cookie", provider)
	}
	return authURL, state, cookie
}

// socialCallback completes the flow with the state cookie in hand.
func (env *testEnv) socialCallback(t *testing.T, provider, state string, cookie *http.Cookie) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet,
		env.srv.URL+"/api/v1/auth/oidc/"+provider+"/callback?code=test-code&state="+url.QueryEscape(state), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(cookie)
	client := *env.srv.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// socialStartBrowser starts a browser-mode sign-in through the "oidc"
// provider, returning to /dashboard, and returns the provider's authorization URL, the state and the sealed
// state cookie.
func (env *testEnv) socialStartBrowser(t *testing.T) (authURL *url.URL, state string, cookie *http.Cookie) {
	t.Helper()
	client := *env.srv.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res, err := client.Get(env.srv.URL + "/api/v1/auth/oidc/oidc/start?next=" + url.QueryEscape("/dashboard"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("start oidc: got %d want 302", res.StatusCode)
	}
	if authURL, err = url.Parse(res.Header.Get("Location")); err != nil {
		t.Fatal(err)
	}
	for _, c := range res.Cookies() {
		if c.Name == "agentry_social_state" {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatalf("start oidc: no sealed state cookie")
	}
	return authURL, authURL.Query().Get("state"), cookie
}

// requireCookieAttributes asserts how a cookie was set: where it applies,
// who can read it, when it may be sent, and how long it lives.
func requireCookieAttributes(t *testing.T, c *http.Cookie, secure bool, maxAge int) {
	t.Helper()
	if c == nil {
		t.Fatal("cookie missing")
	}
	if c.Path != "/" || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Secure != secure || c.MaxAge != maxAge {
		t.Fatalf("%s set with Path=%q HttpOnly=%v SameSite=%v Secure=%v MaxAge=%d, want / HttpOnly Lax Secure=%v MaxAge=%d",
			c.Name, c.Path, c.HttpOnly, c.SameSite, c.Secure, c.MaxAge, secure, maxAge)
	}
}

func findCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name && c.Value != "" {
			return c
		}
	}
	return nil
}

// oidcEnv is a test server whose sign-in OpenID provider is idp, served as
// "oidc".
func oidcEnv(t *testing.T, idp *fakeOIDC) *testEnv {
	t.Helper()
	return newTestEnvCfg(t, idp.configure, func(s *api.Server) {
		s.SetOIDCHTTPClient(idp.srv.Client())
	})
}

// configure registers the server with idp as its sign-in OpenID provider.
func (p *fakeOIDC) configure(cfg *config.Config) {
	cfg.Auth.OIDC = config.OIDCProvider{ClientID: p.clientID, ClientSecret: "oidc-secret", Issuer: p.srv.URL}
}

// oidcLogin runs the whole flow against idp in API mode: the start, the
// browser's visit to the provider (where it learns the nonce), the callback.
func (env *testEnv) oidcLogin(t *testing.T, idp *fakeOIDC) *http.Response {
	t.Helper()
	authURL, state, cookie := env.socialStart(t, "oidc")
	visit, err := idp.srv.Client().Get(authURL.String())
	if err != nil {
		t.Fatal(err)
	}
	_ = visit.Body.Close()
	return env.socialCallback(t, "oidc", state, cookie)
}

// ---- tests ----

func TestSocialLoginJITCreatesAccount(t *testing.T) {
	idp := newFakeOIDC(t)
	idp.email = "jit-" + randSuffix() + "@idp.test"
	env := oidcEnv(t, idp)

	res := env.oidcLogin(t, idp)
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("social callback: got %d want 200", res.StatusCode)
	}
	var out struct {
		User struct {
			Id            string `json:"id"`
			Handle        string `json:"handle"`
			DisplayName   string `json:"displayName"`
			Email         string `json:"email"`
			EmailVerified bool   `json:"emailVerified"`
		} `json:"user"`
		CsrfToken string `json:"csrfToken"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.CsrfToken == "" {
		t.Fatalf("expected a session, got %+v", out)
	}
	if !strings.HasPrefix(out.CsrfToken, "csrf_") {
		t.Fatalf("csrf token %q lacks its prefix", out.CsrfToken[:min(len(out.CsrfToken), 6)])
	}
	// The provider sent no name: the account is named for its handle.
	if out.User.DisplayName == "" || out.User.DisplayName != out.User.Handle {
		t.Fatalf("display name %q, want the handle %q", out.User.DisplayName, out.User.Handle)
	}
	if out.User.Email != idp.email {
		t.Fatalf("email = %q, want %q", out.User.Email, idp.email)
	}
	if !out.User.EmailVerified {
		t.Fatal("a provider-verified email must land verified")
	}

	// The session works, and the identity is recorded as social with a
	// provider-namespaced subject.
	var session string
	for _, c := range res.Cookies() {
		if c.Name == "agentry_session" {
			session = c.Value
		}
	}
	if session == "" {
		t.Fatal("no session cookie")
	}
	if !strings.HasPrefix(session, auth.SessionPrefix) {
		t.Fatalf("session token lacks the %q prefix", auth.SessionPrefix)
	}
	// The session cookie is the page's secret: HttpOnly, Lax, an hour long
	// (the test server's session lifetime), and so is the row behind it.
	requireCookieAttributes(t, findCookie(res.Cookies(), "agentry_session"), false, 3600)
	var expiresAt time.Time
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT expires_at FROM sessions WHERE token_sha256 = $1`, auth.HashToken(session)).Scan(&expiresAt); err != nil {
		t.Fatal(err)
	}
	if left := time.Until(expiresAt); left < 55*time.Minute || left > 61*time.Minute {
		t.Fatalf("the session expires in %s, want the configured hour", left)
	}
	who := env.do(caller{name: "social", session: session}, http.MethodGet, "/api/v1/user", nil)
	_ = who.Body.Close()
	if who.StatusCode != http.StatusOK {
		t.Fatalf("social session GET /user: got %d want 200", who.StatusCode)
	}

	var kind, subject string
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT provider_kind, subject FROM identities WHERE user_id = $1::uuid`, out.User.Id,
	).Scan(&kind, &subject); err != nil {
		t.Fatal(err)
	}
	wantSubject := "oidc:" + idp.sub
	if kind != "social" || subject != wantSubject {
		t.Fatalf("identity = %s/%s, want social/%s", kind, subject, wantSubject)
	}

	// The audit trail says the account was made by this provider's sign-in
	// and that no second factor was asserted (the operator reads that before
	// requiring one).
	var created, login map[string]any
	var raw []byte
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT detail FROM audit_events WHERE action = 'user.social_login' AND target_id = $1::uuid`, out.User.Id).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal(raw, &created)
	if created["jit"] != true || created["provider"] != "oidc" {
		t.Fatalf("user.social_login detail = %s, want jit by oidc", raw)
	}
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT detail FROM audit_events WHERE action = 'user.login' AND target_id = $1::uuid`, out.User.Id).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal(raw, &login)
	if amr, ok := login["amr"].([]any); login["method"] != "social" || login["provider"] != "oidc" || !ok || len(amr) != 0 {
		t.Fatalf("user.login detail = %s, want method social, provider oidc and an empty amr list", raw)
	}

	// A second login through the same provider reuses the account rather than
	// creating another.
	res2 := env.oidcLogin(t, idp)
	_ = res2.Body.Close()
	if res2.StatusCode != http.StatusOK {
		t.Fatalf("repeat social login: got %d want 200", res2.StatusCode)
	}
	var accounts int64
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM users WHERE email = $1`, idp.email).Scan(&accounts); err != nil {
		t.Fatal(err)
	}
	if accounts != 1 {
		t.Fatalf("%d accounts for one provider identity", accounts)
	}

	// A known identity is not re-litigated: the provider now asserting the
	// address of another account does not move the identity, and the second
	// factor it names is on the record.
	other := env.register("soc-known")
	firstEmail := idp.email
	idp.email, idp.amr = other+"@example.test", []string{"pwd", "otp"}
	res3 := env.oidcLogin(t, idp)
	defer func() { _ = res3.Body.Close() }()
	var again struct {
		User struct {
			Id string `json:"id"`
		} `json:"user"`
	}
	if res3.StatusCode != http.StatusOK || json.NewDecoder(res3.Body).Decode(&again) != nil || again.User.Id != out.User.Id {
		t.Fatalf("a known identity asserting another account's address: %d, account %q, want 200 as %q", res3.StatusCode, again.User.Id, out.User.Id)
	}
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT detail FROM audit_events WHERE action = 'user.login' AND target_id = $1::uuid ORDER BY occurred_at DESC LIMIT 1`, out.User.Id).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal(raw, &login)
	if amr, _ := login["amr"].([]any); len(amr) != 2 || amr[0] != "pwd" || amr[1] != "otp" {
		t.Fatalf("user.login detail = %s, want the amr the provider named", raw)
	}
	idp.email, idp.amr = firstEmail, nil

	// An account that is not active gets no session.
	if _, err := env.st.Pool().Exec(context.Background(), `UPDATE users SET state = 'suspended' WHERE id = $1::uuid`, out.User.Id); err != nil {
		t.Fatal(err)
	}
	res4 := env.oidcLogin(t, idp)
	_ = res4.Body.Close()
	if res4.StatusCode != http.StatusUnauthorized || findCookie(res4.Cookies(), "agentry_session") != nil {
		t.Fatalf("sign-in of a suspended account: %d, session cookie %v, want 401 with none", res4.StatusCode, findCookie(res4.Cookies(), "agentry_session"))
	}

	// A browser is sent back to sign in with the reason, and holds no session.
	authURL, state, cookie := env.socialStartBrowser(t)
	if v, err := idp.srv.Client().Get(authURL.String()); err == nil {
		_ = v.Body.Close()
	}
	browser := env.socialCallback(t, "oidc", state, cookie)
	_ = browser.Body.Close()
	if loc := browser.Header.Get("Location"); browser.StatusCode != http.StatusSeeOther || !strings.HasPrefix(loc, "/ui/login?error=") || findCookie(browser.Cookies(), "agentry_session") != nil {
		t.Fatalf("browser-mode sign-in of a suspended account: %d Location %q, want a 303 to the sign-in page and no session", browser.StatusCode, loc)
	}

	// An address the provider does not vouch for makes an account whose
	// address is unconfirmed.
	idp.sub, idp.email, idp.emailUnverified = "s-"+randSuffix(), "unv-"+randSuffix()+"@idp.test", true
	res5 := env.oidcLogin(t, idp)
	defer func() { _ = res5.Body.Close() }()
	var unverified struct {
		User struct {
			Id            string `json:"id"`
			EmailVerified bool   `json:"emailVerified"`
		} `json:"user"`
	}
	if res5.StatusCode != http.StatusOK || json.NewDecoder(res5.Body).Decode(&unverified) != nil {
		t.Fatalf("sign-in with an unvouched address: %d", res5.StatusCode)
	}
	var verifiedAt *time.Time
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT email_verified_at FROM users WHERE id = $1::uuid`, unverified.User.Id).Scan(&verifiedAt); err != nil {
		t.Fatal(err)
	}
	if unverified.User.EmailVerified || verifiedAt != nil {
		t.Fatalf("an address the provider did not vouch for landed verified: body %v, row %v", unverified.User.EmailVerified, verifiedAt)
	}
}

func TestSocialLoginAutoLinksVerifiedEmail(t *testing.T) {
	idp := newFakeOIDC(t)
	env := oidcEnv(t, idp)

	// An existing account whose OWN email is verified.
	handle := env.register("soc-link")
	idp.email = handle + "@example.test"

	res := env.oidcLogin(t, idp)
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("auto-link: got %d want 200", res.StatusCode)
	}
	var out struct {
		User struct {
			Handle string `json:"handle"`
		} `json:"user"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.User.Handle != handle {
		t.Fatalf("auto-link produced %q, want the existing account %q", out.User.Handle, handle)
	}
	// The link is recorded against the account, as a social identity under
	// the provider's namespace, and audited as the person.
	var kind, subject string
	var raw []byte
	var actor string
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT i.provider_kind, i.subject FROM identities i JOIN handles h ON h.id = i.user_id WHERE h.handle = $1`, handle).Scan(&kind, &subject); err != nil {
		t.Fatalf("the auto-link recorded no identity: %v", err)
	}
	if kind != "social" || subject != "oidc:"+idp.sub {
		t.Fatalf("identity = %s/%s, want social/oidc:%s", kind, subject, idp.sub)
	}
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT a.actor_kind, a.detail FROM audit_events a JOIN handles h ON h.id = a.target_id WHERE a.action = 'user.social_login' AND h.handle = $1`, handle).Scan(&actor, &raw); err != nil {
		t.Fatalf("the auto-link was not audited: %v", err)
	}
	var detail map[string]any
	_ = json.Unmarshal(raw, &detail)
	if actor != "user" || detail["linked"] != true || detail["provider"] != "oidc" {
		t.Fatalf("user.social_login row: actor %s, detail %s, want a link by oidc as the person", actor, raw)
	}
}

func TestSocialLoginRefusesUnverifiedLink(t *testing.T) {
	// An email match is only evidence of ownership when BOTH sides are
	// verified. Either half missing means an explicit link, not a takeover.
	t.Run("provider has not verified the address", func(t *testing.T) {
		idp := newFakeOIDC(t)
		env := oidcEnv(t, idp)
		handle := env.register("soc-unv1")
		idp.email = handle + "@example.test"
		idp.emailUnverified = true

		res := env.oidcLogin(t, idp)
		// An address the provider does not vouch for is no evidence of
		// ownership: an explicit link, never a silent takeover.
		if res.StatusCode != http.StatusConflict {
			t.Fatalf("got %d want 409 (explicit link required)", res.StatusCode)
		}
		if got := problemType(t, res); got != "sso-link-required" {
			t.Fatalf("problem type %q, want sso-link-required", got)
		}
		var linked int64
		if err := env.st.Pool().QueryRow(context.Background(),
			`SELECT count(*) FROM identities i JOIN handles h ON h.id = i.user_id WHERE h.handle = $1`,
			handle).Scan(&linked); err != nil {
			t.Fatal(err)
		}
		if linked != 0 {
			t.Fatal("an unverified provider email must never link to an existing account")
		}
	})

	t.Run("account has not verified its own address", func(t *testing.T) {
		idp := newFakeOIDC(t)
		env := oidcEnv(t, idp)
		handle := env.registerUnverified("soc-unv2")
		idp.email = handle + "@example.test"

		res := env.oidcLogin(t, idp)
		if res.StatusCode != http.StatusConflict {
			t.Fatalf("got %d want 409 (explicit link required)", res.StatusCode)
		}
		if got := problemType(t, res); got != "sso-link-required" {
			t.Fatalf("problem type %q, want sso-link-required", got)
		}
	})

	t.Run("an unconfirmed account the directory cannot be asked about", func(t *testing.T) {
		// The account signed in through the provider without its address
		// vouched for; a later sign-in at that address with the address
		// vouched for is not told the account is gone when nothing can say.
		idp := newFakeOIDC(t)
		env := oidcEnv(t, idp)
		idp.email = "squat-" + randSuffix() + "@idp.test"
		idp.emailUnverified = true
		squatter := firstSignIn(t, env, idp)
		idp.emailUnverified = false
		idp.sub = "s-" + randSuffix()
		res := env.oidcLogin(t, idp)
		if res.StatusCode != http.StatusConflict {
			t.Fatalf("got %d want 409 (explicit link required)", res.StatusCode)
		}
		_ = res.Body.Close()
		var state string
		if err := env.st.Pool().QueryRow(context.Background(),
			`SELECT u.state FROM users u JOIN handles h ON h.id = u.id WHERE h.handle = $1`, squatter).Scan(&state); err != nil || state != "active" {
			t.Fatalf("the unconfirmed account: %q, %v, want active", state, err)
		}
	})

	t.Run("a browser is sent back to sign-in with the reason", func(t *testing.T) {
		idp := newFakeOIDC(t)
		env := oidcEnv(t, idp)
		handle := env.register("soc-unv3")
		idp.email = handle + "@example.test"
		idp.emailUnverified = true

		authURL, state, cookie := env.socialStartBrowser(t)
		visit, err := idp.srv.Client().Get(authURL.String())
		if err != nil {
			t.Fatal(err)
		}
		_ = visit.Body.Close()
		res := env.socialCallback(t, "oidc", state, cookie)
		_ = res.Body.Close()
		if loc := res.Header.Get("Location"); res.StatusCode != http.StatusSeeOther || !strings.HasPrefix(loc, "/ui/login?error=") || !strings.Contains(loc, "already") {
			t.Fatalf("browser-mode refusal: %d Location %q, want a 303 to the sign-in page naming the reason", res.StatusCode, loc)
		}
		if findCookie(res.Cookies(), "agentry_session") != nil {
			t.Fatal("a refused link set a session cookie")
		}
	})
}

func TestSocialLoginBrowserModeRedirectsToNext(t *testing.T) {
	idp := newFakeOIDC(t)
	idp.email = "next-" + randSuffix() + "@idp.test"
	env := oidcEnv(t, idp)

	startWith := func(next string) (state string, cookie *http.Cookie) {
		t.Helper()
		client := *env.srv.Client()
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		res, err := client.Get(env.srv.URL + "/api/v1/auth/oidc/oidc/start?next=" + url.QueryEscape(next))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = res.Body.Close() }()
		if res.StatusCode != http.StatusFound {
			t.Fatalf("start: got %d want 302", res.StatusCode)
		}
		authURL, err := url.Parse(res.Header.Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range res.Cookies() {
			if c.Name == "agentry_social_state" {
				cookie = c
			}
		}
		if cookie == nil {
			t.Fatal("no sealed state cookie")
		}
		visit, err := idp.srv.Client().Get(authURL.String())
		if err != nil {
			t.Fatal(err)
		}
		_ = visit.Body.Close()
		return authURL.Query().Get("state"), cookie
	}

	state, cookie := startWith("/dashboard?tab=agents")
	// The sealed state is the flow's secret: out of a script's reach, sent
	// only to this site, and good for ten minutes.
	requireCookieAttributes(t, cookie, false, 600)
	res := env.socialCallback(t, "oidc", state, cookie)
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("browser-mode callback: got %d want 303", res.StatusCode)
	}
	requireClearedCookie(t, res.Cookies(), "agentry_social_state", cookie.Secure)
	if loc := res.Header.Get("Location"); loc != "/dashboard?tab=agents" {
		t.Fatalf("browser-mode callback: Location %q want /dashboard?tab=agents", loc)
	}
	var sess, csrf *http.Cookie
	for _, c := range res.Cookies() {
		if c.Name == "agentry_session" && c.Value != "" {
			sess = c
		}
		if c.Name == "agentry_csrf" && c.Value != "" {
			csrf = c
		}
	}
	if sess == nil {
		t.Fatal("browser-mode callback set no session cookie")
	}
	if csrf == nil {
		t.Fatal("browser-mode callback set no CSRF cookie — the web tier cannot echo a token it never received")
	}
	// Neither cookie is for page script, and each lives as long as the session.
	requireCookieAttributes(t, sess, false, 3600)
	requireCookieAttributes(t, csrf, false, 3600)
	who := env.do(caller{name: "browser", session: sess.Value}, http.MethodGet, "/api/v1/user", nil)
	defer func() { _ = who.Body.Close() }()
	if who.StatusCode != http.StatusOK {
		t.Fatalf("session from browser-mode login: /user got %d", who.StatusCode)
	}
	// The token the cookie carries is the one the session enforces: a
	// mutation that echoes it succeeds, one without it is refused.
	browser := caller{name: "browser", session: sess.Value, csrf: csrf.Value}
	ok := env.do(browser, http.MethodPatch, "/api/v1/user", map[string]any{"displayName": "Browser Mode"})
	_ = ok.Body.Close()
	if ok.StatusCode != http.StatusOK {
		t.Fatalf("mutation with the browser-mode CSRF cookie: got %d want 200", ok.StatusCode)
	}
	bare := env.do(caller{name: "browser-no-csrf", session: sess.Value}, http.MethodPatch, "/api/v1/user", map[string]any{"displayName": "x"})
	_ = bare.Body.Close()
	if bare.StatusCode != http.StatusForbidden {
		t.Fatalf("mutation without the CSRF header: got %d want 403", bare.StatusCode)
	}

	// A return path is admitted up to 512 bytes and not past it, and as is.
	long := "/" + strings.Repeat("a", 511)
	state, cookie = startWith(long)
	atLimit := env.socialCallback(t, "oidc", state, cookie)
	_ = atLimit.Body.Close()
	if atLimit.StatusCode != http.StatusSeeOther || atLimit.Header.Get("Location") != long {
		t.Fatalf("next of 512 bytes: %d Location %.40q, want a 303 to it", atLimit.StatusCode, atLimit.Header.Get("Location"))
	}

	for _, bad := range []string{"//evil.example/x", "/\\evil.example", "https://evil.example", "/dash\nboard", "",
		long + "a", "/dash\rboard", "/dash\x1fboard", "/dash\x7fboard", "/dash\x00board"} {
		state, cookie := startWith(bad)
		res := env.socialCallback(t, "oidc", state, cookie)
		_ = res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("next=%q: got %d; an unsafe next must fall back to API mode (200 JSON), never redirect", bad, res.StatusCode)
		}
		if loc := res.Header.Get("Location"); loc != "" {
			t.Fatalf("next=%q: redirected to %q", bad, loc)
		}
	}

	// On a deployment that serves cookies over TLS only, every one of them
	// is marked so.
	secureIdp := newFakeOIDC(t)
	secureIdp.email = "secure-" + randSuffix() + "@idp.test"
	secureEnv := newTestEnvCfg(t, func(cfg *config.Config) {
		secureIdp.configure(cfg)
		cfg.Auth.CookieSecure = true
	}, func(s *api.Server) { s.SetOIDCHTTPClient(secureIdp.srv.Client()) })
	authURL, state, cookie := secureEnv.socialStartBrowser(t)
	requireCookieAttributes(t, cookie, true, 600)
	if v, err := secureIdp.srv.Client().Get(authURL.String()); err == nil {
		_ = v.Body.Close()
	}
	secured := secureEnv.socialCallback(t, "oidc", state, cookie)
	_ = secured.Body.Close()
	if secured.StatusCode != http.StatusSeeOther {
		t.Fatalf("browser-mode callback on a secure deployment: %d", secured.StatusCode)
	}
	requireClearedCookie(t, secured.Cookies(), "agentry_social_state", true)
	// A browser that arrives without the state is told to start again, and
	// the mark that says so is as secure as the rest.
	restartReq, err := http.NewRequest(http.MethodGet, secureEnv.srv.URL+"/api/v1/auth/oidc/oidc/callback?code=c&state=x", nil)
	if err != nil {
		t.Fatal(err)
	}
	restartReq.Header.Set("Sec-Fetch-Mode", "navigate")
	noRedirect := *secureEnv.srv.Client()
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	restarted, err := noRedirect.Do(restartReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = restarted.Body.Close()
	requireCookieAttributes(t, findCookie(restarted.Cookies(), "agentry_social_restart"), true, 120)
	requireCookieAttributes(t, findCookie(secured.Cookies(), "agentry_session"), true, 3600)
	requireCookieAttributes(t, findCookie(secured.Cookies(), "agentry_csrf"), true, 3600)
}

// A browser landing on the callback without a usable state cookie is the
// cross-device email-confirmation case (signed up on the desktop, confirmed
// on the phone): the fix is a restart of the flow, not an error. One
// restart only — with the guard cookie already present the browser gets a
// message instead of a loop. Non-browser clients keep the 4xx.
func TestSocialLoginCallbackRestartsBrowserWithoutState(t *testing.T) {
	idp := newFakeOIDC(t)
	env := oidcEnv(t, idp)
	client := *env.srv.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	get := func(cookies ...*http.Cookie) *http.Response {
		req, err := http.NewRequest(http.MethodGet,
			env.srv.URL+"/api/v1/auth/oidc/oidc/callback?code=c&state=x", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Sec-Fetch-Mode", "navigate")
		req.Header.Set("Accept", "text/html")
		for _, c := range cookies {
			req.AddCookie(c)
		}
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}

	// First arrival: restart the flow, and set the guard cookie.
	res := get()
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("browser callback without state: got %d want 303", res.StatusCode)
	}
	if loc := res.Header.Get("Location"); loc != "/api/v1/auth/oidc/oidc/start?next=%2Fui%2F" {
		t.Fatalf("restart Location = %q", loc)
	}
	var guard *http.Cookie
	for _, c := range res.Cookies() {
		if c.Name == "agentry_social_restart" && c.Value != "" {
			guard = c
		}
	}
	if guard == nil {
		t.Fatal("restart did not set the loop-guard cookie")
	}
	// The guard is out of a script's reach and lives two minutes.
	requireCookieAttributes(t, guard, false, 120)

	// Second arrival with the guard: a message, not another restart.
	res2 := get(guard)
	defer func() { _ = res2.Body.Close() }()
	if res2.StatusCode != http.StatusSeeOther {
		t.Fatalf("guarded callback: got %d want 303", res2.StatusCode)
	}
	if loc := res2.Header.Get("Location"); !strings.HasPrefix(loc, "/ui/login?error=") {
		t.Fatalf("guarded callback Location = %q, want /login?error=…", loc)
	}

	// A guard with nothing in it guards nothing.
	res4 := get(&http.Cookie{Name: "agentry_social_restart", Value: ""})
	defer func() { _ = res4.Body.Close() }()
	if loc := res4.Header.Get("Location"); res4.StatusCode != http.StatusSeeOther || loc != "/api/v1/auth/oidc/oidc/start?next=%2Fui%2F" {
		t.Fatalf("callback with an empty guard: %d Location %q, want another restart", res4.StatusCode, loc)
	}

	// A browser is told by either of its two marks, and a client that has
	// neither is not.
	for _, tc := range []struct {
		name    string
		headers map[string]string
		want    int
	}{
		{"navigation mode alone", map[string]string{"Sec-Fetch-Mode": "navigate"}, http.StatusSeeOther},
		{"an html Accept alone", map[string]string{"Accept": "text/html,application/xhtml+xml"}, http.StatusSeeOther},
		{"a script's fetch", map[string]string{"Sec-Fetch-Mode": "cors", "Accept": "application/json"}, http.StatusUnprocessableEntity},
		{"a same-origin script", map[string]string{"Sec-Fetch-Mode": "same-origin"}, http.StatusUnprocessableEntity},
		{"a JSON Accept alone", map[string]string{"Accept": "application/json"}, http.StatusUnprocessableEntity},
	} {
		req, err := http.NewRequest(http.MethodGet, env.srv.URL+"/api/v1/auth/oidc/oidc/callback?code=c&state=x", nil)
		if err != nil {
			t.Fatal(err)
		}
		for k, v := range tc.headers {
			req.Header.Set(k, v)
		}
		got, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = got.Body.Close()
		if got.StatusCode != tc.want {
			t.Errorf("callback without state from %s: %d, want %d", tc.name, got.StatusCode, tc.want)
		}
	}

	// API clients (no navigation headers) keep the 422.
	req, _ := http.NewRequest(http.MethodGet,
		env.srv.URL+"/api/v1/auth/oidc/oidc/callback?code=c&state=x", nil)
	res3, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res3.Body.Close() }()
	if res3.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("api callback without state: got %d want 422", res3.StatusCode)
	}
}

func TestSocialLoginUnconfiguredProviderIs404(t *testing.T) {
	idp := newFakeOIDC(t)
	env := oidcEnv(t, idp) // served as oidc

	// The id the provider is not served under answers 404, so probing
	// cannot distinguish "misconfigured" from "not offered" and the page
	// shows no dead buttons.
	res := env.do(anonymous, http.MethodGet, "/api/v1/auth/oidc/authentik/start", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("authentik on a deployment serving oidc: got %d want 404", res.StatusCode)
	}
	// The path parameter is a closed enum, so the retired providers and an
	// unknown one never reach the handler.
	for _, p := range []string{"google", "github", "microsoft", "openai", "claude", "evilcorp"} {
		res := env.do(anonymous, http.MethodGet, "/api/v1/auth/oidc/"+p+"/start", nil)
		_ = res.Body.Close()
		if res.StatusCode == http.StatusFound {
			t.Fatalf("%s started a login", p)
		}
	}
}

func TestSocialLoginRejectsStateMismatch(t *testing.T) {
	idp := newFakeOIDC(t)
	idp.email = "state-" + randSuffix() + "@idp.test"
	env := oidcEnv(t, idp)

	_, _, cookie := env.socialStart(t, "oidc")
	res := env.socialCallback(t, "oidc", "not-the-state", cookie)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("state mismatch: got %d want 401", res.StatusCode)
	}
	// The sealed state is spent whatever came of the attempt.
	requireClearedCookie(t, res.Cookies(), "agentry_social_state", cookie.Secure)

	// The state is checked on its own, not left to the provider's checks: a
	// callback with the browser's visit to the provider behind it and a
	// state of its own making is refused all the same.
	{
		authURL, _, visitCookie := env.socialStart(t, "oidc")
		visit, err := idp.srv.Client().Get(authURL.String())
		if err != nil {
			t.Fatal(err)
		}
		_ = visit.Body.Close()
		forged := env.socialCallback(t, "oidc", "not-the-state", visitCookie)
		_ = forged.Body.Close()
		if forged.StatusCode != http.StatusUnauthorized || findCookie(forged.Cookies(), "agentry_session") != nil {
			t.Fatalf("state mismatch after the provider visit: %d, want 401 and no session", forged.StatusCode)
		}
	}

	{
		callback := func(path string, state string, cookie *http.Cookie) int {
			t.Helper()
			req, err := http.NewRequest(http.MethodGet, env.srv.URL+path+state, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.AddCookie(cookie)
			got, err := env.srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = got.Body.Close()
			return got.StatusCode
		}
		// A state sealed for another provider is not this provider's.
		_, state, cookie := env.socialStart(t, "oidc")
		if got := callback("/api/v1/auth/oidc/authentik/callback?code=c&state=", state, cookie); got != http.StatusUnauthorized {
			t.Fatalf("a state sealed for oidc presented to authentik: %d, want 401", got)
		}
		// A sealed state that was altered does not open; one that is not even
		// encoded is malformed.
		_, state, cookie = env.socialStart(t, "oidc")
		mid := len(cookie.Value) / 2
		flipped := "A"
		if cookie.Value[mid] == 'A' {
			flipped = "B"
		}
		altered := &http.Cookie{Name: cookie.Name, Value: cookie.Value[:mid] + flipped + cookie.Value[mid+1:]}
		if got := callback("/api/v1/auth/oidc/oidc/callback?code=c&state=", state, altered); got != http.StatusUnauthorized {
			t.Fatalf("an altered sealed state: %d, want 401", got)
		}
		if got := callback("/api/v1/auth/oidc/oidc/callback?code=c&state=", state, &http.Cookie{Name: cookie.Name, Value: "!!not-base64!!"}); got != http.StatusUnprocessableEntity {
			t.Fatalf("a sealed state that is not encoded: %d, want 422", got)
		}
		// A callback carrying no code, or an empty one, is refused before the
		// provider is asked anything.
		for name, query := range map[string]string{"no code": "", "an empty code": "code=&"} {
			_, state, cookie := env.socialStart(t, "oidc")
			if got := callback("/api/v1/auth/oidc/oidc/callback?"+query+"state=", state, cookie); got != http.StatusUnprocessableEntity {
				t.Fatalf("a callback with %s: %d, want 422", name, got)
			}
		}
	}

	// And without the sealed cookie at all.
	_, state, _ := env.socialStart(t, "oidc")
	req, _ := http.NewRequest(http.MethodGet,
		env.srv.URL+"/api/v1/auth/oidc/oidc/callback?code=c&state="+state, nil)
	bare, err := env.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = bare.Body.Close()
	if bare.StatusCode == http.StatusOK {
		t.Fatal("a callback without the state cookie must not establish a session")
	}
	if bare.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("a callback without the state cookie: %d, want 422", bare.StatusCode)
	}
}

// ---- the stand-in OpenID provider ----

// fakeOIDC is an in-process OIDC provider signing real ID tokens. Its
// /authorize endpoint records the nonce, as a real IdP does, so the ID token
// can echo it back — which is what makes the RP's nonce check meaningful.
type fakeOIDC struct {
	srv      *httptest.Server
	key      *rsa.PrivateKey
	clientID string
	sub      string
	email    string
	nonce    string
	// amr, when set, rides the ID token.
	amr []string
	// groups, when set, rides the ID token as the `groups` claim.
	groups []string
	// emailUnverified asserts the address without vouching for it
	// (the fold-in must not fire on one).
	emailUnverified bool
	// preferredUsername, when set, rides the ID token as the
	// `preferred_username` claim.
	preferredUsername string
	// extra claims ride the ID token as given (such as
	// agentry_remember_device).
	extra map[string]any
	// base, when set, is the issuer and endpoint origin the fake advertises
	// instead of its listener's address, so a test can give the IdP a host
	// name (the trusted-device cookie's domain); pair it with hostClient.
	base string
}

func newFakeOIDC(t *testing.T) *fakeOIDC {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &fakeOIDC{key: key, clientID: "oidc-client", sub: "s-" + randSuffix()}
	p.email = "person-" + randSuffix() + "@idp.test"
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(w, map[string]any{
			"issuer":                                p.origin(),
			"authorization_endpoint":                p.origin() + "/authorize",
			"token_endpoint":                        p.origin() + "/token",
			"jwks_uri":                              p.origin() + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())
		writeTestJSON(w, map[string]any{"keys": []map[string]any{
			{"kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig", "n": n, "e": e},
		}})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		p.nonce = r.URL.Query().Get("nonce")
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		// PKCE: the RP must send the verifier it committed to at /authorize.
		if r.FormValue("code_verifier") == "" {
			http.Error(w, "missing PKCE verifier", http.StatusBadRequest)
			return
		}
		claimMap := map[string]any{
			"iss": p.origin(), "aud": p.clientID, "sub": p.sub,
			"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
			"email": p.email, "email_verified": !p.emailUnverified,
			"nonce": p.nonce,
		}
		if p.amr != nil {
			claimMap["amr"] = p.amr
		}
		if p.groups != nil {
			claimMap["groups"] = p.groups
		}
		if p.preferredUsername != "" {
			claimMap["preferred_username"] = p.preferredUsername
		}
		for k, v := range p.extra {
			claimMap[k] = v
		}
		claims, _ := json.Marshal(claimMap)
		writeTestJSON(w, map[string]any{
			"access_token": "at", "token_type": "Bearer", "expires_in": 3600,
			"id_token": oidctest.SignIDToken(p.key, "k1", "RS256", string(claims)),
		})
	})
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	return p
}

// origin is where the fake says it lives: base when a test named one, else
// its listener.
func (p *fakeOIDC) origin() string {
	if p.base != "" {
		return p.base
	}
	return p.srv.URL
}

// hostClient reaches the fake whatever host name a URL uses, the way a
// resolver pointing that name at it would.
func (p *fakeOIDC) hostClient() *http.Client {
	addr := p.srv.Listener.Addr().String()
	return &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}}
}

// TestSocialLoginOpenIDProvider exercises the provider end to end —
// discovery, issuer pinning, PKCE (the token endpoint refuses a request with
// no verifier), and the nonce round trip.
func TestSocialLoginOpenIDProvider(t *testing.T) {
	idp := newFakeOIDC(t)
	env := oidcEnv(t, idp)

	authURL, state, cookie := env.socialStart(t, "oidc")
	if authURL.Query().Get("code_challenge") == "" {
		t.Fatal("the authorization URL carries no PKCE challenge")
	}
	q := authURL.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("response_type") != "code" || q.Get("client_id") != idp.clientID {
		t.Fatalf("authorization URL query = %v, want an S256 code flow for the client", q)
	}
	if q.Get("state") == "" || q.Get("nonce") == "" || q.Get("state") == q.Get("nonce") {
		t.Fatalf("the state %q and nonce %q must both be set and differ", q.Get("state"), q.Get("nonce"))
	}
	if scope := " " + q.Get("scope") + " "; !strings.Contains(scope, " openid ") || !strings.Contains(scope, " email ") {
		t.Fatalf("scope %q lacks openid or email", q.Get("scope"))
	}
	if want := env.srv.URL + "/api/v1/auth/oidc/oidc/callback"; q.Get("redirect_uri") != want {
		t.Fatalf("redirect_uri = %q, want %q", q.Get("redirect_uri"), want)
	}
	// The browser leg: this is where a real IdP learns the nonce.
	visit, err := idp.srv.Client().Get(authURL.String())
	if err != nil {
		t.Fatal(err)
	}
	_ = visit.Body.Close()

	res := env.socialCallback(t, "oidc", state, cookie)
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("callback: got %d want 200", res.StatusCode)
	}
	var out struct {
		User struct {
			Id    string `json:"id"`
			Email string `json:"email"`
		} `json:"user"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.User.Email != idp.email {
		t.Fatalf("email = %q, want %q", out.User.Email, idp.email)
	}
	var subject string
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT subject FROM identities WHERE user_id = $1::uuid`, out.User.Id).Scan(&subject); err != nil {
		t.Fatal(err)
	}
	if subject != "oidc:"+idp.sub {
		t.Fatalf("subject = %q, want oidc:%s", subject, idp.sub)
	}

	// With a public address configured, the redirect URI is that address
	// and this route, however the address is written.
	based := newTestEnvCfg(t, func(cfg *config.Config) {
		idp.configure(cfg)
		cfg.BaseURL = "https://agentry.example.test/"
	}, func(s *api.Server) { s.SetOIDCHTTPClient(idp.srv.Client()) })
	baseURL, _, _ := based.socialStart(t, "oidc")
	if want := "https://agentry.example.test/api/v1/auth/oidc/oidc/callback"; baseURL.Query().Get("redirect_uri") != want {
		t.Fatalf("redirect_uri with a configured address = %q, want %q", baseURL.Query().Get("redirect_uri"), want)
	}
}

// firstSignIn runs one API-mode sign-in through idp and returns the
// account's handle.
func firstSignIn(t *testing.T, env *testEnv, idp *fakeOIDC) string {
	t.Helper()
	res := env.oidcLogin(t, idp)
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("callback: got %d want 200", res.StatusCode)
	}
	var out struct {
		User struct {
			Handle string `json:"handle"`
		} `json:"user"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out.User.Handle
}

// TestSocialLoginHandleFromPreferredUsername: the username chosen at the
// directory's sign-up names the account, not the email's local part
// (`blaktron` with chris@… is `blaktron`, not `chris`).
func TestSocialLoginHandleFromPreferredUsername(t *testing.T) {
	idp := newFakeOIDC(t)
	env := oidcEnv(t, idp)
	idp.preferredUsername = "blaktron" + env.sfx
	idp.email = "chris" + env.sfx + "@example.test"

	if got := firstSignIn(t, env, idp); got != idp.preferredUsername {
		t.Fatalf("handle = %q, want the preferred_username %q", got, idp.preferredUsername)
	}
}

// TestSocialLoginTakenUsernameFallsBackDeterministically: a username that
// is already someone's handle gets a fallback that keeps the name, and the
// audit event records what was asked for.
func TestSocialLoginTakenUsernameFallsBackDeterministically(t *testing.T) {
	idp := newFakeOIDC(t)
	sealingKey := base64.StdEncoding.EncodeToString([]byte("taken-username-sealing-key-32-by"))
	var mu sync.Mutex
	var registered []api.Event
	env := newTestEnvCfg(t, func(cfg *config.Config) {
		idp.configure(cfg)
		cfg.Auth.SealingKey = sealingKey
	}, func(s *api.Server) {
		s.SetOIDCHTTPClient(idp.srv.Client())
		s.AddEventHook(func(_ context.Context, ev api.Event) {
			if ev.Kind == "user.registered" {
				mu.Lock()
				registered = append(registered, ev)
				mu.Unlock()
			}
		})
	})
	// The fallback is six hex characters of a keyed hash of the provider's
	// subject: the same person lands on the same name, and the public name
	// confirms no guess at the subject.
	suffixFor := func(sub string) string {
		mac := hmac.New(sha256.New, []byte(sealingKey))
		_, _ = mac.Write([]byte("handle-suffix:oidc-" + sub))
		return hex.EncodeToString(mac.Sum(nil))[:6]
	}
	taken := env.register("taken")
	idp.preferredUsername = taken
	idp.email = "other" + env.sfx + "@example.test"

	got := firstSignIn(t, env, idp)
	if got == taken || !strings.HasPrefix(got, taken+"-") {
		t.Fatalf("handle = %q, want %q with a suffix", got, taken)
	}
	if want := taken + "-" + suffixFor(idp.sub); got != want {
		t.Fatalf("handle = %q, want the name with the subject's keyed suffix %q", got, want)
	}
	var requested string
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT coalesce(detail->>'handleRequested', '') FROM audit_events
		  WHERE action = 'user.social_login' AND target_id = (SELECT id FROM handles WHERE handle = $1)`, got,
	).Scan(&requested); err != nil {
		t.Fatal(err)
	}
	if requested != taken {
		t.Fatalf("audit handleRequested = %q, want %q", requested, taken)
	}
	// Extensions hear the same difference between the name asked for and
	// the one given.
	mu.Lock()
	heard := append([]api.Event(nil), registered...)
	mu.Unlock()
	if len(heard) != 1 || heard[0].Payload["handleRequested"] != taken || heard[0].Payload["handle"] != got {
		t.Fatalf("user.registered events = %+v, want one naming %q asked for and %q given", heard, taken, got)
	}

	// The same person asking again lands on the same name: once the first
	// account has let its handle go, the subject gives it back.
	if _, err := env.st.Pool().Exec(context.Background(), `UPDATE handles SET handle = 'moved-' || handle WHERE handle = $1`, got); err != nil {
		t.Fatal(err)
	}
	if _, err := env.st.Pool().Exec(context.Background(), `DELETE FROM identities WHERE subject = $1`, "oidc:"+idp.sub); err != nil {
		t.Fatal(err)
	}
	idp.email = "again" + env.sfx + "@example.test"
	if again := firstSignIn(t, env, idp); again != got {
		t.Fatalf("the same subject asking again got %q, want %q", again, got)
	}

	// When even that name is taken the name falls to a random suffix, six
	// characters, still recognisably the one asked for.
	idp.sub = "s-" + randSuffix()
	idp.email = "third" + env.sfx + "@example.test"
	if _, err := env.st.Pool().Exec(context.Background(),
		`INSERT INTO handles (id, handle, kind) VALUES (gen_random_uuid(), $1, 'user')`, taken+"-"+suffixFor(idp.sub)); err != nil {
		t.Fatal(err)
	}
	third := firstSignIn(t, env, idp)
	if !regexp.MustCompile(`^`+taken+`-[a-z2-7]{6}$`).MatchString(third) || third == taken+"-"+suffixFor(idp.sub) {
		t.Fatalf("handle = %q, want %s with a random six-character suffix", third, taken)
	}

	// A long name is cut to leave room for the suffix, and the handle stays
	// inside its 39 characters.
	long := strings.Repeat("l", 33) + env.sfx
	idp.sub, idp.email, idp.preferredUsername = "s-"+randSuffix(), "long1"+env.sfx+"@example.test", long
	if first := firstSignIn(t, env, idp); first != long {
		t.Fatalf("handle = %q, want the long name %q", first, long)
	}
	idp.sub, idp.email = "s-"+randSuffix(), "long2"+env.sfx+"@example.test"
	if want := strings.Repeat("l", 30) + "-" + suffixFor(idp.sub); firstSignIn(t, env, idp) != want {
		t.Fatalf("a taken 39-character name did not fall back to %q", want)
	}
}

// TestSocialLoginNonceMismatch: an ID token whose nonce does not match
// the one this login committed to is refused, so a token minted for another
// session cannot be replayed into ours.
func TestSocialLoginNonceMismatch(t *testing.T) {
	idp := newFakeOIDC(t)
	idp.nonce = "a-different-login's-nonce"
	env := oidcEnv(t, idp)

	// Deliberately skip the /authorize leg so the IdP never learns our nonce.
	_, state, cookie := env.socialStart(t, "oidc")
	res := env.socialCallback(t, "oidc", state, cookie)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("nonce mismatch: got %d want 401", res.StatusCode)
	}

	// A browser is sent back to sign in with the reason, and holds no session.
	_, state, cookie = env.socialStartBrowser(t)
	browser := env.socialCallback(t, "oidc", state, cookie)
	_ = browser.Body.Close()
	if loc := browser.Header.Get("Location"); browser.StatusCode != http.StatusSeeOther || !strings.HasPrefix(loc, "/ui/login?error=") {
		t.Fatalf("browser-mode nonce mismatch: %d Location %q, want a 303 to the sign-in page", browser.StatusCode, loc)
	}
	if findCookie(browser.Cookies(), "agentry_session") != nil {
		t.Fatal("a refused sign-in set a session cookie")
	}
}

// randSuffix is lowercase hex: emails and handles are case-insensitive
// (citext), so a mixed-case suffix would not survive the round trip.
func randSuffix() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

var _ = coreoidc.ScopeOpenID
