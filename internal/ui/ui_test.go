package ui

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/blaktron/agentry/internal/auth"
)

// The one session and CSRF pair the fake authorizes; sessCookie and
// csrfCookieV below carry them. A request without the session is signed out,
// and a mutation without the header is refused — which is how the signed-out
// and missing-token cases in this file are written.
const (
	fakeSession = "sess1"
	fakeCSRF    = "csrf1"
)

// fakeAPI stands in for the server: it checks that the in-process call
// carried the browser's session cookie (and the CSRF header on mutations)
// and answers canned JSON.
func fakeAPI(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSession := ""
		if c, err := r.Cookie("agentry_session"); err == nil {
			gotSession = c.Value
		}
		authed := gotSession == fakeSession
		if r.Method != http.MethodGet && authed && r.Header.Get("X-Agentry-CSRF") != fakeCSRF {
			http.Error(w, `{"detail":"missing or invalid CSRF token"}`, http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /api/v1/user":
			if !authed {
				http.Error(w, `{"detail":"sign in"}`, http.StatusUnauthorized)
				return
			}
			_, _ = io.WriteString(w, `{"id":"u1","handle":"chris","email":"c@example.test","displayName":"Chris","emailVerified":true}`)
		case "POST /api/v1/user/tokens/desktop-grant":
			if !authed {
				http.Error(w, `{"detail":"sign in"}`, http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"code":"agd_code","expiresAt":"2026-01-01T00:00:00Z"}`)
		case "POST /api/v1/auth/logout":
			if !authed {
				http.Error(w, `{"detail":"sign in"}`, http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case "POST /api/v1/auth/verify-email":
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["token"] != "good" {
				http.Error(w, `{"detail":"This verification link is invalid or expired."}`, http.StatusUnprocessableEntity)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, `{"detail":"no such fake route `+r.Method+` `+r.URL.Path+`"}`, http.StatusNotFound)
		}
	})
}

func newUI(t *testing.T, opt Options) http.Handler {
	t.Helper()
	if opt.API == nil {
		opt.API = fakeAPI(t)
	}
	return New(opt)
}

func get(h http.Handler, path string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func post(h http.Handler, path string, form url.Values, hdr map[string]string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

var (
	sessCookie  = &http.Cookie{Name: "agentry_session", Value: fakeSession}
	csrfCookieV = &http.Cookie{Name: "agentry_csrf", Value: fakeCSRF}
)

func TestAuthorizeNeedsASession(t *testing.T) {
	h := newUI(t, Options{})
	w := get(h, "/ui/authorize?port=40123&state=abcdefghij")
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/ui/login?next=%2Fui%2Fauthorize%3Fport%3D40123%26state%3Dabcdefghij" {
		t.Fatalf("signed out: %d %s", w.Code, w.Header().Get("Location"))
	}
	// With a site in front, sign-in is the site's.
	h = newUI(t, Options{SiteURL: "https://site.example", Mode: "authorize"})
	w = get(h, "/ui/authorize?port=40123&state=abcdefghij")
	if loc := w.Header().Get("Location"); w.Code != http.StatusSeeOther || !strings.HasPrefix(loc, "https://site.example/login?next=") {
		t.Fatalf("site: %d %s", w.Code, loc)
	}
	// Signed in: the page, with the loopback address in it.
	w = get(newUI(t, Options{}), "/ui/authorize?port=40123&state=abcdefghij", sessCookie, csrfCookieV)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "127.0.0.1:40123") || !strings.Contains(w.Body.String(), "chris") {
		t.Fatalf("page: %d %s", w.Code, w.Body.String())
	}
	// The page names exactly what approving grants: the grant's own list,
	// not a hand-kept copy that could fall behind it.
	if want := "Scopes: " + strings.Join(auth.SignInGrantScopes(), ", ") + "."; !strings.Contains(w.Body.String(), want) || !strings.Contains(want, "secret:write") {
		t.Fatalf("authorize page does not name the grant's scopes %q:\n%s", want, w.Body.String())
	}
	if csp := w.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "form-action 'self' http://127.0.0.1:*") || !strings.Contains(csp, "default-src 'none'") {
		t.Fatalf("csp: %q", csp)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-store, no-transform" {
		t.Fatalf("cache-control: %q", cc)
	}
	if !strings.Contains(w.Body.String(), "/ui/static/ui.css?v="+stylesheetVersion) || len(stylesheetVersion) != 12 {
		t.Fatalf("stylesheet link not versioned by content: %q", stylesheetVersion)
	}
	// Malformed parameters: a page that says so, not a form.
	w = get(newUI(t, Options{}), "/ui/authorize?port=80&state=x", sessCookie, csrfCookieV)
	if w.Code != http.StatusBadRequest || strings.Contains(w.Body.String(), `name="state"`) {
		t.Fatalf("invalid params: %d", w.Code)
	}
}

func TestAuthorizeApproveHandsTheLoopbackACode(t *testing.T) {
	h := newUI(t, Options{})
	form := url.Values{"_csrf": {"csrf1"}, "port": {"40123"}, "state": {"abcdefghij"}}
	w := post(h, "/ui/authorize", form, nil, sessCookie, csrfCookieV)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "http://127.0.0.1:40123/callback?code=agd_code&state=abcdefghij" {
		t.Fatalf("approve: %d %s %s", w.Code, w.Header().Get("Location"), w.Body.String())
	}
	// Cross-site posts and posts without the CSRF field are refused before
	// anything reaches the API.
	w = post(h, "/ui/authorize", form, map[string]string{"Sec-Fetch-Site": "cross-site"}, sessCookie, csrfCookieV)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-site: %d", w.Code)
	}
	w = post(h, "/ui/authorize", url.Values{"port": {"40123"}, "state": {"abcdefghij"}}, nil, sessCookie, csrfCookieV)
	if w.Code != http.StatusForbidden {
		t.Fatalf("no csrf field: %d", w.Code)
	}
	// A bad port never becomes a redirect target.
	w = post(h, "/ui/authorize", url.Values{"_csrf": {"csrf1"}, "port": {"22"}, "state": {"abcdefghij"}}, nil, sessCookie, csrfCookieV)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("bad port: %d", w.Code)
	}
}

func TestModeAuthorizeServesOnlyTheAuthorizePage(t *testing.T) {
	h := newUI(t, Options{Mode: "authorize", SiteURL: "https://site.example"})
	if w := get(h, "/ui/login"); w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "serves no page at this address") {
		t.Fatalf("login in authorize mode: %d %s", w.Code, w.Body.String())
	}
	if w := get(h, "/ui/verify-email?token=good"); w.Code != http.StatusNotFound {
		t.Fatalf("verify-email in authorize mode: %d", w.Code)
	}
	if w := get(h, "/ui/"); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "https://site.example/" {
		t.Fatalf("landing: %d %s", w.Code, w.Header().Get("Location"))
	}
}

// The four refusals answer with the message page inside the layout, carrying
// the reason and the same CSP as any other page. A path that exists under
// another method keeps the mux's 405.
func TestRefusalsRenderInsideTheLayout(t *testing.T) {
	h := newUI(t, Options{Brand: Brand{Name: "Acme Registry"}})
	raw := func(method, path, body string, hdr map[string]string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		for _, c := range cookies {
			r.AddCookie(c)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	// The CSP every page carries, taken from a page that renders normally.
	ok := get(h, "/ui/authorize?port=40123&state=abcdefghij", sessCookie, csrfCookieV)
	csp := ok.Header().Get("Content-Security-Policy")
	if ok.Code != http.StatusOK || !strings.Contains(csp, "default-src 'none'") {
		t.Fatalf("reference page: %d %q", ok.Code, csp)
	}
	for _, tc := range []struct {
		name     string
		got      *httptest.ResponseRecorder
		status   int
		reason   string
		signedIn bool
	}{
		{"cross-origin post", raw(http.MethodPost, "/ui/authorize", "_csrf=csrf1&port=40123&state=abcdefghij", map[string]string{"Sec-Fetch-Site": "cross-site"}, sessCookie, csrfCookieV), http.StatusForbidden, "posted from another site", true},
		{"unparseable form", raw(http.MethodPost, "/ui/authorize", "%zz=1", nil, sessCookie, csrfCookieV), http.StatusBadRequest, "could not read this form", true},
		{"missing csrf field", raw(http.MethodPost, "/ui/authorize", "port=40123&state=abcdefghij", nil, sessCookie, csrfCookieV), http.StatusForbidden, "does not match your cookie", true},
		{"unknown path", raw(http.MethodGet, "/ui/nope", "", nil), http.StatusNotFound, "serves no page at this address", false},
	} {
		body := tc.got.Body.String()
		if tc.got.Code != tc.status {
			t.Fatalf("%s: status %d, want %d", tc.name, tc.got.Code, tc.status)
		}
		if !strings.Contains(body, "<main>") || !strings.Contains(body, "Acme Registry") {
			t.Fatalf("%s: not the layout: %s", tc.name, body)
		}
		if !strings.Contains(body, tc.reason) {
			t.Fatalf("%s: reason %q missing: %s", tc.name, tc.reason, body)
		}
		if ct := tc.got.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
			t.Fatalf("%s: content-type %q", tc.name, ct)
		}
		if got := tc.got.Header().Get("Content-Security-Policy"); got != csp {
			t.Fatalf("%s: csp %q, want %q", tc.name, got, csp)
		}
		// A refusal is a page like any other, and no-store applies to it:
		// nothing about a rejected form or a wrong address is cacheable, and a
		// CDN in front must not rewrite it either.
		if cc := tc.got.Header().Get("Cache-Control"); cc != "no-store, no-transform" {
			t.Fatalf("%s: cache-control %q", tc.name, cc)
		}
		// No page here is a dead end: with no Referer to return to, the link is
		// this surface's entrance.
		if !strings.Contains(body, ">Go to the registry</a>") {
			t.Fatalf("%s: no way back: %s", tc.name, body)
		}
		// A refusal is not a sign-out. With a session it keeps Sign out;
		// without one it carries none.
		chrome := strings.Contains(body, ">Sign out</button>")
		if chrome != tc.signedIn {
			t.Fatalf("%s: signed-in chrome %v, want %v: %s", tc.name, chrome, tc.signedIn, body)
		}
	}
	// The way back is the Referer when it is a path on this origin (the test
	// request's Host is example.com), and never an off-site one.
	if body := raw(http.MethodGet, "/ui/nope", "", map[string]string{"Referer": "http://example.com/ui/login"}).Body.String(); !strings.Contains(body, `href="/ui/login"`) || !strings.Contains(body, ">Go back</a>") {
		t.Fatalf("same-origin referer is not the way back: %s", body)
	}
	if body := raw(http.MethodGet, "/ui/nope", "", map[string]string{"Referer": "https://evil.example/x"}).Body.String(); strings.Contains(body, "evil.example") || !strings.Contains(body, ">Go to the registry</a>") {
		t.Fatalf("off-site referer became the way back: %s", body)
	}
	// A registered path reached with the wrong method is still the mux's 405,
	// not this surface's 404 page.
	if w := raw(http.MethodGet, "/ui/logout", "", nil); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("method mismatch: %d %s", w.Code, w.Body.String())
	}
}

func TestLoginPageIsTheOneThatReadsAnErrorFromTheURL(t *testing.T) {
	h := newUI(t, Options{})
	w := get(h, "/ui/login?error=Sign-in+with+%3Cb%3Ex%3C%2Fb%3E+failed.&ok=Welcome")
	body := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(body, `<p class="flash error">Sign-in with &lt;b&gt;x&lt;/b&gt; failed.</p>`) || strings.Contains(body, "Welcome") {
		t.Fatalf("login with ?error=: %d %s", w.Code, body)
	}
	one := newUI(t, Options{Providers: []Provider{{ID: "authentik", Label: "Acme"}}})
	if w := get(one, "/ui/login"); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/api/v1/auth/oidc/authentik/start?next=%2Fui%2F" {
		t.Fatalf("one provider, nothing to say: %d %s", w.Code, w.Header().Get("Location"))
	}
	if w := get(one, "/ui/login?error=Sign-in+failed."); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Sign-in failed.") || !strings.Contains(w.Body.String(), "Continue with Acme") {
		t.Fatalf("one provider, a message: %d", w.Code)
	}
	rec := httptest.NewRecorder()
	one.(*handler).setFlash(rec, "", "Sign-in succeeded but no session was issued. You are not signed in.")
	if w := get(one, "/ui/login", rec.Result().Cookies()[0]); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "no session was issued") {
		t.Fatalf("one provider, a flash: %d %s", w.Code, w.Body.String())
	}
}

// TestLoginIsAHandOffToTheProvider: the sign-in page has no form of its
// own. It returns where the browser came from (a same-origin next, the
// landing otherwise), offers each provider, and says plainly when there is
// none to offer.
func TestLoginIsAHandOffToTheProvider(t *testing.T) {
	two := newUI(t, Options{Providers: []Provider{{ID: "authentik", Label: "Acme"}, {ID: "oidc", Label: "Other"}}})
	w := get(two, "/ui/login?next=%2Fui%2Fauthorize%3Fport%3D40123")
	body := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(body, `href="/api/v1/auth/oidc/authentik/start?next=%2Fui%2Fauthorize%3Fport%3D40123"`) || !strings.Contains(body, "Continue with Other") {
		t.Fatalf("two providers: %d %s", w.Code, body)
	}
	if strings.Contains(body, "<form") || strings.Contains(body, `type="password"`) {
		t.Fatalf("the sign-in page carries a form: %s", body)
	}
	w = get(two, "/ui/login?next=https%3A%2F%2Fevil.example%2F")
	if body := w.Body.String(); strings.Contains(body, "evil.example") || !strings.Contains(body, "start?next=%2Fui%2F") {
		t.Fatalf("an off-site next survived: %s", body)
	}
	w = get(newUI(t, Options{}), "/ui/login")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "has not configured one") {
		t.Fatalf("no provider: %d %s", w.Code, w.Body.String())
	}
	// Signed in already: straight on to next.
	w = get(two, "/ui/login?next=%2Fui%2Fauthorize", sessCookie)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/ui/authorize" {
		t.Fatalf("signed in: %d %s", w.Code, w.Header().Get("Location"))
	}
	// There is nothing to post to.
	if w := post(two, "/ui/login", url.Values{"login": {"chris"}, "password": {"pw"}}, nil); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /ui/login: %d", w.Code)
	}
}

// TestOnlyTheSignInAndAuthorizePagesAreServed: the account, token, SSH key,
// session, review, staff, organization and invitation pages are not this
// surface's, in either mode.
func TestOnlyTheSignInAndAuthorizePagesAreServed(t *testing.T) {
	for _, mode := range []string{"full", "authorize"} {
		h := newUI(t, Options{Mode: mode})
		for _, path := range []string{"/ui/account", "/ui/account/tokens", "/ui/account/ssh-keys", "/ui/account/sessions", "/ui/review", "/ui/review/x", "/ui/staff", "/ui/orgs", "/ui/orgs/acme", "/ui/invitations/tok"} {
			if w := get(h, path, sessCookie, csrfCookieV); w.Code != http.StatusNotFound {
				t.Errorf("%s mode: GET %s = %d, want 404", mode, path, w.Code)
			}
		}
	}
}

// TestLandingSaysWhoIsSignedIn: a signed-in visitor is named, as text, with
// Sign out beside it; a signed-out one is sent to sign in.
func TestLandingSaysWhoIsSignedIn(t *testing.T) {
	base := fakeAPI(t)
	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("agentry_session"); r.URL.Path == "/api/v1/user" && err == nil && c.Value == fakeSession {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "u1", "handle": "<b>chris</b>", "email": "c@example.test"})
			return
		}
		base.ServeHTTP(w, r)
	})
	h := newUI(t, Options{API: api})
	w := get(h, "/ui/", sessCookie, csrfCookieV)
	body := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(body, "You are signed in as &lt;b&gt;chris&lt;/b&gt;.") || strings.Contains(body, "<b>chris</b>") || !strings.Contains(body, ">Sign out</button>") {
		t.Fatalf("landing, signed in: %d %s", w.Code, body)
	}
	if w := get(h, "/ui/"); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/ui/login" {
		t.Fatalf("landing, signed out: %d %s", w.Code, w.Header().Get("Location"))
	}
}

// TestLogoutRevokesAndClears: sign-out posts through the API and clears
// both cookies, then ends at the provider's sign-out where one is set.
func TestLogoutRevokesAndClears(t *testing.T) {
	h := newUI(t, Options{IdPLogoutURL: "https://idp.example/logout"})
	w := post(h, "/ui/logout", url.Values{"_csrf": {fakeCSRF}}, nil, sessCookie, csrfCookieV)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "https://idp.example/logout" {
		t.Fatalf("logout: %d %s", w.Code, w.Header().Get("Location"))
	}
	cleared := map[string]bool{}
	for _, c := range w.Result().Cookies() {
		if c.MaxAge < 0 {
			cleared[c.Name] = true
		}
	}
	if !cleared["agentry_session"] || !cleared["agentry_csrf"] {
		t.Fatalf("cookies not cleared: %v", w.Result().Cookies())
	}
	if w := post(h, "/ui/logout", url.Values{}, nil, sessCookie, csrfCookieV); w.Code != http.StatusForbidden {
		t.Fatalf("logout without the form token: %d", w.Code)
	}
}

// TestVerifyEmailConfirmsThroughTheAPI: the activation link's page posts
// the token and says how it went.
func TestVerifyEmailConfirmsThroughTheAPI(t *testing.T) {
	h := newUI(t, Options{})
	if w := get(h, "/ui/verify-email?token=good"); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "account is activated") {
		t.Fatalf("good token: %d %s", w.Code, w.Body.String())
	}
	if w := get(h, "/ui/verify-email?token=bad"); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "invalid or expired") {
		t.Fatalf("bad token: %d %s", w.Code, w.Body.String())
	}
	if w := get(h, "/ui/verify-email"); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "missing its token") {
		t.Fatalf("no token: %d", w.Code)
	}
}

// The directory's sign-out URL is a redirect chain that browsers hold to the
// page's form-action; the policy admits its origin and nothing more of it,
// so a path and a query on the same host (a cancel-view shape) change
// nothing here.
func TestCSPAdmitsTheSignOutOrigin(t *testing.T) {
	h := newUI(t, Options{IdPLogoutURL: "https://auth.site.example/flows/-/cancel/?next=/application/o/agentry/end-session/", SiteURL: "https://site.example"})
	w := get(h, "/ui/login")
	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "form-action 'self' http://127.0.0.1:* https://auth.site.example https://site.example") {
		t.Fatalf("csp: %q", csp)
	}
	if strings.Contains(csp, "cancel") || strings.Contains(csp, "end-session") {
		t.Fatalf("csp carries more than the origin: %q", csp)
	}
}
