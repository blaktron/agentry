package ui

import (
	"encoding/base64"
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
		case "POST /api/v1/auth/login":
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["password"] != "pw" {
				http.Error(w, `{"type":"about:blank","detail":"invalid credentials"}`, http.StatusUnauthorized)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "agentry_session", Value: fakeSession, Path: "/", HttpOnly: true, MaxAge: 3600})
			_, _ = io.WriteString(w, `{"csrfToken":"csrf1","user":{"id":"u1","handle":"chris"}}`)
		case "POST /api/v1/user/tokens/desktop-grant":
			if !authed {
				http.Error(w, `{"detail":"sign in"}`, http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"code":"agd_code","expiresAt":"2026-01-01T00:00:00Z"}`)
		case "PATCH /api/v1/user":
			_, _ = io.WriteString(w, `{"id":"u1"}`)
		case "GET /api/v1/user/notifications":
			if !authed {
				http.Error(w, `{"detail":"sign in"}`, http.StatusUnauthorized)
				return
			}
			_, _ = io.WriteString(w, `{"email":{"dependencyAlerts":true,"quarantine":true,"reviewDecisions":false,"advisories":true,"orgInvites":true},"web":{"dependencyAlerts":true}}`)
		case "GET /api/v1/knowledge/usage":
			if !authed {
				http.Error(w, `{"detail":"sign in"}`, http.StatusUnauthorized)
				return
			}
			_, _ = io.WriteString(w, `{"bytes":3670016,"packs":2,"used":3670016,"max":104857600,"pooled":false}`)
		case "PUT /api/v1/user/notifications":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			b, _ := json.Marshal(body)
			_, _ = w.Write(b)
		case "GET /api/v1/user/ssh-keys":
			if !authed {
				http.Error(w, `{"detail":"sign in"}`, http.StatusUnauthorized)
				return
			}
			_, _ = io.WriteString(w, `[{"id":"k1","title":"laptop","keyType":"ssh-ed25519","fingerprint":"SHA256:abc","createdAt":"2026-01-01T00:00:00Z"}]`)
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

// flashOf decodes the flash cookie a redirect set (ui.go back): the ok and
// error notices the next render will show. A redirect without one yields
// two empty strings and no cookie.
func flashOf(t *testing.T, w *httptest.ResponseRecorder) (okMsg, errMsg string, cookie *http.Cookie) {
	t.Helper()
	for _, c := range w.Result().Cookies() {
		if c.Name != flashCookie || c.MaxAge < 0 {
			continue
		}
		b, err := base64.RawURLEncoding.DecodeString(c.Value)
		if err != nil {
			t.Fatalf("flash cookie: %v", err)
		}
		var f flash
		if err := json.Unmarshal(b, &f); err != nil {
			t.Fatalf("flash cookie: %v", err)
		}
		return f.OK, f.Error, c
	}
	return "", "", nil
}

// redirectedTo reports the redirect's target, ok notice and error notice.
func redirectedTo(t *testing.T, w *httptest.ResponseRecorder) (loc, okMsg, errMsg string) {
	t.Helper()
	okMsg, errMsg, _ = flashOf(t, w)
	return w.Header().Get("Location"), okMsg, errMsg
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

func TestLoginMirrorsTheSessionOntoTheBrowser(t *testing.T) {
	h := newUI(t, Options{})
	w := post(h, "/ui/login", url.Values{"login": {"chris"}, "password": {"pw"}, "next": {"/ui/account/tokens"}}, nil)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/ui/account/tokens" {
		t.Fatalf("login: %d %s %s", w.Code, w.Header().Get("Location"), w.Body.String())
	}
	var sess, csrf bool
	for _, c := range w.Result().Cookies() {
		switch c.Name {
		case "agentry_session":
			sess = c.Value == "sess1" && c.HttpOnly && c.MaxAge == 3600
		case "agentry_csrf":
			csrf = c.Value == "csrf1" && c.HttpOnly && c.MaxAge == 3600
		}
	}
	if !sess || !csrf {
		t.Fatalf("cookies: %v", w.Result().Cookies())
	}
	// Wrong password: back to the form with the message in the flash
	// cookie and no session or CSRF cookie.
	w = post(h, "/ui/login", url.Values{"login": {"chris"}, "password": {"nope"}}, nil)
	if loc, _, errMsg := redirectedTo(t, w); w.Code != http.StatusSeeOther || loc != "/ui/login?login=chris&next=%2Fui%2Faccount" || errMsg != "invalid credentials" {
		t.Fatalf("bad login: %d %s %q", w.Code, loc, errMsg)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name != flashCookie {
			t.Fatalf("bad login set a cookie: %v", c)
		}
	}
	// An open redirect is not a next.
	w = post(h, "/ui/login", url.Values{"login": {"chris"}, "password": {"pw"}, "next": {"https://evil.example/"}}, nil)
	if w.Header().Get("Location") != "/ui/account" {
		t.Fatalf("next: %s", w.Header().Get("Location"))
	}
}

func TestModeAuthorizeServesOnlyTheAuthorizePage(t *testing.T) {
	h := newUI(t, Options{Mode: "authorize", SiteURL: "https://site.example"})
	if w := get(h, "/ui/login"); w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "serves no page at this address") {
		t.Fatalf("login in authorize mode: %d %s", w.Code, w.Body.String())
	}
	if w := get(h, "/ui/account", sessCookie); w.Code != http.StatusNotFound {
		t.Fatalf("account in authorize mode: %d", w.Code)
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
		// A refusal is not a sign-out. With a session it keeps the section nav
		// and Sign out; without one it carries neither.
		chrome := strings.Contains(body, ">Sign out</button>") && strings.Contains(body, `class="sections"`)
		if chrome != tc.signedIn {
			t.Fatalf("%s: signed-in chrome %v, want %v: %s", tc.name, chrome, tc.signedIn, body)
		}
	}
	// The way back is the Referer when it is a path on this origin (the test
	// request's Host is example.com), and never an off-site one.
	if body := raw(http.MethodGet, "/ui/nope", "", map[string]string{"Referer": "http://example.com/ui/account/tokens"}).Body.String(); !strings.Contains(body, `href="/ui/account/tokens"`) || !strings.Contains(body, ">Go back</a>") {
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

func TestAccountPagesAndTheDirectoryRedirect(t *testing.T) {
	h := newUI(t, Options{Brand: Brand{Name: "Acme Registry", SupportEmail: "help@example.test"}})
	w := get(h, "/ui/account", sessCookie, csrfCookieV)
	body := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(body, "Acme Registry") || !strings.Contains(body, "help@example.test") || !strings.Contains(body, `value="Chris"`) {
		t.Fatalf("account: %d %s", w.Code, body)
	}
	if w := get(h, "/ui/account"); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/ui/login?next=%2Fui%2Faccount" {
		t.Fatalf("signed out: %d %s", w.Code, w.Header().Get("Location"))
	}
	w = post(h, "/ui/account", url.Values{"_csrf": {"csrf1"}, "displayName": {"C."}}, nil, sessCookie, csrfCookieV)
	okMsg, _, flashC := flashOf(t, w)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/ui/account" || okMsg != "Profile saved." || flashC == nil || !flashC.HttpOnly || flashC.Path != "/ui" {
		t.Fatalf("save: %d %s %q %v", w.Code, w.Header().Get("Location"), okMsg, flashC)
	}
	// The render that follows shows the flash once and clears the cookie.
	w = get(h, "/ui/account", sessCookie, csrfCookieV, flashC)
	if !strings.Contains(w.Body.String(), `<p class="flash ok">Profile saved.</p>`) {
		t.Fatalf("flash not shown: %s", w.Body.String())
	}
	var cleared bool
	for _, c := range w.Result().Cookies() {
		if c.Name == flashCookie && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatalf("flash cookie not cleared: %v", w.Result().Cookies())
	}
	// The flash is text, never markup.
	rec := httptest.NewRecorder()
	h.(*handler).setFlash(rec, "", "<b>x</b>")
	w = get(h, "/ui/account", sessCookie, csrfCookieV, rec.Result().Cookies()[0])
	if strings.Contains(w.Body.String(), "<b>x</b>") || !strings.Contains(w.Body.String(), "&lt;b&gt;x&lt;/b&gt;") {
		t.Fatalf("flash escaping: %s", w.Body.String())
	}
	// The URL cannot choose a page's notice: ?ok= and ?error= are ignored
	// everywhere, the 404 page included.
	for _, path := range []string{"/ui/account?ok=Token+revoked.&error=%3Cb%3Ex%3C%2Fb%3E", "/ui/no-such?ok=Token+revoked."} {
		w = get(h, path, sessCookie, csrfCookieV)
		if body := w.Body.String(); strings.Contains(body, "Token revoked.") || strings.Contains(body, "x&lt;/b&gt;") || strings.Contains(body, `class="flash ok"`) {
			t.Fatalf("%s: the URL chose a flash: %s", path, body)
		}
	}
}

// The SSH keys page: the only template no test executed, so a broken action
// in it would have reached a reader first. It carries the key's identity and
// the one claim the page makes about what a key is worth.
func TestSSHKeysPageRendersTheKeyAndItsLimits(t *testing.T) {
	h := newUI(t, Options{Brand: Brand{Name: "Acme Registry"}})
	w := get(h, "/ui/account/ssh-keys", sessCookie, csrfCookieV)
	body := w.Body.String()
	if w.Code != http.StatusOK {
		t.Fatalf("ssh keys: %d %s", w.Code, body)
	}
	for _, want := range []string{
		"<strong>laptop</strong>",
		"SHA256:abc",
		"Public key",
		"never the API",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("ssh keys page missing %q: %s", want, body)
		}
	}
	if w := get(h, "/ui/account/ssh-keys"); w.Code != http.StatusSeeOther {
		t.Fatalf("signed out: %d", w.Code)
	}
}

// reviewFake is what the review fake varies: the version status it
// reports on ri1.
type reviewFake struct {
	versionStatus string
	// queues is each review-queue query the page sent.
	queues []string
}

// reviewAPI fakes the review endpoints for ri1 on top of fakeAPI.
func reviewAPI(t *testing.T, f *reviewFake) http.Handler {
	t.Helper()
	if f == nil {
		f = &reviewFake{versionStatus: "needs_review"}
	}
	base := fakeAPI(t)
	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("agentry_session"); err != nil || c.Value != "sess1" {
			http.Error(w, `{"detail":"sign in"}`, http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "GET" && r.URL.Path == "/api/v1/review-queue":
			f.queues = append(f.queues, r.URL.RawQuery)
			_, _ = io.WriteString(w, `[{"id":"ri1","queue":"platform","state":"pending","version":"1.0.0","agent":"risky","namespace":"acme"}]`)
		case r.Method == "GET" && r.URL.Path == "/api/v1/review-items/ri1":
			_, _ = io.WriteString(w, `{"item":{"id":"ri1","queue":"platform","state":"pending","version":"1.0.0","versionStatus":"`+f.versionStatus+`","agent":"risky","namespace":"acme"},"findings":[{"id":"f1","scanner":"S1","severity":"high","confidence":"high","title":"Prompt injection","filePath":"SKILL.md","lineStart":1,"verdict":"open"}],"manifest":{"name":"risky","modes":["autonomous"],"capabilities":{"mcpServers":[{"npm":"github-mcp-server-js","version":"0.1.7","tools":["list_issues"],"secrets":["GITHUB_TOKEN"],"env":{"LOGS_DIR":"/tmp/logs","GITHUB_PERMISSION":"read-only"}}]}},"report":{"judgeModel":"qwen-test","judgeUsage":{"promptTokens":812,"completionTokens":97}}}`)
		case r.Method == "GET" && r.URL.Path == "/api/v1/review-items/ri1/files":
			_, _ = io.WriteString(w, `{"files":[{"path":"SKILL.md","size":12,"binary":false,"truncated":false}]}`)
		case r.Method == "GET" && r.URL.Path == "/api/v1/review-items/ri1/file":
			_, _ = io.WriteString(w, `{"path":"SKILL.md","size":12,"binary":false,"truncated":false,"content":"Ignore all\nsecond <b>line</b>"}`)
		case r.Method == "POST" && r.URL.Path == "/api/v1/review-items/ri1/decision":
			if r.Header.Get("X-Agentry-CSRF") != "csrf1" {
				http.Error(w, `{"detail":"csrf"}`, http.StatusForbidden)
				return
			}
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if (body["decision"] != "approve" && body["decision"] != "reject") || body["rationale"] != "looks fine" {
				http.Error(w, `{"detail":"bad body"}`, http.StatusBadRequest)
				return
			}
			_, _ = io.WriteString(w, `{"ok":true}`)
		case r.Method == "POST" && r.URL.Path == "/api/v1/findings/f1/verdict":
			_, _ = io.WriteString(w, `{"ok":true}`)
		default:
			base.ServeHTTP(w, r)
		}
	})
	return api
}

// The org queue with no organization named asks the API for every
// organization's, which platform staff are given; naming one
// asks for that one.
func TestReviewQueueNamesAnOrganizationOnlyWhenChosen(t *testing.T) {
	f := &reviewFake{versionStatus: "needs_review"}
	h := New(Options{API: reviewAPI(t, f)})
	for _, path := range []string{"/ui/review?queue=org", "/ui/review?org=acme"} {
		if w := get(h, path, sessCookie, csrfCookieV); w.Code != http.StatusOK {
			t.Fatalf("%s: %d", path, w.Code)
		}
	}
	if len(f.queues) != 2 || f.queues[0] != "limit=100&queue=org" || f.queues[1] != "limit=100&queue=org&org=acme" {
		t.Fatalf("the queries sent: %q", f.queues)
	}
}

// The operator pages act through the same client: the queue, an item with
// its findings and file view, a decision — each refused before the API
// when the form is cross-site or lacks the CSRF field.
func TestReviewPages(t *testing.T) {
	h := New(Options{API: reviewAPI(t, nil)})
	w := get(h, "/ui/review", sessCookie, csrfCookieV)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "acme/risky") {
		t.Fatalf("queue: %d %s", w.Code, w.Body.String())
	}
	w = get(h, "/ui/review/ri1?file=SKILL.md", sessCookie, csrfCookieV)
	body := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(body, "Prompt injection") || !strings.Contains(body, `id="L1" class="ln hit"`) || !strings.Contains(body, "second &lt;b&gt;line&lt;/b&gt;") || !strings.Contains(body, "name: risky") {
		t.Fatalf("item: %d %s", w.Code, body)
	}
	// A declared server's plain env is shown beside its tools, keys sorted,
	// so a reviewer reads the configuration the server will receive; the
	// order is fixed so the page never shuffles.
	if !strings.Contains(body, `capabilities: {mcpServers={env={GITHUB_PERMISSION=read-only LOGS_DIR=/tmp/logs} npm=github-mcp-server-js secrets=GITHUB_TOKEN tools=list_issues version=0.1.7}}`) {
		t.Fatalf("manifest summary lacks the server's env beside its tools: %s", body)
	}
	// The judge line names the model and, when the API sent it (platform
	// staff), what the adjudication cost in tokens.
	if !strings.Contains(body, "Judge: qwen-test · 812 prompt tokens, 97 completion tokens") {
		t.Fatalf("review page lacks the judge usage line: %s", body)
	}
	// The verdict control offers labels; the values stay the API's enum.
	if !strings.Contains(body, `<option value="dismissed_false_positive">False positive</option>`) ||
		!strings.Contains(body, `<option value="dismissed_accepted_risk">Accepted risk (medium and below)</option>`) {
		t.Fatalf("verdict options: %s", body)
	}
	w = post(h, "/ui/review/ri1/decision", url.Values{"_csrf": {"csrf1"}, "decision": {"approve"}, "rationale": {"looks fine"}}, nil, sessCookie, csrfCookieV)
	if loc, okMsg, _ := redirectedTo(t, w); w.Code != http.StatusSeeOther || loc != "/ui/review" || okMsg != "Approved. The version is published as soon as its attestation is signed, which takes moments." {
		t.Fatalf("decide: %d %s %q %s", w.Code, loc, okMsg, w.Body.String())
	}
	// A needs_review version rejected will not publish; the item said which
	// status the version was in (the quarantined branches are
	// TestReviewDecisionFlashNamesTheConsequence).
	w = post(h, "/ui/review/ri1/decision", url.Values{"_csrf": {"csrf1"}, "decision": {"reject"}, "rationale": {"looks fine"}}, nil, sessCookie, csrfCookieV)
	if loc, okMsg, _ := redirectedTo(t, w); w.Code != http.StatusSeeOther || loc != "/ui/review" || okMsg != "Rejected. This version will not publish." {
		t.Fatalf("reject: %d %s %q %s", w.Code, loc, okMsg, w.Body.String())
	}
	w = post(h, "/ui/review/ri1/findings/f1/verdict", url.Values{"_csrf": {"csrf1"}, "verdict": {"dismissed_false_positive"}, "reason": {"fixture"}}, nil, sessCookie, csrfCookieV)
	if loc, okMsg, _ := redirectedTo(t, w); w.Code != http.StatusSeeOther || loc != "/ui/review/ri1" || okMsg != "Verdict recorded." {
		t.Fatalf("verdict: %d %s %q", w.Code, loc, okMsg)
	}
	if w := post(h, "/ui/review/ri1/decision", url.Values{"decision": {"approve"}, "rationale": {"x"}}, nil, sessCookie, csrfCookieV); w.Code != http.StatusForbidden {
		t.Fatalf("no csrf field: %d", w.Code)
	}
	if w := get(h, "/ui/review"); w.Code != http.StatusSeeOther {
		t.Fatalf("signed out: %d", w.Code)
	}
}

// Each enforcement action's flash names what a consumer now meets, and the
// three read as sentences, not as the action name plus "d" ("blockd"). An
// action the form does not offer never reaches the API.
func TestStaffEnforcementFlashesNameTheConsequence(t *testing.T) {
	base := fakeAPI(t)
	calls := 0
	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/v1/platform/agents/acme/risky/") {
			calls++
			w.WriteHeader(http.StatusNoContent)
			return
		}
		base.ServeHTTP(w, r)
	})
	h := New(Options{API: api})
	notice := func(t *testing.T, w *httptest.ResponseRecorder) string {
		t.Helper()
		okMsg, errMsg, _ := flashOf(t, w)
		return okMsg + errMsg
	}
	for _, tc := range []struct{ action, want string }{
		{"quarantine", "acme/risky quarantined. A published version under quarantine answers 409 on download; the QuickAgent stays in search, carrying the state."},
		{"block", "acme/risky blocked. Every download for it answers 410 Gone."},
		{"reinstate", "acme/risky reinstated. Quarantined and blocked versions are published again; yanked ones stay yanked."},
	} {
		w := post(h, "/ui/staff/agent-action", url.Values{"_csrf": {"csrf1"}, "ref": {"acme/risky"}, "action": {tc.action}, "reason": {"reported malware"}}, nil, sessCookie, csrfCookieV)
		if w.Code != http.StatusSeeOther || notice(t, w) != tc.want {
			t.Fatalf("%s: %d %q", tc.action, w.Code, notice(t, w))
		}
	}
	w := post(h, "/ui/staff/agent-action", url.Values{"_csrf": {"csrf1"}, "ref": {"acme/risky"}, "action": {"delete"}, "reason": {"x"}}, nil, sessCookie, csrfCookieV)
	if w.Code != http.StatusSeeOther || !strings.HasPrefix(notice(t, w), "Nothing was done:") {
		t.Fatalf("unknown action: %d %q", w.Code, notice(t, w))
	}
	if calls != 3 {
		t.Fatalf("API calls: %d, want 3", calls)
	}
	// The panel renders with its object and its consequences on it.
	if w := get(h, "/ui/staff", sessCookie, csrfCookieV); w.Code != http.StatusOK ||
		!strings.Contains(w.Body.String(), "QuickAgent enforcement") ||
		!strings.Contains(w.Body.String(), "answers 410 Gone") ||
		!strings.Contains(w.Body.String(), "Nothing awaits platform review.") {
		t.Fatalf("staff page: %d %s", w.Code, w.Body.String())
	}
}

// The org admin page over a fake API: the sections render from the org's
// data, a non-admin gets the members refusal as the page's own status, and
// the policy form posts the parsed document.
func TestOrgAdminPage(t *testing.T) {
	base := fakeAPI(t)
	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("agentry_session"); err != nil || c.Value != "sess1" {
			http.Error(w, `{"detail":"sign in"}`, http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /api/v1/orgs/acme":
			_, _ = io.WriteString(w, `{"handle":"acme","displayName":"Acme Corp","ssoRequired":false,"domain":"acme.example","verifiedDomains":["acme.example","acme.co"],"state":"active","seats":{"used":1,"invited":1,"pending":1,"max":5}}`)
		case "GET /api/v1/orgs/acme/members":
			_, _ = io.WriteString(w, `[{"user":{"handle":"chris"},"role":"admin","state":"active"},{"user":{"handle":"pat"},"role":"member","state":"pending","viaScim":true}]`)
		case "GET /api/v1/orgs/acme/invitations":
			_, _ = io.WriteString(w, `[{"id":"i1","email":"dana@acme.example","role":"member","expiresAt":"2026-09-25T00:00:00Z"}]`)
		case "GET /api/v1/orgs/acme/teams":
			_, _ = io.WriteString(w, `[{"id":"t1","slug":"platform"}]`)
		case "GET /api/v1/orgs/acme/teams/platform/members":
			_, _ = io.WriteString(w, `[{"user":{"handle":"pat"},"role":"member"}]`)
		case "GET /api/v1/orgs/acme/policy":
			_, _ = io.WriteString(w, `{"allowPrivateIps":false}`)
		case "GET /api/v1/orgs/acme/sso/connections":
			_, _ = io.WriteString(w, `[{"kind":"saml","enabled":true,"config":{"idpMetadataXml":"<EntityDescriptor/>"}},{"kind":"oidc","enabled":false,"config":{"issuer":"https://idp.example","clientId":"cid"}}]`)
		case "POST /api/v1/orgs/acme/sso/connections/oidc/test":
			// The probe is a 200 either way; the verdict is in the body.
			_, _ = io.WriteString(w, `{"ok":false,"kind":"oidc","summary":"The discovery document could not be fetched.","checkedAt":"2026-09-12T00:00:00Z"}`)
		case "POST /api/v1/orgs/acme/sso/connections/saml/test":
			_, _ = io.WriteString(w, `{"ok":true,"kind":"saml","summary":"The IdP metadata parsed and the SP metadata is served.","warnings":["The IdP certificate expires in 20 days."],"checkedAt":"2026-09-12T00:00:00Z"}`)
		case "GET /api/v1/orgs/acme/scim/tokens", "GET /api/v1/orgs/acme/domain-claims", "GET /api/v1/orgs/acme/webhooks":
			_, _ = io.WriteString(w, `[]`)
		case "POST /api/v1/orgs/acme/decommission":
			var body map[string]string
			if json.NewDecoder(r.Body).Decode(&body) != nil || body["confirm"] != "acme" {
				http.Error(w, `{"detail":"Type the organization's handle, acme, as confirm to decommission it."}`, http.StatusUnprocessableEntity)
				return
			}
			_, _ = io.WriteString(w, `{"handle":"acme","state":"decommissioning"}`)
		case "PUT /api/v1/orgs/acme/policy":
			var doc map[string]any
			if json.NewDecoder(r.Body).Decode(&doc) != nil || doc["allowPrivateIps"] != true {
				http.Error(w, `{"detail":"bad policy"}`, http.StatusBadRequest)
				return
			}
			_, _ = io.WriteString(w, `{}`)
		case "GET /api/v1/orgs/other":
			_, _ = io.WriteString(w, `{"handle":"other"}`)
		case "GET /api/v1/orgs/other/members":
			http.Error(w, `{"detail":"org admin required"}`, http.StatusForbidden)
		default:
			base.ServeHTTP(w, r)
		}
	})
	h := New(Options{API: api})
	w := get(h, "/ui/orgs/acme", sessCookie, csrfCookieV)
	body := w.Body.String()
	for _, want := range []string{"Acme Corp", "<strong>chris</strong>", "<strong>platform</strong>", `&#34;allowPrivateIps&#34;: false`, "Create webhook",
		// Seats, the pending member's two buttons and the open invitation:
		// the page an admin runs the doors from.
		"Seats: 1 used, 1 invited, 1 waiting of 5",
		"waiting for approval", `name="action" value="approve"`, `name="action" value="decline"`,
		"<strong>dana@acme.example</strong>", `value="invitation"`,
		// The SSO forms reflect the stored state on load — the
		// SAML metadata and its Enabled box, the OIDC fields with Enabled off.
		`<textarea name="idpMetadataXml" rows="4" class="mono">&lt;EntityDescriptor/&gt;</textarea>`,
		`<input type="checkbox" name="enabled" value="true" checked> Enabled</label><div><button type="submit" class="secondary">Save SAML</button>`,
		`value="https://idp.example"`, `placeholder="blank keeps the stored secret"`,
		`<input type="checkbox" name="enabled" value="true"> Enabled</label><div><button type="submit" class="secondary">Save OIDC</button>`,
		// The domain and the decommission form; no staff
		// section for a viewer who is not staff.
		"Registered at <strong>acme.example</strong>", "Verified domains: acme.example, acme.co",
		`name="section" value="decommission"`, `Type <code>acme</code> to confirm`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("org page missing %q: %d %s", want, w.Code, body)
		}
	}
	if strings.Contains(body, `value="suspend"`) {
		t.Fatalf("a viewer who is not staff sees the suspend form")
	}
	// The decommission form posts the confirmation and reports the hold.
	w = post(h, "/ui/orgs/acme", url.Values{"_csrf": {"csrf1"}, "section": {"decommission"}, "confirm": {"acme"}}, nil, sessCookie, csrfCookieV)
	if loc, okMsg, errMsg := redirectedTo(t, w); w.Code != http.StatusSeeOther || loc != "/ui/orgs/acme" || errMsg != "" || !strings.Contains(okMsg, "read-only") {
		t.Fatalf("decommission: %d %s ok=%q err=%q", w.Code, loc, okMsg, errMsg)
	}
	// The probe's verdict reaches the flash: ok=false is the error flash with
	// the summary, ok=true the success flash with the summary and warnings.
	w = post(h, "/ui/orgs/acme", url.Values{"_csrf": {"csrf1"}, "section": {"sso"}, "kind": {"oidc"}, "action": {"test"}}, nil, sessCookie, csrfCookieV)
	if loc, _, errMsg := redirectedTo(t, w); w.Code != http.StatusSeeOther || loc != "/ui/orgs/acme" || errMsg != "The discovery document could not be fetched." {
		t.Fatalf("failed probe: %d %s %q", w.Code, loc, errMsg)
	}
	w = post(h, "/ui/orgs/acme", url.Values{"_csrf": {"csrf1"}, "section": {"sso"}, "kind": {"saml"}, "action": {"test"}}, nil, sessCookie, csrfCookieV)
	if loc, okMsg, _ := redirectedTo(t, w); w.Code != http.StatusSeeOther || loc != "/ui/orgs/acme" || okMsg != "The IdP metadata parsed and the SP metadata is served. Warnings: The IdP certificate expires in 20 days." {
		t.Fatalf("passed probe: %d %s %q", w.Code, loc, okMsg)
	}
	w = post(h, "/ui/orgs/acme", url.Values{"_csrf": {"csrf1"}, "section": {"policy"}, "policy": {`{"allowPrivateIps": true}`}}, nil, sessCookie, csrfCookieV)
	if loc, okMsg, _ := redirectedTo(t, w); w.Code != http.StatusSeeOther || loc != "/ui/orgs/acme" || okMsg != "Policy saved." {
		t.Fatalf("policy: %d %s %q", w.Code, loc, okMsg)
	}
	w = post(h, "/ui/orgs/acme", url.Values{"_csrf": {"csrf1"}, "section": {"policy"}, "policy": {`{not json`}}, nil, sessCookie, csrfCookieV)
	if _, _, errMsg := redirectedTo(t, w); errMsg != "The policy must be valid JSON." {
		t.Fatalf("bad json: %q", errMsg)
	}
	w = get(h, "/ui/orgs/other", sessCookie, csrfCookieV)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "org admin required") {
		t.Fatalf("non-admin: %d %s", w.Code, w.Body.String())
	}
}

// TestAccountPagesTellCouldNotLookFromEmpty: a read the API
// refused renders a notice that the page could not look, never the empty
// state that claims there is nothing; an answered-empty read renders the
// empty state and no notice.
func TestAccountPagesTellCouldNotLookFromEmpty(t *testing.T) {
	base := fakeAPI(t)
	var status int
	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /api/v1/user/tokens", "GET /api/v1/user/ssh-keys", "GET /api/v1/user/sessions", "GET /api/v1/user/directory", "GET /api/v1/user/notifications", "GET /api/v1/knowledge/usage":
			w.Header().Set("Content-Type", "application/json")
			if status == http.StatusOK {
				w.WriteHeader(http.StatusOK)
				switch r.URL.Path {
				case "/api/v1/user/sessions":
					_, _ = io.WriteString(w, `{"sessions":[]}`)
				case "/api/v1/user/directory":
					_, _ = io.WriteString(w, `{"passwordChangeUrl":"https://idp.example/password"}`)
				case "/api/v1/user/notifications":
					_, _ = io.WriteString(w, `{"email":{"dependencyAlerts":true,"quarantine":true,"reviewDecisions":true,"advisories":true,"orgInvites":true},"web":{"dependencyAlerts":true}}`)
				case "/api/v1/knowledge/usage":
					_, _ = io.WriteString(w, `{"bytes":0,"packs":0,"used":0,"max":0,"pooled":false}`)
				default:
					_, _ = io.WriteString(w, `[]`)
				}
				return
			}
			http.Error(w, `{"type":"https://agentry.dev/problems/internal","title":"Internal error","detail":"The directory did not answer."}`, status)
			return
		}
		base.ServeHTTP(w, r)
	})
	h := newUI(t, Options{API: api, ExternalOnly: true})
	pages := []struct{ path, what, empty string }{
		{"/ui/account/tokens", "your tokens", "No tokens."},
		{"/ui/account/ssh-keys", "your SSH keys", "No SSH keys."},
		{"/ui/account/sessions", "your sessions", "No sessions are recorded."},
		{"/ui/account", "the password and authenticator links", "Change password"},
		{"/ui/account", "your notification settings", "Save notifications"},
		{"/ui/account", "your knowledge allocation", "0 packs kept here, 0.0 MB, with no cap on this registry."},
	}
	status = http.StatusInternalServerError
	for _, pg := range pages {
		w := get(h, pg.path, sessCookie, csrfCookieV)
		body := w.Body.String()
		want := `<p class="flash error">The registry could not fetch ` + pg.what + `. The directory did not answer. Reload to try again.</p>`
		if w.Code != http.StatusOK || !strings.Contains(body, want) || strings.Contains(body, pg.empty) {
			t.Errorf("%s on 500: %d, want the notice %q and not %q:\n%s", pg.path, w.Code, want, pg.empty, body)
		}
	}
	status = http.StatusOK
	for _, pg := range pages {
		w := get(h, pg.path, sessCookie, csrfCookieV)
		body := w.Body.String()
		if w.Code != http.StatusOK || !strings.Contains(body, pg.empty) || strings.Contains(body, "could not fetch") {
			t.Errorf("%s on an answered read: %d, want %q and no notice:\n%s", pg.path, w.Code, pg.empty, body)
		}
	}
}

// TestLoginPageIsTheOneThatReadsAnErrorFromTheURL: the API's
// social-login callback addresses the signed-out entrance with ?error= on
// a headless deployment, so that page alone honours it, as text; ?ok= is
// not read there either. With one directory and nothing else the page
// bounces to the directory unless it has something to say — that message,
// or a flash a redirect left.
func TestLoginPageIsTheOneThatReadsAnErrorFromTheURL(t *testing.T) {
	h := newUI(t, Options{})
	w := get(h, "/ui/login?error=Sign-in+with+%3Cb%3Ex%3C%2Fb%3E+failed.&ok=Welcome")
	body := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(body, `<p class="flash error">Sign-in with &lt;b&gt;x&lt;/b&gt; failed.</p>`) || strings.Contains(body, "Welcome") {
		t.Fatalf("login with ?error=: %d %s", w.Code, body)
	}
	one := newUI(t, Options{ExternalOnly: true, Providers: []Provider{{ID: "authentik", Label: "Acme"}}})
	if w := get(one, "/ui/login"); w.Code != http.StatusSeeOther || !strings.HasPrefix(w.Header().Get("Location"), "/api/v1/auth/oidc/authentik/start?") {
		t.Fatalf("one directory, nothing to say: %d %s", w.Code, w.Header().Get("Location"))
	}
	if w := get(one, "/ui/login?error=Sign-in+failed."); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Sign-in failed.") {
		t.Fatalf("one directory, a message: %d", w.Code)
	}
	rec := httptest.NewRecorder()
	one.(*handler).setFlash(rec, "", "Sign-in succeeded but no session was issued. You are not signed in.")
	if w := get(one, "/ui/login", rec.Result().Cookies()[0]); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "no session was issued") {
		t.Fatalf("one directory, a flash: %d %s", w.Code, w.Body.String())
	}
}

// TestReviewDecisionFlashNamesTheConsequence: the decision
// flash says what the state machine does to the version it decided —
// a quarantined version is public, so approve publishes it again and
// reject yanks it — and when the item could not be read before the
// decision, the flash records the decision and claims nothing more. The
// item page tells the reviewer beforehand.
func TestReviewDecisionFlashNamesTheConsequence(t *testing.T) {
	f := &reviewFake{versionStatus: "quarantined"}
	h := newUI(t, Options{API: reviewAPI(t, f)})
	if body := get(h, "/ui/review/ri1", sessCookie, csrfCookieV).Body.String(); !strings.Contains(body, `<span class="badge warn">version quarantined</span>`) || !strings.Contains(body, "reject yanks it") {
		t.Fatalf("item page does not say the version is quarantined:\n%s", body)
	}
	for _, tc := range []struct{ status, decision, want string }{
		{"quarantined", "reject", "Rejected. The version was published, then quarantined, so it is yanked: an exact pin still resolves it, nothing else does."},
		{"quarantined", "approve", "Approved. The version was published, then quarantined; it is published and signed again."},
		{"needs_review", "reject", "Rejected. This version will not publish."},
		{"needs_review", "approve", "Approved. The version is published as soon as its attestation is signed, which takes moments."},
		{"", "reject", "Rejected. The decision and rationale are recorded with the version."},
	} {
		f.versionStatus = tc.status
		w := post(h, "/ui/review/ri1/decision", url.Values{"_csrf": {"csrf1"}, "decision": {tc.decision}, "rationale": {"looks fine"}}, nil, sessCookie, csrfCookieV)
		if loc, okMsg, _ := redirectedTo(t, w); w.Code != http.StatusSeeOther || loc != "/ui/review" || okMsg != tc.want {
			t.Errorf("%s %s: %d %s %q", tc.status, tc.decision, w.Code, loc, okMsg)
		}
	}
	f.versionStatus = ""
	if body := get(h, "/ui/review/ri1", sessCookie, csrfCookieV).Body.String(); strings.Contains(body, "version </span>") {
		t.Fatalf("an unknown status renders an empty badge:\n%s", body)
	}
	// A status the page could not read before the decision — the item
	// read refused — leaves the bare record, whatever the decision did.
	f.versionStatus = "quarantined"
	inner := reviewAPI(t, f)
	blind := newUI(t, Options{API: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/api/v1/review-items/ri1" {
			http.Error(w, `{"detail":"not now"}`, http.StatusServiceUnavailable)
			return
		}
		inner.ServeHTTP(w, r)
	})})
	w := post(blind, "/ui/review/ri1/decision", url.Values{"_csrf": {"csrf1"}, "decision": {"reject"}, "rationale": {"looks fine"}}, nil, sessCookie, csrfCookieV)
	if _, okMsg, _ := redirectedTo(t, w); okMsg != "Rejected. The decision and rationale are recorded with the version." {
		t.Errorf("unread status: %q", okMsg)
	}
}

// TestAccountNotificationSettings: the account page shows
// the person's mail and in-app switches as the API reports them, and the
// form sends the whole set back — an unticked box is a switch off — then
// flashes the save.
func TestAccountNotificationSettings(t *testing.T) {
	h := newUI(t, Options{})
	body := get(h, "/ui/account", sessCookie, csrfCookieV).Body.String()
	if !strings.Contains(body, `name="email.advisories" value="true" checked`) || !strings.Contains(body, `name="email.reviewDecisions" value="true">`) || !strings.Contains(body, `name="web.dependencyAlerts" value="true" checked`) {
		t.Fatalf("the switches do not follow the API:\n%s", body)
	}
	var sent string
	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && r.URL.Path == "/api/v1/user/notifications" {
			b, _ := io.ReadAll(r.Body)
			sent = string(b)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(b)
			return
		}
		fakeAPI(t).ServeHTTP(w, r)
	})
	h = New(Options{API: api})
	w := post(h, "/ui/account/notifications", url.Values{"_csrf": {"csrf1"}, "email.advisories": {"true"}, "web.dependencyAlerts": {"true"}}, nil, sessCookie, csrfCookieV)
	if loc, okMsg, _ := redirectedTo(t, w); w.Code != http.StatusSeeOther || loc != "/ui/account" || okMsg != "Notification settings saved." {
		t.Fatalf("save: %d %s %q", w.Code, loc, okMsg)
	}
	var got notificationSettings
	if err := json.Unmarshal([]byte(sent), &got); err != nil {
		t.Fatalf("sent %q: %v", sent, err)
	}
	if !got.Email.Advisories || got.Email.DependencyAlerts || got.Email.Quarantine || got.Email.ReviewDecisions || got.Email.OrgInvites || !got.Web.DependencyAlerts {
		t.Errorf("sent settings = %+v (unticked boxes must be off)", got)
	}
}

// TestOrgsIndexCreateForm: the organizations page offers the
// create form to a person who belongs to no organization, posts it
// in-process, lands them on the new organization's page with what was
// recorded, renders the API's refusal inside the layout, and withholds the
// form from someone who is already a member.
func TestOrgsIndexCreateForm(t *testing.T) {
	base := fakeAPI(t)
	member := false
	var created []map[string]any
	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("agentry_session"); err != nil || c.Value != "sess1" {
			http.Error(w, `{"detail":"sign in"}`, http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /api/v1/user":
			if member {
				_, _ = io.WriteString(w, `{"id":"u1","handle":"chris","email":"c@example.test","emailVerified":true,"orgs":[{"handle":"acme","role":"member","state":"active"}]}`)
				return
			}
			_, _ = io.WriteString(w, `{"id":"u1","handle":"chris","email":"c@example.test","emailVerified":true}`)
		case "POST /api/v1/orgs":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["handle"] == "taken" {
				http.Error(w, `{"type":"https://agentry.dev/problems/domain-claimed","detail":"newco.example is registered to Acme (acme) on this registry. Its administrators can add you; ask them, or verify a different domain."}`, http.StatusConflict)
				return
			}
			created = append(created, body)
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"handle":"newco","displayName":"New Co","domain":"newco.example","state":"active"}`)
		default:
			base.ServeHTTP(w, r)
		}
	})
	h := New(Options{API: api})
	w := get(h, "/ui/orgs", sessCookie, csrfCookieV)
	body := w.Body.String()
	for _, want := range []string{`action="/ui/orgs"`, `name="handle"`, `name="displayName"`, `name="noDomain"`, "Create organization"} {
		if !strings.Contains(body, want) {
			t.Fatalf("orgs page missing %q: %d %s", want, w.Code, body)
		}
	}
	w = post(h, "/ui/orgs", url.Values{"_csrf": {"csrf1"}, "handle": {"NewCo"}, "displayName": {"New Co"}}, nil, sessCookie, csrfCookieV)
	if loc, okMsg, errMsg := redirectedTo(t, w); w.Code != http.StatusSeeOther || loc != "/ui/orgs/newco" || errMsg != "" ||
		!strings.Contains(okMsg, "newco created") || !strings.Contains(okMsg, "newco.example") {
		t.Fatalf("create: %d %s ok=%q err=%q", w.Code, loc, okMsg, errMsg)
	}
	if len(created) != 1 || created[0]["handle"] != "newco" || created[0]["domain"] != nil {
		t.Fatalf("what the form sent: %v", created)
	}
	w = post(h, "/ui/orgs", url.Values{"_csrf": {"csrf1"}, "handle": {"newco"}, "displayName": {"New Co"}, "noDomain": {"true"}}, nil, sessCookie, csrfCookieV)
	if loc, _, _ := redirectedTo(t, w); loc != "/ui/orgs/newco" || len(created) != 2 || created[1]["domain"] != "none" {
		t.Fatalf("the no-domain box: %s %v", loc, created)
	}
	w = post(h, "/ui/orgs", url.Values{"_csrf": {"csrf1"}, "handle": {"taken"}, "displayName": {"Taken"}}, nil, sessCookie, csrfCookieV)
	if loc, _, errMsg := redirectedTo(t, w); loc != "/ui/orgs" || !strings.Contains(errMsg, "registered to Acme (acme)") {
		t.Fatalf("refusal: %s %q", loc, errMsg)
	}
	w = post(h, "/ui/orgs", url.Values{"_csrf": {"csrf1"}, "handle": {""}, "displayName": {""}}, nil, sessCookie, csrfCookieV)
	if _, _, errMsg := redirectedTo(t, w); errMsg != "Enter the organization's handle and display name." {
		t.Fatalf("empty form: %q", errMsg)
	}
	member = true
	w = get(h, "/ui/orgs", sessCookie, csrfCookieV)
	body = w.Body.String()
	if strings.Contains(body, `name="handle"`) || !strings.Contains(body, "leave it before creating another") || !strings.Contains(body, "<strong>acme</strong>") {
		t.Fatalf("a member's orgs page: %d %s", w.Code, body)
	}
}

// TestStaffOrgFormSuspendsAndReinstates: a suspended
// organization answers 404 to everyone, platform staff included, so the
// reinstate form on its page is unreachable once staff have used the
// suspend form there. The staff console carries the two acts by handle —
// no listing — and the org page keeps its forms for an organization it
// can show: suspend while active, reinstate while decommissioning.
func TestStaffOrgFormSuspendsAndReinstates(t *testing.T) {
	base := fakeAPI(t)
	var suspended, reinstated []string
	// Two sessions: staff, and a signed-in member of the public whom the
	// API refuses before it looks the handle up.
	const plainSession = "sess-plain"
	plainCookie := &http.Cookie{Name: "agentry_session", Value: plainSession}
	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := ""
		if c, err := r.Cookie("agentry_session"); err == nil {
			sess = c.Value
		}
		if sess != fakeSession && sess != plainSession {
			http.Error(w, `{"detail":"sign in"}`, http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet && r.Header.Get("X-Agentry-CSRF") != fakeCSRF {
			http.Error(w, `{"detail":"missing or invalid CSRF token"}`, http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if sess == plainSession {
			switch {
			case r.URL.Path == "/api/v1/user":
				_, _ = io.WriteString(w, `{"id":"u2","handle":"pat","email":"p@example.test","emailVerified":true}`)
			case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/v1/orgs/"):
				http.Error(w, `{"detail":"This action is open to platform staff only."}`, http.StatusForbidden)
			default:
				base.ServeHTTP(w, r)
			}
			return
		}
		switch r.Method + " " + r.URL.Path {
		case "GET /api/v1/user":
			_, _ = io.WriteString(w, `{"id":"u1","handle":"chris","email":"c@example.test","displayName":"Chris","emailVerified":true,"platformStaff":true}`)
		case "POST /api/v1/orgs/m4-lifecycle/suspend":
			var body map[string]string
			if json.NewDecoder(r.Body).Decode(&body) != nil || body["reason"] == "" {
				http.Error(w, `{"detail":"Give a reason of 1-500 characters; it is audited."}`, http.StatusUnprocessableEntity)
				return
			}
			suspended = append(suspended, body["reason"])
			_, _ = io.WriteString(w, `{"handle":"m4-lifecycle","state":"suspended"}`)
		case "POST /api/v1/orgs/m4-lifecycle/reinstate":
			reinstated = append(reinstated, "m4-lifecycle")
			_, _ = io.WriteString(w, `{"handle":"m4-lifecycle","state":"active"}`)
		case "POST /api/v1/orgs/held/suspend":
			http.Error(w, `{"detail":"The held organization is decommissioning, not active; only an active organization is suspended."}`, http.StatusConflict)
		case "POST /api/v1/orgs/erased/reinstate":
			// An erasure releases the handle, so the API's direct lookup
			// answers its bare 404 (internal/api problemNotFound), the same
			// answer a typo gets.
			http.Error(w, `{"type":"about:blank","title":"Not found"}`, http.StatusNotFound)
		case "GET /api/v1/orgs/m4-lifecycle":
			// The invariant the console exists for: absent to staff too.
			http.Error(w, `{"detail":"org not found"}`, http.StatusNotFound)
		case "GET /api/v1/orgs/held":
			_, _ = io.WriteString(w, `{"handle":"held","displayName":"Held","state":"decommissioning","decommissionAt":"2026-10-01T00:00:00Z"}`)
		case "GET /api/v1/orgs/live":
			_, _ = io.WriteString(w, `{"handle":"live","displayName":"Live","state":"active"}`)
		case "GET /api/v1/orgs/held/members", "GET /api/v1/orgs/live/members":
			_, _ = io.WriteString(w, `[{"user":{"handle":"chris"},"role":"admin","state":"active"}]`)
		case "GET /api/v1/orgs/held/invitations", "GET /api/v1/orgs/held/teams", "GET /api/v1/orgs/held/sso/connections", "GET /api/v1/orgs/held/scim/tokens", "GET /api/v1/orgs/held/domain-claims", "GET /api/v1/orgs/held/webhooks",
			"GET /api/v1/orgs/live/invitations", "GET /api/v1/orgs/live/teams", "GET /api/v1/orgs/live/sso/connections", "GET /api/v1/orgs/live/scim/tokens", "GET /api/v1/orgs/live/domain-claims", "GET /api/v1/orgs/live/webhooks":
			_, _ = io.WriteString(w, `[]`)
		case "GET /api/v1/orgs/held/policy", "GET /api/v1/orgs/live/policy":
			_, _ = io.WriteString(w, `{}`)
		default:
			base.ServeHTTP(w, r)
		}
	})
	h := New(Options{API: api})

	// The console carries the form: a handle, a reason, the two acts.
	w := get(h, "/ui/staff", sessCookie, csrfCookieV)
	body := w.Body.String()
	for _, want := range []string{`action="/ui/staff/org"`, `name="handle"`, `name="reason"`, `name="action" value="suspend"`, `name="action" value="reinstate"`, "answer as absent"} {
		if w.Code != http.StatusOK || !strings.Contains(body, want) {
			t.Fatalf("staff page missing %q: %d %s", want, w.Code, body)
		}
	}
	// Suspending needs a reason; the API is not asked without one.
	w = post(h, "/ui/staff/org", url.Values{"_csrf": {fakeCSRF}, "handle": {"m4-lifecycle"}, "action": {"suspend"}}, nil, sessCookie, csrfCookieV)
	if _, errMsg, _ := flashOf(t, w); w.Code != http.StatusSeeOther || !strings.HasPrefix(errMsg, "Nothing was done:") || len(suspended) != 0 {
		t.Fatalf("suspend without reason: %d %q suspended=%v", w.Code, errMsg, suspended)
	}
	// Nor without a handle, nor with an action the console does not offer.
	w = post(h, "/ui/staff/org", url.Values{"_csrf": {fakeCSRF}, "handle": {" "}, "action": {"reinstate"}}, nil, sessCookie, csrfCookieV)
	if _, errMsg, _ := flashOf(t, w); w.Code != http.StatusSeeOther || !strings.HasPrefix(errMsg, "Nothing was done:") {
		t.Fatalf("no handle: %d %q", w.Code, errMsg)
	}
	w = post(h, "/ui/staff/org", url.Values{"_csrf": {fakeCSRF}, "handle": {"m4-lifecycle"}, "action": {"decommission"}, "reason": {"x"}}, nil, sessCookie, csrfCookieV)
	if _, errMsg, _ := flashOf(t, w); w.Code != http.StatusSeeOther || !strings.HasPrefix(errMsg, "Nothing was done:") {
		t.Fatalf("unknown action: %d %q", w.Code, errMsg)
	}
	// A signed-in viewer who is not staff meets the API's refusal, and the
	// API was asked nothing that would tell them whether the handle exists.
	w = post(h, "/ui/staff/org", url.Values{"_csrf": {fakeCSRF}, "handle": {"m4-lifecycle"}, "action": {"suspend"}, "reason": {"x"}}, nil, plainCookie, csrfCookieV)
	if _, errMsg, _ := flashOf(t, w); w.Code != http.StatusSeeOther || errMsg != "This action is open to platform staff only." || len(suspended) != 0 {
		t.Fatalf("not staff: %d %q suspended=%v", w.Code, errMsg, suspended)
	}
	// Suspend, with the reason passed through and the consequence named;
	// the handle is normalised the way the API stores it.
	w = post(h, "/ui/staff/org", url.Values{"_csrf": {fakeCSRF}, "handle": {" M4-Lifecycle "}, "action": {"suspend"}, "reason": {" spam "}}, nil, sessCookie, csrfCookieV)
	if loc, okMsg, errMsg := redirectedTo(t, w); w.Code != http.StatusSeeOther || loc != "/ui/staff" || errMsg != "" ||
		okMsg != "m4-lifecycle is suspended: it and everything under it answer as absent until it is reinstated." ||
		len(suspended) != 1 || suspended[0] != "spam" {
		t.Fatalf("suspend: %d %s ok=%q err=%q suspended=%v", w.Code, loc, okMsg, errMsg, suspended)
	}
	// Its page is now absent to staff too — that is the invariant — and
	// says where the reinstate form lives.
	w = get(h, "/ui/orgs/m4-lifecycle", sessCookie, csrfCookieV)
	if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "org not found") || !strings.Contains(w.Body.String(), `href="/ui/staff"`) {
		t.Fatalf("suspended org page for staff: %d %s", w.Code, w.Body.String())
	}
	// Reinstate from the console.
	w = post(h, "/ui/staff/org", url.Values{"_csrf": {fakeCSRF}, "handle": {"m4-lifecycle"}, "action": {"reinstate"}}, nil, sessCookie, csrfCookieV)
	if loc, okMsg, errMsg := redirectedTo(t, w); w.Code != http.StatusSeeOther || loc != "/ui/staff" || errMsg != "" ||
		okMsg != "m4-lifecycle is active again." || len(reinstated) != 1 {
		t.Fatalf("reinstate: %d %s ok=%q err=%q", w.Code, loc, okMsg, errMsg)
	}
	// The API's refusal is the flash, word for word — except its bare 404,
	// which is what an erased organization's released handle answers, and
	// which the console spells out for staff.
	w = post(h, "/ui/staff/org", url.Values{"_csrf": {fakeCSRF}, "handle": {"held"}, "action": {"suspend"}, "reason": {"x"}}, nil, sessCookie, csrfCookieV)
	if _, errMsg, _ := flashOf(t, w); w.Code != http.StatusSeeOther || errMsg != "The held organization is decommissioning, not active; only an active organization is suspended." {
		t.Fatalf("conflict: %d %q", w.Code, errMsg)
	}
	w = post(h, "/ui/staff/org", url.Values{"_csrf": {fakeCSRF}, "handle": {"erased"}, "action": {"reinstate"}}, nil, sessCookie, csrfCookieV)
	if _, errMsg, _ := flashOf(t, w); w.Code != http.StatusSeeOther || errMsg != "No organization is called erased. A suspended one is still found here; one that has been erased is not, and cannot come back." {
		t.Fatalf("erased: %d %q", w.Code, errMsg)
	}
	// The org page keeps its forms for an organization it can show.
	w = get(h, "/ui/orgs/live", sessCookie, csrfCookieV)
	if body := w.Body.String(); w.Code != http.StatusOK || !strings.Contains(body, `name="section" value="suspend"`) || strings.Contains(body, `name="section" value="reinstate"`) {
		t.Fatalf("active org page for staff: %d %s", w.Code, body)
	}
	w = get(h, "/ui/orgs/held", sessCookie, csrfCookieV)
	if body := w.Body.String(); w.Code != http.StatusOK || !strings.Contains(body, `name="section" value="reinstate"`) || strings.Contains(body, `name="section" value="suspend"`) {
		t.Fatalf("decommissioning org page for staff: %d %s", w.Code, body)
	}
}

// TestLayoutNamesThePendingOrganization: while GET /user
// carries pendingOrg, every page says which organization the person is
// waiting on and that they hold nothing of it yet; the wording names the
// door. Without it, no notice.
func TestLayoutNamesThePendingOrganization(t *testing.T) {
	base := fakeAPI(t)
	pending := `{"handle":"acme","displayName":"Acme Corp","via":"domain"}`
	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/user" && pending != "" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"id":"u1","handle":"chris","email":"c@acme.example","displayName":"Chris","emailVerified":true,"pendingOrg":`+pending+`}`)
			return
		}
		base.ServeHTTP(w, r)
	})
	h := New(Options{API: api})
	w := get(h, "/ui/account", sessCookie, csrfCookieV)
	if body := w.Body.String(); w.Code != http.StatusOK ||
		!strings.Contains(body, `<p class="flash notice">Your email domain is registered to the <strong>Acme Corp (acme)</strong> organization: its administrators have been asked to add you.`) ||
		!strings.Contains(body, "you hold nothing of the organization") {
		t.Fatalf("pending notice: %d %s", w.Code, body)
	}
	pending = `{"handle":"acme","displayName":"acme","via":"scim"}`
	w = get(h, "/ui/account", sessCookie, csrfCookieV)
	if body := w.Body.String(); !strings.Contains(body, `The <strong>acme</strong> organization's identity provider has provisioned this account`) {
		t.Fatalf("scim notice: %s", body)
	}
	pending = ""
	if w := get(h, "/ui/account", sessCookie, csrfCookieV); strings.Contains(w.Body.String(), `flash notice`) {
		t.Fatalf("no pending org, yet a notice: %s", w.Body.String())
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

// TestAccountShowsTheKnowledgeMeter: the account view says
// what the person keeps in the registry against their allocation, and that
// a registry with the store off keeps none.
func TestAccountShowsTheKnowledgeMeter(t *testing.T) {
	h := newUI(t, Options{})
	w := get(h, "/ui/account", sessCookie, csrfCookieV)
	if body := w.Body.String(); w.Code != http.StatusOK || !strings.Contains(body, "2 packs kept here, 3.5 MB of 100.0 MB.") {
		t.Fatalf("account: %d, no meter:\n%s", w.Code, body)
	}
	base := fakeAPI(t)
	off := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/knowledge/usage" {
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, `{"type":"https://agentry.dev/problems/knowledge-unconfigured","title":"Knowledge store off","status":503}`)
			return
		}
		base.ServeHTTP(w, r)
	})
	pooled := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/knowledge/usage" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"bytes":1048576,"packs":1,"used":5242880,"max":10485760,"pooled":true}`)
			return
		}
		base.ServeHTTP(w, r)
	})
	w = get(newUI(t, Options{API: pooled}), "/ui/account", sessCookie, csrfCookieV)
	if body := w.Body.String(); !strings.Contains(body, "1 pack kept here, 1.0 MB. The allocation you share with your organization: 5.0 MB used of 10.0 MB.") {
		t.Fatalf("account with a pooled allocation:\n%s", body)
	}
	w = get(newUI(t, Options{API: off}), "/ui/account", sessCookie, csrfCookieV)
	if body := w.Body.String(); !strings.Contains(body, "This registry keeps no knowledge packs.") || strings.Contains(body, "could not fetch your knowledge") {
		t.Fatalf("account with the store off:\n%s", body)
	}
}

// TestTokenFormOffersEveryScope: the token form's list, kept in the order
// the page shows it, is the closed scope list exactly — a scope added to
// auth and not to the form (or the reverse) fails here.
func TestTokenFormOffersEveryScope(t *testing.T) {
	want := map[string]bool{}
	for _, s := range auth.AllScopes() {
		want[string(s)] = true
	}
	got := map[string]bool{}
	for _, s := range scopes {
		if got[s] {
			t.Errorf("the form offers %s twice", s)
		}
		got[s] = true
		if !want[s] {
			t.Errorf("the form offers %s, which is no scope", s)
		}
	}
	for s := range want {
		if !got[s] {
			t.Errorf("the form does not offer %s", s)
		}
	}
}

// TestAccountActivationResend: an account that is not activated is told so
// on its account page and can ask for a new link there; the
// registry's refusal inside five minutes reaches the person in its words.
func TestAccountActivationResend(t *testing.T) {
	tooSoon := false
	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /api/v1/user":
			_, _ = io.WriteString(w, `{"id":"u1","handle":"chris","email":"c@example.test","displayName":"Chris","emailVerified":false}`)
		case "POST /api/v1/user/email-verification":
			if r.Header.Get("X-Agentry-CSRF") != fakeCSRF {
				http.Error(w, `{"detail":"csrf"}`, http.StatusForbidden)
				return
			}
			if tooSoon {
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = io.WriteString(w, `{"type":"https://agentry.dev/problems/activation-too-soon","detail":"An activation link went to this address less than 5 minutes ago."}`)
				return
			}
			_, _ = io.WriteString(w, `{"sentTo":"c@example.test","resendAfter":"2026-10-02T12:05:00Z"}`)
		default:
			http.Error(w, `{"detail":"no such fake route"}`, http.StatusNotFound)
		}
	})
	h := newUI(t, Options{API: api})
	body := get(h, "/ui/account", sessCookie, csrfCookieV).Body.String()
	if !strings.Contains(body, "not activated yet") || !strings.Contains(body, `action="/ui/account/activation"`) {
		t.Fatalf("the account page offers no activation link: %s", body)
	}
	w := post(h, "/ui/account/activation", url.Values{"_csrf": {"csrf1"}}, nil, sessCookie, csrfCookieV)
	if okMsg, _, _ := flashOf(t, w); w.Code != http.StatusSeeOther || !strings.Contains(okMsg, "new activation link") {
		t.Fatalf("resend: %d %q", w.Code, okMsg)
	}
	tooSoon = true
	w = post(h, "/ui/account/activation", url.Values{"_csrf": {"csrf1"}}, nil, sessCookie, csrfCookieV)
	if _, errMsg, _ := flashOf(t, w); !strings.Contains(errMsg, "less than 5 minutes") {
		t.Fatalf("resend too soon: %q", errMsg)
	}
}
