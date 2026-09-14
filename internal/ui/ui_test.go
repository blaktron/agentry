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

// The four refusals that used to answer as bare text: the same status codes,
// now the message page inside the layout, carrying the reason and the same
// CSP as any other page. A path that exists under another method keeps the
// mux's 405.
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
		// A refusal is a page like any other, and §5b's no-store applies to it:
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
	// everywhere, the 404 page included (agentry#271).
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

// The operator pages act through the same client: the queue, an item with
// its findings and file view, a decision — each refused before the API
// when the form is cross-site or lacks the CSRF field.
func TestReviewPages(t *testing.T) {
	base := fakeAPI(t)
	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("agentry_session"); err != nil || c.Value != "sess1" {
			http.Error(w, `{"detail":"sign in"}`, http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "GET" && r.URL.Path == "/api/v1/review-queue":
			_, _ = io.WriteString(w, `[{"id":"ri1","queue":"platform","state":"pending","version":"1.0.0","agent":"risky","namespace":"acme"}]`)
		case r.Method == "GET" && r.URL.Path == "/api/v1/review-items/ri1":
			_, _ = io.WriteString(w, `{"item":{"id":"ri1","queue":"platform","state":"pending","version":"1.0.0","agent":"risky","namespace":"acme"},"findings":[{"id":"f1","scanner":"S1","severity":"high","confidence":"high","title":"Prompt injection","filePath":"SKILL.md","lineStart":1,"verdict":"open"}],"manifest":{"name":"risky","modes":["autonomous"],"capabilities":{"mcpServers":[{"npm":"github-mcp-server-js","version":"0.1.7","tools":["list_issues"],"secrets":["GITHUB_TOKEN"],"env":{"LOGS_DIR":"/tmp/logs","GITHUB_PERMISSION":"read-only"}}]}},"report":{"judgeModel":"qwen-test","judgeUsage":{"promptTokens":812,"completionTokens":97}}}`)
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
	h := New(Options{API: api})
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
	// so a reviewer reads the configuration the server will receive
	// (agentry#286); the order is fixed so the page never shuffles.
	if !strings.Contains(body, `capabilities: {mcpServers={env={GITHUB_PERMISSION=read-only LOGS_DIR=/tmp/logs} npm=github-mcp-server-js secrets=GITHUB_TOKEN tools=list_issues version=0.1.7}}`) {
		t.Fatalf("manifest summary lacks the server's env beside its tools: %s", body)
	}
	// The judge line names the model and, when the API sent it (platform
	// staff), what the adjudication cost in tokens (agentry#318).
	if !strings.Contains(body, "Judge: qwen-test · 812 prompt tokens, 97 completion tokens") {
		t.Fatalf("review page lacks the judge usage line: %s", body)
	}
	// The verdict control offers labels; the values stay the API's enum.
	if !strings.Contains(body, `<option value="dismissed_false_positive">False positive</option>`) ||
		!strings.Contains(body, `<option value="dismissed_accepted_risk">Accepted risk (medium and below)</option>`) {
		t.Fatalf("verdict options: %s", body)
	}
	w = post(h, "/ui/review/ri1/decision", url.Values{"_csrf": {"csrf1"}, "decision": {"approve"}, "rationale": {"looks fine"}}, nil, sessCookie, csrfCookieV)
	if loc, okMsg, _ := redirectedTo(t, w); w.Code != http.StatusSeeOther || loc != "/ui/review" || !strings.HasPrefix(okMsg, "Approved") {
		t.Fatalf("decide: %d %s %q %s", w.Code, loc, okMsg, w.Body.String())
	}
	// A reject records a decision; whether the version ends at `rejected` or,
	// if it was quarantined, at `yanked` is the API's to decide, and this page
	// posts blind. The flash therefore claims nothing about publication.
	w = post(h, "/ui/review/ri1/decision", url.Values{"_csrf": {"csrf1"}, "decision": {"reject"}, "rationale": {"looks fine"}}, nil, sessCookie, csrfCookieV)
	if loc, okMsg, _ := redirectedTo(t, w); w.Code != http.StatusSeeOther || loc != "/ui/review" || okMsg != "Rejected. The decision and rationale are recorded with the version." {
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
// three read as sentences: the flash used to be built as action + "d.", which
// said "blockd". An action the form does not offer never reaches the API.
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
		{"quarantine", "acme/risky quarantined. A published version under quarantine answers 409 on download; the BriefAgent stays in search, carrying the state."},
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
		!strings.Contains(w.Body.String(), "BriefAgent enforcement") ||
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
			_, _ = io.WriteString(w, `{"handle":"acme","displayName":"Acme Corp","ssoRequired":false}`)
		case "GET /api/v1/orgs/acme/members":
			_, _ = io.WriteString(w, `[{"user":{"handle":"chris"},"role":"owner"},{"user":{"handle":"pat"},"role":"member"}]`)
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
		// agentry#272: the SSO forms reflect the stored state on load — the
		// SAML metadata and its Enabled box, the OIDC fields with Enabled off.
		`<textarea name="idpMetadataXml" rows="4" class="mono">&lt;EntityDescriptor/&gt;</textarea>`,
		`<input type="checkbox" name="enabled" value="true" checked> Enabled</label><div><button type="submit" class="secondary">Save SAML</button>`,
		`value="https://idp.example"`, `placeholder="blank keeps the stored secret"`,
		`<input type="checkbox" name="enabled" value="true"> Enabled</label><div><button type="submit" class="secondary">Save OIDC</button>`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("org page missing %q: %d %s", want, w.Code, body)
		}
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

// TestAccountPagesTellCouldNotLookFromEmpty (agentry#271): a read the API
// refused renders a notice that the page could not look, never the empty
// state that claims there is nothing; an answered-empty read renders the
// empty state and no notice.
func TestAccountPagesTellCouldNotLookFromEmpty(t *testing.T) {
	base := fakeAPI(t)
	var status int
	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /api/v1/user/tokens", "GET /api/v1/user/ssh-keys", "GET /api/v1/user/sessions", "GET /api/v1/user/directory":
			w.Header().Set("Content-Type", "application/json")
			if status == http.StatusOK {
				w.WriteHeader(http.StatusOK)
				switch r.URL.Path {
				case "/api/v1/user/sessions":
					_, _ = io.WriteString(w, `{"sessions":[]}`)
				case "/api/v1/user/directory":
					_, _ = io.WriteString(w, `{"passwordChangeUrl":"https://idp.example/password"}`)
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

// TestLoginPageIsTheOneThatReadsAnErrorFromTheURL (agentry#271): the API's
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
