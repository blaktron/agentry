package ui

import (
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
	// Wrong password: back to the form with the message, no cookies.
	w = post(h, "/ui/login", url.Values{"login": {"chris"}, "password": {"nope"}}, nil)
	if w.Code != http.StatusSeeOther || !strings.Contains(w.Header().Get("Location"), "error=invalid+credentials") || len(w.Result().Cookies()) != 0 {
		t.Fatalf("bad login: %d %s", w.Code, w.Header().Get("Location"))
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
		name   string
		got    *httptest.ResponseRecorder
		status int
		reason string
	}{
		{"cross-origin post", raw(http.MethodPost, "/ui/authorize", "_csrf=csrf1&port=40123&state=abcdefghij", map[string]string{"Sec-Fetch-Site": "cross-site"}, sessCookie, csrfCookieV), http.StatusForbidden, "posted from another site"},
		{"unparseable form", raw(http.MethodPost, "/ui/authorize", "%zz=1", nil, sessCookie, csrfCookieV), http.StatusBadRequest, "could not read this form"},
		{"missing csrf field", raw(http.MethodPost, "/ui/authorize", "port=40123&state=abcdefghij", nil, sessCookie, csrfCookieV), http.StatusForbidden, "does not match your cookie"},
		{"unknown path", raw(http.MethodGet, "/ui/nope", "", nil), http.StatusNotFound, "serves no page at this address"},
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
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/ui/account?ok=Profile+saved." {
		t.Fatalf("save: %d %s", w.Code, w.Header().Get("Location"))
	}
	// The flash is text, never markup.
	w = get(h, "/ui/account?error=%3Cb%3Ex%3C%2Fb%3E", sessCookie, csrfCookieV)
	if strings.Contains(w.Body.String(), "<b>x</b>") || !strings.Contains(w.Body.String(), "&lt;b&gt;x&lt;/b&gt;") {
		t.Fatalf("flash escaping: %s", w.Body.String())
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
			_, _ = io.WriteString(w, `{"item":{"id":"ri1","queue":"platform","state":"pending","version":"1.0.0","agent":"risky","namespace":"acme"},"findings":[{"id":"f1","scanner":"S1","severity":"high","confidence":"high","title":"Prompt injection","filePath":"SKILL.md","lineStart":1,"verdict":"open"}],"manifest":{"name":"risky","modes":["autonomous"]}}`)
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
	// The verdict control offers labels; the values stay the API's enum.
	if !strings.Contains(body, `<option value="dismissed_false_positive">False positive</option>`) ||
		!strings.Contains(body, `<option value="dismissed_accepted_risk">Accepted risk (medium and below)</option>`) {
		t.Fatalf("verdict options: %s", body)
	}
	w = post(h, "/ui/review/ri1/decision", url.Values{"_csrf": {"csrf1"}, "decision": {"approve"}, "rationale": {"looks fine"}}, nil, sessCookie, csrfCookieV)
	if w.Code != http.StatusSeeOther || !strings.HasPrefix(w.Header().Get("Location"), "/ui/review?ok=Approved") {
		t.Fatalf("decide: %d %s %s", w.Code, w.Header().Get("Location"), w.Body.String())
	}
	// A reject records a decision; whether the version ends at `rejected` or,
	// if it was quarantined, at `yanked` is the API's to decide, and this page
	// posts blind. The flash therefore claims nothing about publication.
	w = post(h, "/ui/review/ri1/decision", url.Values{"_csrf": {"csrf1"}, "decision": {"reject"}, "rationale": {"looks fine"}}, nil, sessCookie, csrfCookieV)
	if loc := w.Header().Get("Location"); w.Code != http.StatusSeeOther || loc != "/ui/review?ok=Rejected.+The+decision+and+rationale+are+recorded+with+the+version." {
		t.Fatalf("reject: %d %s %s", w.Code, loc, w.Body.String())
	}
	w = post(h, "/ui/review/ri1/findings/f1/verdict", url.Values{"_csrf": {"csrf1"}, "verdict": {"dismissed_false_positive"}, "reason": {"fixture"}}, nil, sessCookie, csrfCookieV)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/ui/review/ri1?ok=Verdict+recorded." {
		t.Fatalf("verdict: %d %s", w.Code, w.Header().Get("Location"))
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
	flash := func(t *testing.T, w *httptest.ResponseRecorder) string {
		t.Helper()
		u, err := url.Parse(w.Header().Get("Location"))
		if err != nil {
			t.Fatalf("location: %v", err)
		}
		return u.Query().Get("ok") + u.Query().Get("error")
	}
	for _, tc := range []struct{ action, want string }{
		{"quarantine", "acme/risky quarantined. Its latest published version answers 409 on download. The BriefAgent stays in search, carrying the quarantine state."},
		{"block", "acme/risky blocked. Every download for it answers 410 Gone."},
		{"reinstate", "acme/risky reinstated. Its versions are published again."},
	} {
		w := post(h, "/ui/staff/agent-action", url.Values{"_csrf": {"csrf1"}, "ref": {"acme/risky"}, "action": {tc.action}, "reason": {"reported malware"}}, nil, sessCookie, csrfCookieV)
		if w.Code != http.StatusSeeOther || flash(t, w) != tc.want {
			t.Fatalf("%s: %d %q", tc.action, w.Code, flash(t, w))
		}
	}
	w := post(h, "/ui/staff/agent-action", url.Values{"_csrf": {"csrf1"}, "ref": {"acme/risky"}, "action": {"delete"}, "reason": {"x"}}, nil, sessCookie, csrfCookieV)
	if w.Code != http.StatusSeeOther || !strings.HasPrefix(flash(t, w), "Nothing was done:") {
		t.Fatalf("unknown action: %d %q", w.Code, flash(t, w))
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
		case "GET /api/v1/orgs/acme/sso/connections", "GET /api/v1/orgs/acme/scim/tokens", "GET /api/v1/orgs/acme/domain-claims", "GET /api/v1/orgs/acme/webhooks":
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
	for _, want := range []string{"Acme Corp", "<strong>chris</strong>", "<strong>platform</strong>", `&#34;allowPrivateIps&#34;: false`, "Create webhook"} {
		if !strings.Contains(body, want) {
			t.Fatalf("org page missing %q: %d %s", want, w.Code, body)
		}
	}
	w = post(h, "/ui/orgs/acme", url.Values{"_csrf": {"csrf1"}, "section": {"policy"}, "policy": {`{"allowPrivateIps": true}`}}, nil, sessCookie, csrfCookieV)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/ui/orgs/acme?ok=Policy+saved." {
		t.Fatalf("policy: %d %s", w.Code, w.Header().Get("Location"))
	}
	w = post(h, "/ui/orgs/acme", url.Values{"_csrf": {"csrf1"}, "section": {"policy"}, "policy": {`{not json`}}, nil, sessCookie, csrfCookieV)
	if !strings.Contains(w.Header().Get("Location"), "error=the+policy+must+be+valid+JSON") {
		t.Fatalf("bad json: %s", w.Header().Get("Location"))
	}
	w = get(h, "/ui/orgs/other", sessCookie, csrfCookieV)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "org admin required") {
		t.Fatalf("non-admin: %d %s", w.Code, w.Body.String())
	}
}
