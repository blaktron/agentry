package api_test

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/config"
	storegen "github.com/blaktron/agentry/internal/store/gen"
	"github.com/blaktron/agentry/internal/testidp"
)

// The server's own browser surface (internal/ui) against the real API and a
// stand-in OpenID provider: the device-authorize page sends a signed-out
// browser to sign in, the sign-in page hands it to the provider, the
// callback brings it back signed in, the page approves the device, the app
// exchanges the code, and sign-out ends the session — every step through the
// same handlers and the same session the API issues.
func TestCoreUISignInAccountAndDeviceAuthorize(t *testing.T) {
	br := newUIBrowser(t, nil)
	env, handle, jar, client, base := br.env, br.handle, br.jar, br.client, br.base
	follow, postForm := br.follow, br.postForm

	// Signed out: the device page goes through sign-in and comes back.
	res, landed := follow("/ui/authorize?port=40123&state=state_abcdefgh")
	b, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK || !strings.HasSuffix(landed, "/ui/authorize?port=40123&state=state_abcdefgh") ||
		!strings.Contains(string(b), "127.0.0.1:40123") || !strings.Contains(string(b), handle) {
		t.Fatalf("authorize after sign-in: %d at %s: %s", res.StatusCode, landed, b)
	}
	if csrfCookie(jar, base) == "" {
		t.Fatal("no csrf cookie after sign-in")
	}
	// The page is the form the browser submits: the cookie's token and the
	// program's port and state ride in its hidden fields to the page's own
	// route, and nothing on it may be cached or loaded from elsewhere.
	csrf := csrfCookie(jar, base)
	for _, frag := range []string{
		`<form method="post" action="/ui/authorize">`,
		`<input type="hidden" name="_csrf" value="` + csrf + `">`,
		`<input type="hidden" name="port" value="40123">`,
		`<input type="hidden" name="state" value="state_abcdefgh">`,
		"Scopes: " + strings.Join(auth.SignInGrantScopes(), ", ") + ".",
	} {
		if !strings.Contains(string(b), frag) {
			t.Errorf("the device page lacks %s: %s", frag, b)
		}
	}
	for k, want := range map[string]string{
		"Content-Security-Policy": uiBareCSP,
		"Cache-Control":           "no-store, no-transform",
		"Content-Type":            "text/html; charset=utf-8",
	} {
		if got := res.Header.Get(k); got != want {
			t.Errorf("device page %s = %q, want %q", k, got, want)
		}
	}
	res, _ = follow("/ui/")
	b, _ = io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK || !strings.Contains(string(b), "signed in as "+handle) {
		t.Fatalf("landing: %d %s", res.StatusCode, b)
	}
	if want := `<form method="post" action="/ui/logout"><input type="hidden" name="_csrf" value="` + csrf + `">`; !strings.Contains(string(b), want) {
		t.Fatalf("the signed-in page has no sign-out form carrying the cookie's token: %s", b)
	}

	// The approval, the loopback redirect with a code, the exchange from
	// "the app".
	res = postForm("/ui/authorize", url.Values{"port": {"40123"}, "state": {"state_abcdefgh"}})
	loc := res.Header.Get("Location")
	if res.StatusCode != http.StatusSeeOther || !strings.HasPrefix(loc, "http://127.0.0.1:40123/callback?") {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("approve: %d %s %s", res.StatusCode, loc, b)
	}
	cb, _ := url.Parse(loc)
	code := cb.Query().Get("code")
	if !strings.HasPrefix(code, "agd_") || cb.Query().Get("state") != "state_abcdefgh" {
		t.Fatalf("callback: %s", loc)
	}
	var minted struct {
		Token string `json:"token"`
	}
	env.doJSON(anonymous, http.MethodPost, "/api/v1/auth/desktop/exchange", map[string]any{"code": code, "state": "state_abcdefgh"}, &minted, http.StatusCreated)
	if !strings.HasPrefix(minted.Token, "agy_") {
		t.Fatalf("exchange: %+v", minted)
	}
	env.doJSON(caller{name: "app", pat: minted.Token}, http.MethodGet, "/api/v1/user", nil, nil, http.StatusOK)

	// Sign out clears the cookies; the device page asks for sign-in again.
	session := cookieOf(jar, base, "agentry_session")
	// A sign-out another site posted, or one without the page's token,
	// leaves the session alone.
	for name, c := range map[string]struct {
		hdr  map[string]string
		form url.Values
		want string
	}{
		"from another site":  {map[string]string{"Sec-Fetch-Site": "cross-site"}, url.Values{"_csrf": {csrf}}, "Form refused"},
		"without the token":  {map[string]string{"Sec-Fetch-Site": "same-origin"}, url.Values{}, "Form token mismatch"},
		"with another token": {map[string]string{"Sec-Fetch-Site": "same-origin"}, url.Values{"_csrf": {"csrf_other"}}, "Form token mismatch"},
	} {
		r, body := br.rawPost("/ui/logout", c.hdr, c.form.Encode(), session, csrf)
		if r.StatusCode != http.StatusForbidden || !strings.Contains(body, c.want) {
			t.Errorf("sign-out %s: %d %s, want 403 %q", name, r.StatusCode, body, c.want)
		}
		env.doJSON(caller{name: "browser", session: session, csrf: csrf}, http.MethodGet, "/api/v1/user", nil, nil, http.StatusOK)
	}
	res = postForm("/ui/logout", url.Values{})
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("logout: %d", res.StatusCode)
	}
	if got := res.Header.Get("Location"); got != "/ui/" {
		t.Errorf("logout sends the browser to %q, want /ui/", got)
	}
	cleared := map[string]*http.Cookie{}
	for _, c := range res.Cookies() {
		cleared[c.Name] = c
	}
	for _, name := range []string{"agentry_session", "agentry_csrf"} {
		if c := cleared[name]; c == nil || c.Value != "" || c.Path != "/" || c.MaxAge >= 0 || !c.HttpOnly {
			t.Errorf("logout does not clear %s for the whole site: %+v", name, c)
		}
	}
	// The session is revoked on the server, not only forgotten by the browser.
	env.doJSON(caller{name: "browser", session: session, csrf: csrf}, http.MethodGet, "/api/v1/user", nil, nil, http.StatusUnauthorized)
	res, err := client.Get(env.srv.URL + "/ui/authorize?port=40123&state=state_abcdefgh")
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusSeeOther || !strings.HasPrefix(res.Header.Get("Location"), "/ui/login?next=") {
		t.Fatalf("after logout: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	// The way back after signing in is the whole address of the page,
	// query included, as one value.
	if want := "/ui/login?next=%2Fui%2Fauthorize%3Fport%3D40123%26state%3Dstate_abcdefgh"; res.Header.Get("Location") != want {
		t.Fatalf("after logout: sent to %q, want %q", res.Header.Get("Location"), want)
	}

	t.Run("the device page admits only a listener port and a state the API admits", func(t *testing.T) {
		br := newUIBrowser(t, nil)
		br.signIn()
		for _, c := range []struct {
			name, port, state string
			ok                bool
		}{
			{"lowest port", "1024", "abcdefgh", true},
			{"port below the lowest", "1023", "abcdefgh", false},
			{"highest port", "65535", "abcdefgh", true},
			{"port above the highest", "65536", "abcdefgh", false},
			{"port that is not a number", "forty", "abcdefgh", false},
			{"no port", "", "abcdefgh", false},
			{"shortest state", "40123", "abcdefgh", true},
			{"state one character short", "40123", "abcdefg", false},
			{"longest state", "40123", strings.Repeat("a", 128), true},
			{"state one character long", "40123", strings.Repeat("a", 129), false},
			{"every kind of allowed character", "40123", "Az09_-Az09_-", true},
			{"a dot in the state", "40123", "abcdefg.h", false},
			{"junk before the state", "40123", "!abcdefgh", false},
			{"junk after the state", "40123", "abcdefgh!", false},
		} {
			q := url.Values{"port": {c.port}, "state": {c.state}}
			page, body := br.get("/ui/authorize?" + q.Encode())
			wantStatus := http.StatusOK
			if !c.ok {
				wantStatus = http.StatusBadRequest
			}
			if page.StatusCode != wantStatus || strings.Contains(body, "127.0.0.1:"+c.port+"</code>") != c.ok ||
				strings.Contains(body, "missing or malformed") == c.ok || strings.Contains(body, `<form method="post" action="/ui/authorize">`) != c.ok {
				t.Errorf("%s: page %d, want %d: %s", c.name, page.StatusCode, wantStatus, body)
			}
			res := br.postForm("/ui/authorize", q)
			b, _ := io.ReadAll(res.Body)
			_ = res.Body.Close()
			if c.ok {
				loc := res.Header.Get("Location")
				if res.StatusCode != http.StatusSeeOther || !strings.HasPrefix(loc, "http://127.0.0.1:"+c.port+"/callback?") ||
					!strings.Contains(loc, "state="+url.QueryEscape(c.state)) {
					t.Errorf("%s: approval %d -> %q", c.name, res.StatusCode, loc)
					continue
				}
				// The code is bound to the state the program sent: it
				// exchanges for a token with that state and with no other.
				cb, _ := url.Parse(loc)
				code := cb.Query().Get("code")
				br.env.doJSON(anonymous, http.MethodPost, "/api/v1/auth/desktop/exchange", map[string]any{"code": code, "state": "state_not_the_one"}, nil, http.StatusForbidden)
				var minted struct {
					Token string `json:"token"`
				}
				br.env.doJSON(anonymous, http.MethodPost, "/api/v1/auth/desktop/exchange", map[string]any{"code": code, "state": c.state}, &minted, http.StatusCreated)
				if !strings.HasPrefix(minted.Token, "agy_") {
					t.Errorf("%s: exchange gave %+v", c.name, minted)
				}
			} else if res.StatusCode != http.StatusBadRequest || !strings.Contains(string(b), "Invalid device request") || res.Header.Get("Location") != "" {
				t.Errorf("%s: approval %d %s, want 400 Invalid device request", c.name, res.StatusCode, b)
			}
		}
	})

	t.Run("the approval is accepted only as the page's own form", func(t *testing.T) {
		br := newUIBrowser(t, nil)
		br.signIn()
		session, csrf := cookieOf(br.jar, br.base, "agentry_session"), cookieOf(br.jar, br.base, "agentry_csrf")
		form := func(token string) string {
			return url.Values{"port": {"40123"}, "state": {"state_abcdefgh"}, "_csrf": {token}}.Encode()
		}
		const callback = "http://127.0.0.1:40123/callback?"
		for _, c := range []struct {
			name   string
			hdr    map[string]string
			body   string
			cookie []string // session, csrf cookie values; "" omits the cookie
			status int
			want   string // in the body of a refusal, or the start of the Location
		}{
			{"same-origin", map[string]string{"Sec-Fetch-Site": "same-origin"}, form(csrf), []string{session, csrf}, http.StatusSeeOther, callback},
			{"address bar (none)", map[string]string{"Sec-Fetch-Site": "none"}, form(csrf), []string{session, csrf}, http.StatusSeeOther, callback},
			{"another site", map[string]string{"Sec-Fetch-Site": "cross-site"}, form(csrf), []string{session, csrf}, http.StatusForbidden, "Form refused"},
			{"a sibling site", map[string]string{"Sec-Fetch-Site": "same-site"}, form(csrf), []string{session, csrf}, http.StatusForbidden, "Form refused"},
			{"no fetch metadata, no origin", nil, form(csrf), []string{session, csrf}, http.StatusSeeOther, callback},
			{"no fetch metadata, this origin", map[string]string{"Origin": br.env.srv.URL}, form(csrf), []string{session, csrf}, http.StatusSeeOther, callback},
			{"no fetch metadata, another origin", map[string]string{"Origin": "https://elsewhere.example"}, form(csrf), []string{session, csrf}, http.StatusForbidden, "Form refused"},
			{"a forwarded host from a proxy the server does not trust", map[string]string{"Origin": "https://registry.example", "X-Forwarded-Host": "registry.example"}, form(csrf), []string{session, csrf}, http.StatusForbidden, "Form refused"},
			{"this origin beside an untrusted forwarded host", map[string]string{"Origin": br.env.srv.URL, "X-Forwarded-Host": "registry.example"}, form(csrf), []string{session, csrf}, http.StatusSeeOther, callback},
			{"no token in the form", map[string]string{"Sec-Fetch-Site": "same-origin"}, form(""), []string{session, csrf}, http.StatusForbidden, "Form token mismatch"},
			{"another token in the form", map[string]string{"Sec-Fetch-Site": "same-origin"}, form("csrf_other"), []string{session, csrf}, http.StatusForbidden, "Form token mismatch"},
			{"no token cookie and none in the form", map[string]string{"Sec-Fetch-Site": "same-origin"}, form(""), []string{session, ""}, http.StatusForbidden, "Form token mismatch"},
			{"a form the server cannot read", map[string]string{"Sec-Fetch-Site": "same-origin"}, "port=%zz", []string{session, csrf}, http.StatusBadRequest, "Unreadable form"},
		} {
			res, body := br.rawPost("/ui/authorize", c.hdr, c.body, c.cookie[0], c.cookie[1])
			if res.StatusCode != c.status {
				t.Errorf("%s: %d %s, want %d", c.name, res.StatusCode, body, c.status)
				continue
			}
			if c.status == http.StatusSeeOther {
				if loc := res.Header.Get("Location"); !strings.HasPrefix(loc, c.want) {
					t.Errorf("%s: sent to %q, want %q...", c.name, loc, c.want)
				}
			} else if !strings.Contains(body, c.want) || res.Header.Get("Location") != "" {
				t.Errorf("%s: %s, want the refusal %q", c.name, body, c.want)
			}
		}
	})

	t.Run("behind a trusted proxy the origin is matched against the forwarded host", func(t *testing.T) {
		br := newUIBrowser(t, func(c *config.Config) { c.HTTP.TrustedProxies = 1 })
		br.signIn()
		session, csrf := cookieOf(br.jar, br.base, "agentry_session"), cookieOf(br.jar, br.base, "agentry_csrf")
		form := url.Values{"port": {"40123"}, "state": {"state_abcdefgh"}, "_csrf": {csrf}}.Encode()
		for _, c := range []struct {
			name   string
			hdr    map[string]string
			status int
		}{
			{"the forwarded host's origin", map[string]string{"Origin": "https://registry.example", "X-Forwarded-Host": "registry.example"}, http.StatusSeeOther},
			{"another origin", map[string]string{"Origin": "https://elsewhere.example", "X-Forwarded-Host": "registry.example"}, http.StatusForbidden},
			{"the inner address instead of the forwarded host", map[string]string{"Origin": br.env.srv.URL, "X-Forwarded-Host": "registry.example"}, http.StatusForbidden},
		} {
			res, body := br.rawPost("/ui/authorize", c.hdr, form, session, csrf)
			if res.StatusCode != c.status {
				t.Errorf("%s: %d %s, want %d", c.name, res.StatusCode, body, c.status)
			}
		}
	})

	t.Run("an approval from a session that has ended goes back to sign-in", func(t *testing.T) {
		br := newUIBrowser(t, nil)
		br.signIn()
		csrf := cookieOf(br.jar, br.base, "agentry_csrf")
		form := url.Values{"port": {"40123"}, "state": {"state_abcdefgh"}, "_csrf": {csrf}}.Encode()
		res, body := br.rawPost("/ui/authorize", map[string]string{"Sec-Fetch-Site": "same-origin"}, form, "ses_ended", csrf)
		want := "/ui/login?next=%2Fui%2Fauthorize%3Fport%3D40123%26state%3Dstate_abcdefgh"
		if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != want {
			t.Errorf("approval with a dead session: %d -> %q %s, want 303 to %q", res.StatusCode, res.Header.Get("Location"), body, want)
		}
		// A live session whose token is not the one the page's cookie holds
		// is refused by the API, and the page sends the person to sign in
		// the same way.
		session := cookieOf(br.jar, br.base, "agentry_session")
		form = url.Values{"port": {"40123"}, "state": {"state_abcdefgh"}, "_csrf": {"csrf_other"}}.Encode()
		res, body = br.rawPost("/ui/authorize", map[string]string{"Sec-Fetch-Site": "same-origin"}, form, session, "csrf_other")
		if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != want {
			t.Errorf("approval with another session's token: %d -> %q %s, want 303 to %q", res.StatusCode, res.Header.Get("Location"), body, want)
		}
	})

	t.Run("sign-in sends a signed-in browser on only to a page of this site", func(t *testing.T) {
		br := newUIBrowser(t, nil)
		br.signIn()
		for _, c := range []struct{ name, next, want string }{
			{"no way on", "", "/ui/"},
			{"a page of this site", "/ui/authorize?port=40123&state=state_abcdefgh", "/ui/authorize?port=40123&state=state_abcdefgh"},
			{"another site", "https://elsewhere.example/ui/", "/ui/"},
			{"a protocol-relative address", "//elsewhere.example/ui/", "/ui/"},
			{"a backslash address", "/\\elsewhere.example/ui/", "/ui/"},
			{"a bare host", "elsewhere.example", "/ui/"},
			{"a line break", "/ui/\r\nSet-Cookie: x=y", "/ui/"},
		} {
			path := "/ui/login"
			if c.next != "" {
				path += "?next=" + url.QueryEscape(c.next)
			}
			res, _ := br.get(path)
			if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != c.want {
				t.Errorf("%s: %d -> %q, want 303 to %q", c.name, res.StatusCode, res.Header.Get("Location"), c.want)
			}
		}
	})

	t.Run("a signed-out browser is sent to sign in, and the sign-in page says what it is told", func(t *testing.T) {
		br := newUIBrowser(t, func(c *config.Config) { c.Auth.OIDC.DisplayName = "Acme SSO" })
		res, _ := br.get("/ui/")
		if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/ui/login" {
			t.Errorf("GET /ui/ signed out: %d -> %q, want 303 to /ui/login", res.StatusCode, res.Header.Get("Location"))
		}
		// One provider and nothing to show: straight to the provider, and the
		// way on rides escaped as one value.
		res, _ = br.get("/ui/login")
		if want := "/api/v1/auth/oidc/oidc/start?next=%2Fui%2F"; res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != want {
			t.Errorf("GET /ui/login signed out: %d -> %q, want 303 to %q", res.StatusCode, res.Header.Get("Location"), want)
		}
		// A message to show keeps the page, as escaped text with the
		// provider's button under its configured name.
		res, body := br.get("/ui/login?error=" + url.QueryEscape("<script>alert(1)</script>"))
		if res.StatusCode != http.StatusOK || strings.Contains(body, "<script>") ||
			!strings.Contains(body, `<p class="flash error">&lt;script&gt;alert(1)&lt;/script&gt;</p>`) ||
			!strings.Contains(body, `href="/api/v1/auth/oidc/oidc/start?next=%2Fui%2F">Continue with Acme SSO</a>`) {
			t.Errorf("GET /ui/login?error=: %d %s", res.StatusCode, body)
		}
		// A page that asks a person to approve something is not asked for
		// without a session, whatever its parameters are.
		res, _ = br.get("/ui/authorize?port=1&state=x")
		if want := "/ui/login?next=%2Fui%2Fauthorize%3Fport%3D1%26state%3Dx"; res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != want {
			t.Errorf("GET /ui/authorize signed out: %d -> %q, want 303 to %q", res.StatusCode, res.Header.Get("Location"), want)
		}
		// A notice a redirect left for this page is shown instead of the
		// direct hand-off, once: the cookie that carried it is cleared. A
		// message in the address wins over the cookie's.
		flash := base64.RawURLEncoding.EncodeToString([]byte(`{"ok":"Saved it.","error":"Could not do it."}`))
		withFlash := func(path string) (*http.Response, string) {
			req, _ := http.NewRequest(http.MethodGet, br.env.srv.URL+path, nil)
			req.AddCookie(&http.Cookie{Name: "agentry_flash", Value: flash})
			res, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
			if err != nil {
				t.Fatal(err)
			}
			b, _ := io.ReadAll(res.Body)
			_ = res.Body.Close()
			return res, string(b)
		}
		res, body = withFlash("/ui/login")
		if res.StatusCode != http.StatusOK || !strings.Contains(body, `<p class="flash ok">Saved it.</p>`) || !strings.Contains(body, `<p class="flash error">Could not do it.</p>`) {
			t.Errorf("sign-in page with a notice waiting: %d %s", res.StatusCode, body)
		}
		var cleared *http.Cookie
		for _, c := range res.Cookies() {
			if c.Name == "agentry_flash" {
				cleared = c
			}
		}
		if cleared == nil || cleared.Value != "" || cleared.Path != "/ui" || cleared.MaxAge >= 0 || !cleared.HttpOnly {
			t.Errorf("the notice's cookie is not cleared after it is shown: %+v", cleared)
		}
		_, body = withFlash("/ui/login?error=" + url.QueryEscape("From the address"))
		if !strings.Contains(body, `<p class="flash error">From the address</p>`) || strings.Contains(body, "Could not do it.") || !strings.Contains(body, "Saved it.") {
			t.Errorf("a message in the address and a notice waiting: %s", body)
		}
		// Without a configured name the button says "your OpenID provider".
		plain := newUIBrowser(t, nil)
		_, body = plain.get("/ui/login?error=x")
		if !strings.Contains(body, "Continue with your OpenID provider</a>") {
			t.Errorf("the default provider label is missing: %s", body)
		}
	})

	t.Run("the address-confirmation link confirms through the API and says how it went", func(t *testing.T) {
		br := newUIBrowser(t, nil)
		res, body := br.get("/ui/verify-email")
		if res.StatusCode != http.StatusBadRequest || !strings.Contains(body, "This link is missing its token.") {
			t.Errorf("no token: %d %s", res.StatusCode, body)
		}
		res, body = br.get("/ui/verify-email?token=" + url.QueryEscape("vfy_never_issued"))
		if res.StatusCode != http.StatusBadRequest || !strings.Contains(body, "This verification link is invalid or expired.") {
			t.Errorf("a token never issued: %d %s", res.StatusCode, body)
		}
		h := br.env.registerUnverified("uivfy")
		var id uuid.UUID
		if err := br.env.st.Pool().QueryRow(context.Background(), `SELECT id FROM handles WHERE handle = $1`, h).Scan(&id); err != nil {
			t.Fatal(err)
		}
		token := "vfy_issued_for_the_ui_page_" + br.env.sfx
		if err := br.env.st.Queries().CreateEmailVerification(context.Background(), storegen.CreateEmailVerificationParams{
			TokenSha256: auth.HashToken(token), UserID: id, ExpiresAt: time.Now().Add(time.Hour),
		}); err != nil {
			t.Fatal(err)
		}
		res, body = br.get("/ui/verify-email?token=" + url.QueryEscape(token))
		if res.StatusCode != http.StatusOK || !strings.Contains(body, "Your email address is confirmed and your account is activated.") ||
			!strings.Contains(body, `<a class="button" href="/ui/login">Sign in</a>`) {
			t.Errorf("a token issued: %d %s", res.StatusCode, body)
		}
		var verified bool
		if err := br.env.st.Pool().QueryRow(context.Background(), `SELECT email_verified_at IS NOT NULL FROM users WHERE id = $1`, id).Scan(&verified); err != nil || !verified {
			t.Errorf("the address is not confirmed after the link: %v %v", verified, err)
		}
		// The link works once.
		res, body = br.get("/ui/verify-email?token=" + url.QueryEscape(token))
		if res.StatusCode != http.StatusBadRequest || !strings.Contains(body, "This verification link is invalid or expired.") {
			t.Errorf("the same token again: %d %s", res.StatusCode, body)
		}
	})

	t.Run("sign-out ends at the provider's sign-out address when the deployment has one", func(t *testing.T) {
		const idpOut = "https://idp.example/application/o/agentry/end-session/"
		br := newUIBrowser(t, func(c *config.Config) { c.Auth.IdPLogoutURL = idpOut })
		br.signIn()
		res := br.postForm("/ui/logout", url.Values{})
		_ = res.Body.Close()
		if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != idpOut {
			t.Errorf("sign-out: %d -> %q, want 303 to %q", res.StatusCode, res.Header.Get("Location"), idpOut)
		}
		if got := res.Header.Get("Content-Security-Policy"); got != "" {
			t.Errorf("a redirect carries a page policy: %q", got)
		}
	})

	t.Run("a deployment that serves over https has the cookies the surface clears marked Secure", func(t *testing.T) {
		br := newUIBrowser(t, func(c *config.Config) { c.Auth.CookieSecure = true })
		person := br.env.login(br.env.register("uisec"))
		res, body := br.rawPost("/ui/logout", map[string]string{"Sec-Fetch-Site": "same-origin"}, url.Values{"_csrf": {person.csrf}}.Encode(), person.session, person.csrf)
		if res.StatusCode != http.StatusSeeOther {
			t.Fatalf("sign-out: %d %s", res.StatusCode, body)
		}
		if len(res.Cookies()) != 2 {
			t.Errorf("sign-out sets %d cookies, want the two it clears", len(res.Cookies()))
		}
		for _, c := range res.Cookies() {
			if !c.Secure || !c.HttpOnly || c.MaxAge >= 0 {
				t.Errorf("cleared cookie %s = %+v, want Secure, HttpOnly and expired", c.Name, c)
			}
		}
		req, _ := http.NewRequest(http.MethodGet, br.env.srv.URL+"/ui/login", nil)
		req.AddCookie(&http.Cookie{Name: "agentry_flash", Value: base64.RawURLEncoding.EncodeToString([]byte(`{"error":"x"}`))})
		page, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = page.Body.Close()
		var flash *http.Cookie
		for _, c := range page.Cookies() {
			if c.Name == "agentry_flash" {
				flash = c
			}
		}
		if flash == nil || !flash.Secure || !flash.HttpOnly || flash.MaxAge >= 0 {
			t.Errorf("the notice's cleared cookie = %+v, want Secure, HttpOnly and expired", flash)
		}
	})

	t.Run("the API's record of a sign-out names the person's browser and address", func(t *testing.T) {
		br := newUIBrowser(t, func(c *config.Config) { c.HTTP.TrustedProxies = 1 })
		br.signIn()
		session, csrf := cookieOf(br.jar, br.base, "agentry_session"), cookieOf(br.jar, br.base, "agentry_csrf")
		res, body := br.rawPost("/ui/logout", map[string]string{
			"Sec-Fetch-Site": "same-origin", "User-Agent": "agentry-ui-test/1", "X-Forwarded-For": "203.0.113.9",
		}, url.Values{"_csrf": {csrf}}.Encode(), session, csrf)
		if res.StatusCode != http.StatusSeeOther {
			t.Fatalf("sign-out: %d %s", res.StatusCode, body)
		}
		var ua, ip string
		if err := br.env.st.Pool().QueryRow(context.Background(),
			`SELECT user_agent, host(ip) FROM audit_events WHERE action = $1 AND target_id = (SELECT id FROM handles WHERE handle = $2)`,
			string(audit.ActionUserLogout), br.handle).Scan(&ua, &ip); err != nil {
			t.Fatal(err)
		}
		if ua != "agentry-ui-test/1" || ip != "203.0.113.9" {
			t.Errorf("the sign-out audit row names %q at %s, want the browser's agent and its forwarded address", ua, ip)
		}
	})
}

// uiBrowser is a person's browser against the server's own pages: a cookie
// jar signed in through the stand-in provider, and a client that follows
// nothing on its own.
type uiBrowser struct {
	t      *testing.T
	env    *testEnv
	idp    *testidp.IdP
	jar    http.CookieJar
	client *http.Client
	base   *url.URL
	handle string
}

func newUIBrowser(t *testing.T, cfgFn func(*config.Config)) *uiBrowser {
	t.Helper()
	env, idp := newOIDCTestEnv(t, cfgFn)
	handle := "uiuser" + env.sfx
	idp.SignInAs(testidp.Person{Subject: "sub-" + handle, Email: handle + "@example.test", EmailVerified: true, Username: handle})

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	base, _ := url.Parse(env.srv.URL)
	return &uiBrowser{t: t, env: env, idp: idp, jar: jar, client: client, base: base, handle: handle}
}

// follow walks the redirects a browser would, the provider's included,
// and returns the first answer that is not one.
func (b *uiBrowser) follow(to string) (*http.Response, string) {
	b.t.Helper()
	for range 10 {
		u, err := b.base.Parse(to)
		if err != nil {
			b.t.Fatal(err)
		}
		c := b.client
		if u.Host != b.base.Host {
			c = &http.Client{Transport: b.idp.Client().Transport, CheckRedirect: b.client.CheckRedirect}
		}
		res, err := c.Get(u.String())
		if err != nil {
			b.t.Fatal(err)
		}
		if res.StatusCode != http.StatusSeeOther && res.StatusCode != http.StatusFound {
			return res, u.String()
		}
		_ = res.Body.Close()
		to = res.Header.Get("Location")
	}
	b.t.Fatal("too many redirects")
	return nil, ""
}

// postForm posts a form from a page of this site with the cookie's token.
func (b *uiBrowser) postForm(path string, form url.Values) *http.Response {
	b.t.Helper()
	if c := csrfCookie(b.jar, b.base); c != "" {
		form.Set("_csrf", c)
	}
	req, _ := http.NewRequest(http.MethodPost, b.env.srv.URL+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	res, err := b.client.Do(req)
	if err != nil {
		b.t.Fatal(err)
	}
	return res
}

// get is one request of the browser's own, not followed, body read.
func (b *uiBrowser) get(path string) (*http.Response, string) {
	b.t.Helper()
	res, err := b.client.Get(b.env.srv.URL + path)
	if err != nil {
		b.t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	return res, string(body)
}

// signIn takes the browser through the device page's sign-in.
func (b *uiBrowser) signIn() {
	b.t.Helper()
	res, _ := b.follow("/ui/authorize?port=40123&state=state_abcdefgh")
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		b.t.Fatalf("sign-in: %d", res.StatusCode)
	}
}

// rawPost posts a form the way a script or another site would: no jar,
// chosen headers, and chosen session and token cookies ("" leaves one out).
func (b *uiBrowser) rawPost(path string, hdr map[string]string, body string, session, csrf string) (*http.Response, string) {
	b.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, b.env.srv.URL+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	if session != "" {
		req.AddCookie(&http.Cookie{Name: "agentry_session", Value: session})
	}
	if csrf != "" {
		req.AddCookie(&http.Cookie{Name: "agentry_csrf", Value: csrf})
	}
	res, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if err != nil {
		b.t.Fatal(err)
	}
	out, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	return res, string(out)
}

func cookieOf(jar http.CookieJar, u *url.URL, name string) string {
	for _, c := range jar.Cookies(u) {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

func csrfCookie(jar http.CookieJar, u *url.URL) string { return cookieOf(jar, u, "agentry_csrf") }
