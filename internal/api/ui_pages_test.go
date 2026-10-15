package api_test

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
)

// The server's own browser surface (internal/ui) against the real
// API: sign in through the form, read the account, mint a token, authorize
// a device and exchange its code, sign out — every step through the same
// handlers and the same session the API issues.
func TestCoreUISignInAccountAndDeviceAuthorize(t *testing.T) {
	env := newTestEnv(t)
	handle := env.register("uiuser")

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	base, _ := url.Parse(env.srv.URL)
	postForm := func(path string, form url.Values) *http.Response {
		t.Helper()
		if c := csrfCookie(jar, base); c != "" {
			form.Set("_csrf", c)
		}
		req, _ := http.NewRequest(http.MethodPost, env.srv.URL+path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	getPage := func(path string) (int, string) {
		t.Helper()
		res, err := client.Get(env.srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = res.Body.Close() }()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(b)
	}

	// Signed out: the account page sends you to sign in, remembering where.
	if res, _ := client.Get(env.srv.URL + "/ui/account"); res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/ui/login?next=%2Fui%2Faccount" {
		t.Fatalf("signed out: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	res := postForm("/ui/login", url.Values{"login": {handle}, "password": {"hunter2hunter2"}, "next": {"/ui/account"}})
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/ui/account" {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("login: %d %s %s", res.StatusCode, res.Header.Get("Location"), b)
	}
	if csrfCookie(jar, base) == "" {
		t.Fatal("no csrf cookie after sign-in")
	}
	if code, body := getPage("/ui/account"); code != http.StatusOK || !strings.Contains(body, handle) {
		t.Fatalf("account: %d %s", code, body)
	}

	// A token, shown once on the POST's own page.
	res = postForm("/ui/account/tokens", url.Values{"action": {"create"}, "name": {"ci"}, "scopes": {"agent:read"}})
	b, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK || !strings.Contains(string(b), "agy_") {
		t.Fatalf("token: %d %s", res.StatusCode, b)
	}
	if code, body := getPage("/ui/account/tokens"); code != http.StatusOK || !strings.Contains(body, "<strong>ci</strong>") {
		t.Fatalf("tokens list: %d %s", code, body)
	}
	if code, body := getPage("/ui/account/sessions"); code != http.StatusOK || !strings.Contains(body, "this browser") {
		t.Fatalf("sessions: %d %s", code, body)
	}

	// The device flow: the page, the approval, the loopback redirect with a
	// code, the exchange from "the app".
	if code, body := getPage("/ui/authorize?port=40123&state=state_abcdefgh"); code != http.StatusOK || !strings.Contains(body, "127.0.0.1:40123") {
		t.Fatalf("authorize page: %d %s", code, body)
	}
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

	// Sign out clears the cookies; the account page is closed again.
	res = postForm("/ui/logout", url.Values{})
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("logout: %d", res.StatusCode)
	}
	if res, _ := client.Get(env.srv.URL + "/ui/account"); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("after logout: %d", res.StatusCode)
	}
}

func csrfCookie(jar http.CookieJar, u *url.URL) string {
	for _, c := range jar.Cookies(u) {
		if c.Name == "agentry_csrf" {
			return c.Value
		}
	}
	return ""
}
