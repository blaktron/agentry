package api_test

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	"github.com/blaktron/agentry/internal/testidp"
)

// The server's own browser surface (internal/ui) against the real API and a
// stand-in OpenID provider: the device-authorize page sends a signed-out
// browser to sign in, the sign-in page hands it to the provider, the
// callback brings it back signed in, the page approves the device, the app
// exchanges the code, and sign-out ends the session — every step through the
// same handlers and the same session the API issues.
func TestCoreUISignInAccountAndDeviceAuthorize(t *testing.T) {
	env, idp := newOIDCTestEnv(t, nil)
	handle := "uiuser" + env.sfx
	idp.SignInAs(testidp.Person{Subject: "sub-" + handle, Email: handle + "@example.test", EmailVerified: true, Username: handle})

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	base, _ := url.Parse(env.srv.URL)
	// follow walks the redirects a browser would, the provider's included,
	// and returns the first answer that is not one.
	follow := func(to string) (*http.Response, string) {
		t.Helper()
		for range 10 {
			u, err := base.Parse(to)
			if err != nil {
				t.Fatal(err)
			}
			c := client
			if u.Host != base.Host {
				c = &http.Client{Transport: idp.Client().Transport, CheckRedirect: client.CheckRedirect}
			}
			res, err := c.Get(u.String())
			if err != nil {
				t.Fatal(err)
			}
			if res.StatusCode != http.StatusSeeOther && res.StatusCode != http.StatusFound {
				return res, u.String()
			}
			_ = res.Body.Close()
			to = res.Header.Get("Location")
		}
		t.Fatal("too many redirects")
		return nil, ""
	}
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
	res, _ = follow("/ui/")
	b, _ = io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK || !strings.Contains(string(b), "signed in as "+handle) {
		t.Fatalf("landing: %d %s", res.StatusCode, b)
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
	res = postForm("/ui/logout", url.Values{})
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("logout: %d", res.StatusCode)
	}
	res, err := client.Get(env.srv.URL + "/ui/authorize?port=40123&state=state_abcdefgh")
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusSeeOther || !strings.HasPrefix(res.Header.Get("Location"), "/ui/login?next=") {
		t.Fatalf("after logout: %d %s", res.StatusCode, res.Header.Get("Location"))
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
