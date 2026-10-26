package api_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/httpmux"
)

// The /ui/ surface is dispatched in front of the mux, not registered on it:
// registered, "/ui/" and git's "GET /{ns}/{repo}/info/refs" are a ServeMux
// conflict and the process panics at start-up (the gitsrv conformance test
// covers it). Both must route with git mounted.
func TestUIMountsBesideGitPatterns(t *testing.T) {
	cfg := config.Default()
	cfg.DevMode = true
	srv := api.New(cfg, nil, nil)
	gitHits := 0
	// Registered behind api.Mount's back, on purpose: the recorder still sees
	// the patterns, which is what makes an undeclared mount fail the
	// completeness gate rather than only a missing declaration panic here.
	h := api.NewHandlerWithGit(srv, func(mux httpmux.Mux) {
		mux.HandleFunc("GET /{ns}/{repo}/info/refs", func(w http.ResponseWriter, _ *http.Request) { gitHits++; w.WriteHeader(http.StatusOK) })
		mux.HandleFunc("POST /{ns}/{repo}/git-upload-pack", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
		mux.HandleFunc("POST /{ns}/{repo}/git-receive-pack", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	})
	ts := httptest.NewServer(h)
	defer ts.Close()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	res, err := client.Get(ts.URL + "/acme/tool.git/info/refs")
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK || gitHits != 1 {
		t.Fatalf("git route: %d hits=%d", res.StatusCode, gitHits)
	}
	res, err = client.Get(ts.URL + "/ui/login")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK || !strings.Contains(string(b), "Sign in") {
		t.Fatalf("ui route: %d %s", res.StatusCode, b)
	}
	res, err = client.Get(ts.URL + "/ui/x/info/refs")
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if gitHits != 1 {
		t.Fatalf("/ui/x/info/refs reached git (hits=%d)", gitHits)
	}

	// Only the handle "ui" is the surface's: a namespace that merely begins
	// with those letters is a repository, and git answers for it.
	res, err = client.Get(ts.URL + "/uitools/widget.git/info/refs")
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK || gitHits != 2 {
		t.Fatalf("a namespace that begins with ui: %d hits=%d, want git's 200 and 2 hits", res.StatusCode, gitHits)
	}
	// The bare /ui is the surface's too: it is its entrance, which sends a
	// signed-out browser to sign in.
	res, err = client.Get(ts.URL + "/ui")
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/ui/login" {
		t.Fatalf("GET /ui: %d -> %q, want 303 to /ui/login", res.StatusCode, res.Header.Get("Location"))
	}

	t.Run("the mounted pages carry the surface's headers and exact policy", func(t *testing.T) {
		res, err := client.Get(ts.URL + "/ui/login")
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		for k, want := range map[string]string{
			"Content-Security-Policy": uiBareCSP,
			"Cache-Control":           "no-store, no-transform",
			"Content-Type":            "text/html; charset=utf-8",
			"X-Content-Type-Options":  "nosniff",
			"X-Frame-Options":         "DENY",
			"Referrer-Policy":         "no-referrer",
		} {
			if got := res.Header.Get(k); got != want {
				t.Errorf("%s = %q, want %q", k, got, want)
			}
		}
	})

	t.Run("the stylesheet is served as a cacheable sheet", func(t *testing.T) {
		res, err := client.Get(ts.URL + "/ui/static/ui.css")
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		if res.StatusCode != http.StatusOK || len(b) == 0 {
			t.Fatalf("stylesheet: %d, %d bytes", res.StatusCode, len(b))
		}
		if got := res.Header.Get("Content-Type"); got != "text/css; charset=utf-8" {
			t.Errorf("Content-Type = %q", got)
		}
		if got := res.Header.Get("Cache-Control"); got != "public, max-age=3600" {
			t.Errorf("Cache-Control = %q", got)
		}
		// The link a page carries names the sheet by a short hash of its
		// bytes, so a changed sheet is fetched again inside the hour.
		page, err := client.Get(ts.URL + "/ui/login")
		if err != nil {
			t.Fatal(err)
		}
		pb, _ := io.ReadAll(page.Body)
		_ = page.Body.Close()
		if !regexp.MustCompile(`href="/ui/static/ui\.css\?v=[0-9a-f]{12}"`).Match(pb) {
			t.Errorf("the sign-in page does not link the sheet by a 12-digit hash: %s", pb)
		}
	})

	t.Run("a path the surface does not serve gets its own refusal page", func(t *testing.T) {
		get := func(path, referer string) (*http.Response, string) {
			req, _ := http.NewRequest(http.MethodGet, ts.URL+path, nil)
			if referer != "" {
				req.Header.Set("Referer", referer)
			}
			res, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			b, _ := io.ReadAll(res.Body)
			_ = res.Body.Close()
			return res, string(b)
		}
		res, body := get("/ui/nope", "")
		if res.StatusCode != http.StatusNotFound || !strings.Contains(body, "No such page") ||
			!strings.Contains(body, `href="/ui/">Go to the registry</a>`) {
			t.Fatalf("an unknown page: %d %s", res.StatusCode, body)
		}
		// The way back is the page the browser came from, when that page is
		// on this origin (its path, never its query); a referer from another
		// site is not followed.
		res, body = get("/ui/nope", ts.URL+"/ui/authorize?port=40123")
		if res.StatusCode != http.StatusNotFound || !strings.Contains(body, `href="/ui/authorize">Go back</a>`) {
			t.Fatalf("an unknown page after /ui/authorize: %d %s", res.StatusCode, body)
		}
		res, body = get("/ui/nope", "https://elsewhere.example/ui/authorize")
		if res.StatusCode != http.StatusNotFound || !strings.Contains(body, `href="/ui/">Go to the registry</a>`) ||
			strings.Contains(body, "Go back") {
			t.Fatalf("an unknown page after another site's page: %d %s", res.StatusCode, body)
		}
		// A page that exists under another method keeps the router's 405.
		resp, err := client.Post(ts.URL+"/ui/login", "application/x-www-form-urlencoded", strings.NewReader(""))
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed || !strings.Contains(resp.Header.Get("Allow"), "GET") {
			t.Fatalf("POST /ui/login: %d Allow=%q, want 405 naming GET", resp.StatusCode, resp.Header.Get("Allow"))
		}
	})

	// Each configuration below is a deployment: what it is set to reaches
	// the mounted surface, not a default.
	mount := func(t *testing.T, mod func(*config.Config)) *httptest.Server {
		t.Helper()
		cfg := config.Default()
		cfg.DevMode = true
		mod(&cfg)
		h := api.NewHandlerWithGit(api.New(cfg, nil, nil), func(mux httpmux.Mux) {
			mux.HandleFunc("GET /{ns}/{repo}/info/refs", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
		})
		s := httptest.NewServer(h)
		t.Cleanup(s.Close)
		return s
	}
	fetch := func(t *testing.T, base, method, path string) (*http.Response, string) {
		t.Helper()
		req, _ := http.NewRequest(method, base+path, nil)
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		return res, string(b)
	}

	t.Run("ui.mode off mounts no pages and leaves the repositories alone", func(t *testing.T) {
		s := mount(t, func(c *config.Config) { c.UI.Mode = "off" })
		for _, path := range []string{"/ui/login", "/ui/", "/ui"} {
			res, body := fetch(t, s.URL, http.MethodGet, path)
			if res.StatusCode != http.StatusNotFound || strings.Contains(body, "Sign in") || res.Header.Get("Content-Security-Policy") == uiBareCSP {
				t.Errorf("GET %s with the surface off: %d %s", path, res.StatusCode, body)
			}
		}
		if res, _ := fetch(t, s.URL, http.MethodGet, "/acme/tool.git/info/refs"); res.StatusCode != http.StatusTeapot {
			t.Errorf("git with the surface off: %d", res.StatusCode)
		}
	})

	t.Run("ui.mode authorize serves the device page only and sends the rest to the site", func(t *testing.T) {
		s := mount(t, func(c *config.Config) {
			c.UI.Mode = "authorize"
			c.Web.URL = "https://site.example/"
		})
		for _, path := range []string{"/ui/login", "/ui/verify-email?token=abc"} {
			res, body := fetch(t, s.URL, http.MethodGet, path)
			if res.StatusCode != http.StatusNotFound || !strings.Contains(body, "No such page") {
				t.Errorf("GET %s in authorize mode: %d %s", path, res.StatusCode, body)
			}
		}
		if res, body := fetch(t, s.URL, http.MethodPost, "/ui/logout"); res.StatusCode != http.StatusNotFound || !strings.Contains(body, "No such page") {
			t.Errorf("POST /ui/logout in authorize mode: %d %s", res.StatusCode, body)
		}
		// The entrance and the sign-in hand-off are the site's.
		if res, _ := fetch(t, s.URL, http.MethodGet, "/ui/"); res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "https://site.example/" {
			t.Errorf("GET /ui/ in authorize mode: %d -> %q, want 303 to the site", res.StatusCode, res.Header.Get("Location"))
		}
		res, _ := fetch(t, s.URL, http.MethodGet, "/ui/authorize?port=40123&state=state_abcdefgh")
		if want := "https://site.example/login?next=%2Fui%2Fauthorize%3Fport%3D40123%26state%3Dstate_abcdefgh"; res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != want {
			t.Errorf("signed-out device page with a site: %d -> %q, want 303 to %q", res.StatusCode, res.Header.Get("Location"), want)
		}
		// With the site named, the policy lets a form leave for it (sign-out).
		res, _ = fetch(t, s.URL, http.MethodGet, "/ui/static/ui.css")
		if res.StatusCode != http.StatusOK {
			t.Errorf("stylesheet in authorize mode: %d", res.StatusCode)
		}
	})

	t.Run("a branded deployment's origins reach the policy and its names reach the page", func(t *testing.T) {
		s := mount(t, func(c *config.Config) {
			c.Web.URL = "https://site.example"
			c.Auth.IdPLogoutURL = "https://auth.brand.example/flows/-/cancel/?next=/end-session/"
			c.Brand = config.Brand{
				Name: "Brand Registry", LogoURL: "https://img.brand.example/logo.png", CSSURL: "https://cdn.brand.example/theme.css",
				SupportEmail: "help@brand.example", SecurityEmail: "security@brand.example",
				PrivacyURL: "https://brand.example/privacy", TermsURL: "https://brand.example/terms",
			}
		})
		res, body := fetch(t, s.URL, http.MethodGet, "/ui/login")
		const want = "default-src 'none'; style-src 'self' https://cdn.brand.example; img-src 'self' data: https://img.brand.example; " +
			"form-action 'self' http://127.0.0.1:* https://auth.brand.example https://site.example; base-uri 'none'; frame-ancestors 'none'"
		if got := res.Header.Get("Content-Security-Policy"); got != want {
			t.Errorf("policy\n got %q\nwant %q", got, want)
		}
		for _, frag := range []string{
			"<title>Sign in · Brand Registry</title>",
			`<link rel="stylesheet" href="https://cdn.brand.example/theme.css">`,
			`<img src="https://img.brand.example/logo.png"`,
			`<a href="mailto:help@brand.example">Support</a>`,
			`<a href="https://brand.example/privacy">Privacy</a>`,
			`<a href="https://brand.example/terms">Terms</a>`,
		} {
			if !strings.Contains(body, frag) {
				t.Errorf("the page lacks %s: %s", frag, body)
			}
		}
		if strings.Contains(body, "security@brand.example") {
			t.Errorf("the page prints the security address: %s", body)
		}
		// With a site in front, signed-out people are sent to its sign-in.
		if res, _ := fetch(t, s.URL, http.MethodGet, "/ui/"); res.Header.Get("Location") != "https://site.example/login" {
			t.Errorf("GET /ui/ with a site: -> %q, want the site's sign-in", res.Header.Get("Location"))
		}
	})

	t.Run("the policy lists an origin once and takes none from an address that has no origin", func(t *testing.T) {
		s := mount(t, func(c *config.Config) {
			c.Web.URL = "https://site.example"
			c.Auth.IdPLogoutURL = "https://site.example/signed-out"
			c.Brand = config.Brand{LogoURL: "data:image/png;base64,AAAA", CSSURL: "/static/theme.css"}
		})
		res, _ := fetch(t, s.URL, http.MethodGet, "/ui/login")
		const want = "default-src 'none'; style-src 'self'; img-src 'self' data:; form-action 'self' http://127.0.0.1:* https://site.example; base-uri 'none'; frame-ancestors 'none'"
		if got := res.Header.Get("Content-Security-Policy"); got != want {
			t.Errorf("policy\n got %q\nwant %q", got, want)
		}
		s2 := mount(t, func(c *config.Config) { c.Brand = config.Brand{LogoURL: "//cdn.example/logo.png"} })
		res, _ = fetch(t, s2.URL, http.MethodGet, "/ui/login")
		if got := res.Header.Get("Content-Security-Policy"); got != uiBareCSP {
			t.Errorf("a scheme-less logo address changed the policy: %q", got)
		}
	})
}

// uiBareCSP is the policy the surface sends when the deployment names no
// origin of its own: no scripts, no inline styles, forms only to itself and
// to the loopback listener of the program that opened the device page.
const uiBareCSP = "default-src 'none'; style-src 'self'; img-src 'self' data:; form-action 'self' http://127.0.0.1:*; base-uri 'none'; frame-ancestors 'none'"
