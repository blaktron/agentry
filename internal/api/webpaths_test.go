package api

import (
	"testing"

	"github.com/blaktron/agentry/internal/config"
)

// The one table every browser destination goes through: with a
// site in front the destinations are the site's pages; without one they
// are the server's own /ui/ pages, relative for redirects and absolute
// from baseURL for links that leave the browser.
func TestWebPaths(t *testing.T) {
	cases := []struct {
		name          string
		cfg           config.Config
		login, loginE string
		dashPath      string
		dashURL       string
		home          string
		verify        string
		account       string
		authorize     string
		report        string
	}{
		{
			name:      "core alone, public origin known",
			cfg:       config.Config{BaseURL: "https://reg.example/"},
			login:     "/ui/login",
			loginE:    "/ui/login?error=nope+%26+no",
			dashPath:  "/ui/account",
			dashURL:   "https://reg.example/ui/account",
			home:      "https://reg.example/ui/",
			verify:    "https://reg.example/ui/verify-email?token=t%2F1",
			account:   "https://reg.example/ui/account/directory",
			authorize: "https://reg.example/ui/authorize",
			report:    "https://reg.example/api/v1/agents/acme/widget/versions/1.0.0+build/report",
		},
		{
			name:     "core alone, no public origin",
			cfg:      config.Config{},
			login:    "/ui/login",
			loginE:   "/ui/login?error=nope+%26+no",
			dashPath: "/ui/account",
		},
		{
			name:      "a site in front",
			cfg:       config.Config{BaseURL: "https://reg.example", Web: config.Web{URL: "https://site.example/"}},
			login:     "https://site.example/login",
			loginE:    "https://site.example/login?error=nope+%26+no",
			dashPath:  "/dashboard",
			dashURL:   "https://site.example/dashboard",
			home:      "https://site.example/",
			verify:    "https://site.example/auth/verify-email?token=t%2F1",
			account:   "https://site.example/settings/authentication",
			authorize: "https://reg.example/ui/authorize",
			report:    "https://site.example/acme/widget/versions/1.0.0+build",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := newWebPaths(c.cfg)
			check := func(what, got, want string) {
				t.Helper()
				if got != want {
					t.Errorf("%s = %q, want %q", what, got, want)
				}
			}
			check("login", p.login(""), c.login)
			check("login(error)", p.login("nope & no"), c.loginE)
			check("dashboardPath", p.dashboardPath(), c.dashPath)
			check("dashboardURL", p.dashboardURL(), c.dashURL)
			check("homeURL", p.homeURL(), c.home)
			check("verifyEmailURL", p.verifyEmailURL("t/1"), c.verify)
			check("accountSettingsURL", p.accountSettingsURL(), c.account)
			check("authorizeURL", p.authorizeURL(), c.authorize)
			check("reportCardURL", p.reportCardURL("acme/widget", "1.0.0+build"), c.report)
		})
	}
}
