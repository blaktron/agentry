package api

import (
	"testing"

	"github.com/blaktron/agentry/internal/config"
)

// The one table every browser destination goes through: with a
// site in front the destinations are the site's pages; without one they
// are the server's own /ui/ pages, relative for redirects and absolute
// from baseURL for links that leave the browser, and nothing where only a
// site has the page (a dashboard, settings, invitations, an organization
// console).
func TestWebPaths(t *testing.T) {
	cases := []struct {
		name          string
		cfg           config.Config
		login, loginE string
		dashPath      string
		dashURL       string
		settings      string
		invitation    string
		orgConsole    string
		home          string
		verify        string
		authorize     string
		report        string
	}{
		{
			name:      "core alone, public origin known",
			cfg:       config.Config{BaseURL: "https://reg.example/"},
			login:     "/ui/login",
			loginE:    "/ui/login?error=nope+%26+no",
			dashPath:  "/ui/",
			home:      "https://reg.example/ui/",
			verify:    "https://reg.example/ui/verify-email?token=t%2F1",
			authorize: "https://reg.example/ui/authorize",
			report:    "https://reg.example/api/v1/agents/acme/widget/versions/1.0.0+build/report",
		},
		{
			name:     "core alone, no public origin",
			cfg:      config.Config{},
			login:    "/ui/login",
			loginE:   "/ui/login?error=nope+%26+no",
			dashPath: "/ui/",
		},
		{
			name:       "a site in front",
			cfg:        config.Config{BaseURL: "https://reg.example", Web: config.Web{URL: "https://site.example/"}},
			login:      "https://site.example/login",
			loginE:     "https://site.example/login?error=nope+%26+no",
			dashPath:   "/dashboard",
			dashURL:    "https://site.example/dashboard",
			settings:   "https://site.example/settings",
			invitation: "https://site.example/invitations/tok",
			orgConsole: "https://site.example/orgs/acme/admin",
			home:       "https://site.example/",
			verify:     "https://site.example/auth/verify-email?token=t%2F1",
			authorize:  "https://reg.example/ui/authorize",
			report:     "https://site.example/acme/widget/versions/1.0.0+build",
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
			check("settingsURL", p.settingsURL(), c.settings)
			check("invitationURL", p.invitationURL("tok"), c.invitation)
			check("orgConsoleURL", p.orgConsoleURL("acme"), c.orgConsole)
			check("homeURL", p.homeURL(), c.home)
			check("verifyEmailURL", p.verifyEmailURL("t/1"), c.verify)
			check("authorizeURL", p.authorizeURL(), c.authorize)
			check("reportCardURL", p.reportCardURL("acme/widget", "1.0.0+build"), c.report)
		})
	}

	// Whatever a destination names is escaped for the place it lands: a
	// path segment, or a query value (where "+" and "&" would otherwise
	// change what the link says).
	t.Run("what a destination names is escaped for its place", func(t *testing.T) {
		site := newWebPaths(config.Config{BaseURL: "https://reg.example", Web: config.Web{URL: "https://site.example"}})
		core := newWebPaths(config.Config{BaseURL: "https://reg.example"})
		for _, c := range []struct{ what, got, want string }{
			{"invitation token", site.invitationURL("a/b c?d"), "https://site.example/invitations/a%2Fb%20c%3Fd"},
			{"organization handle", site.orgConsoleURL("a b/c"), "https://site.example/orgs/a%20b%2Fc/admin"},
			{"version on the site", site.reportCardURL("acme/widget", "1.0.0 rc/1"), "https://site.example/acme/widget/versions/1.0.0%20rc%2F1"},
			{"version on the API", core.reportCardURL("acme/widget", "1.0.0 rc/1"), "https://reg.example/api/v1/agents/acme/widget/versions/1.0.0%20rc%2F1/report"},
			{"verification token on the site", site.verifyEmailURL("a+b c/d&e=f"), "https://site.example/auth/verify-email?token=a%2Bb+c%2Fd%26e%3Df"},
			{"verification token on the server", core.verifyEmailURL("a+b c/d&e=f"), "https://reg.example/ui/verify-email?token=a%2Bb+c%2Fd%26e%3Df"},
			{"sign-in message on the site", site.login("a+b&c=d"), "https://site.example/login?error=a%2Bb%26c%3Dd"},
		} {
			if c.got != c.want {
				t.Errorf("%s = %q, want %q", c.what, c.got, c.want)
			}
		}
	})
}
