package api

import (
	"net/url"
	"strings"

	"github.com/blaktron/agentry/internal/config"
)

// webPaths answers every browser destination this server writes into a
// redirect or an email: where a failed sign-in lands, where a signed-in
// browser goes, where a verification link points, where sign-out ends,
// where a client opens the device-authorize page (DEV-091, plan
// core-web-split §3.1).
//
// With web.url set — a site fronts this server — they are that site's
// pages, absolute. Without it they are the server's own pages under /ui/:
// relative for redirects (same origin by construction) and absolute from
// baseURL for links that leave the browser (emails, clients).
type webPaths struct {
	web  string // the site's origin without a trailing slash; "" = none
	base string // this server's public origin without a trailing slash; "" = unknown
}

func newWebPaths(cfg config.Config) webPaths {
	return webPaths{web: strings.TrimRight(cfg.Web.URL, "/"), base: strings.TrimRight(cfg.BaseURL, "/")}
}

func (p webPaths) site() bool { return p.web != "" }

// abs joins a server-relative path onto the public origin; "" when the
// origin is not configured (callers that need an absolute link say so).
func (p webPaths) abs(path string) string {
	if p.base == "" {
		return ""
	}
	return p.base + path
}

// login is where a browser is sent to sign in; msg, when non-empty, rides
// along as ?error= for the page to show.
func (p webPaths) login(msg string) string {
	dest := "/ui/login"
	if p.site() {
		dest = p.web + "/login"
	}
	if msg != "" {
		dest += "?error=" + url.QueryEscape(msg)
	}
	return dest
}

// dashboardPath is where a signed-in browser lands, as a path: it is the
// `next` of an OIDC start, and safeNextPath admits paths only. (A site on
// another origin than this server would need an absolute next; the compose
// stack shares one origin through the edge, so a path is right there.)
func (p webPaths) dashboardPath() string {
	if p.site() {
		return "/dashboard"
	}
	return "/ui/account"
}

// dashboardURL is the same destination for an email.
func (p webPaths) dashboardURL() string {
	if p.site() {
		return p.web + "/dashboard"
	}
	return p.abs("/ui/account")
}

// settingsURL is the page where a person switches the registry's mails on
// and off: the site's settings page, or this server's account page, which
// carries the same switches (agentry#274).
func (p webPaths) settingsURL() string {
	if p.site() {
		return p.web + "/settings"
	}
	return p.abs("/ui/account")
}

// homeURL is where sign-out ends; "" when neither a site nor a public
// origin is configured.
func (p webPaths) homeURL() string {
	if p.site() {
		return p.web + "/"
	}
	return p.abs("/ui/")
}

// verifyEmailURL is the address-verification link for a token; "" when no
// absolute origin is known (the notifier then sends the code itself).
func (p webPaths) verifyEmailURL(token string) string {
	if p.site() {
		return p.web + "/auth/verify-email?token=" + url.QueryEscape(token)
	}
	if p.base == "" {
		return ""
	}
	return p.base + "/ui/verify-email?token=" + url.QueryEscape(token)
}

// invitationURL is where an invited person accepts an organization
// invitation; "" when no absolute origin is known, in which case the admin
// conveys the token itself.
func (p webPaths) invitationURL(token string) string {
	if p.site() {
		return p.web + "/invitations/" + url.PathEscape(token)
	}
	if p.base == "" {
		return ""
	}
	return p.base + "/ui/invitations/" + url.PathEscape(token)
}

// accountSettingsURL is where the directory's flows return a browser after
// a password change or an authenticator enrolment.
func (p webPaths) accountSettingsURL() string {
	if p.site() {
		return p.web + "/settings/authentication"
	}
	return p.abs("/ui/account/directory")
}

// reportCardURL is where an author is sent to read a version's report card
// from a quarantine or review email (agentry#270). With a site it is the
// site's version page, which carries the full report. The server's own
// pages have no version page, so without a site the link is the API's
// report resource — JSON, but reachable, which a page that does not exist
// is not. "" when neither origin is configured.
func (p webPaths) reportCardURL(agent, version string) string {
	if p.site() {
		return p.web + "/" + agent + "/versions/" + url.PathEscape(version)
	}
	return p.abs("/api/v1/agents/" + agent + "/versions/" + url.PathEscape(version) + "/report")
}

// authorizeURL is the device-authorize page a CLI or the desktop app opens
// (DR-17, D-018). It is always the server's own page: the site links to it
// rather than serving one. "" when the public origin is not configured.
func (p webPaths) authorizeURL() string {
	return p.abs("/ui/authorize")
}

// orgConsoleURL is where an organization's admins manage it: the site's
// organization console, or the server's own page. "" when neither origin
// is configured, in which case a mail names the organization and no link.
func (p webPaths) orgConsoleURL(handle string) string {
	if p.site() {
		return p.web + "/orgs/" + url.PathEscape(handle) + "/admin"
	}
	return p.abs("/ui/orgs/" + url.PathEscape(handle))
}
