package api

// pathHandles are the names no user or organization may take because they
// are root paths of this server or of the site that fronts it: a handle is
// the first segment of `/<ns>/<name>` pages, and `ui` is the server's own
// surface (DEV-091). The list is the union of both surfaces so a handle
// stays valid whichever fronts a deployment. Nobody can create these, staff
// included: an org named `ui` would shadow the server's own pages.
var pathHandles = map[string]bool{
	"ui": true, "api": true, "auth": true, "sso": true, "scim": true, "healthz": true, "readyz": true, "metrics": true,
	"login": true, "logout": true, "signup": true, "settings": true, "dashboard": true, "search": true, "build": true,
	"new": true, "review": true, "staff": true, "orgs": true, "tags": true, "trust": true, "advisories": true,
	"download": true, "downloads": true, "docs": true, "about": true, "contact": true, "privacy": true, "terms": true,
	"cookies": true, "agent-template": true, "admin": true, "static": true, "img": true,
	// The site's runs, invitations and pricing pages (plan web-dashboard-shell
	// §4, agentry#448): served before they were reserved.
	"runs": true, "invitations": true, "pricing": true,
	// The site's About us page (agentry#1083, plan web-landing-page.md M0), its
	// account-deleted page (agentry-web#297), its Scheduled pages
	// (agentry-web#1346) and its OAuth client metadata documents
	// (agentry-web#1331), the last three agentry#506: each served before it
	// was reserved, none held by any account on dev or production when added.
	"aboutus": true, "account-deleted": true, "scheduled": true, "oauth": true,
	// The site's Report bug page (agentry-web#1576, plan report-bug.md §5),
	// agentry#1124: reserved before it shipped to production, held by no
	// account on dev or production when added.
	"report-bug": true,
}

// firstPartyHandles are the product's own names, reserved so that nobody
// on a public registry can pass their content off as first-party. Unlike
// pathHandles they are meant to exist: platform staff may create an
// organization with one of them — the `agentry` org that publishes the
// example QuickAgents (agentry#285, DEV-098).
var firstPartyHandles = map[string]bool{
	"agentry": true, "secureagentry": true,
}

// firstPartyOrg reports whether an organization handle is one of the
// product's own: the platform-internal security_reviewer role exists only
// there (plan organization-subscriptions D20, agentry#360); everywhere else
// the admins hold its powers.
func firstPartyOrg(h string) bool { return firstPartyHandles[h] }

// handleReserved reports whether no sign-up may take h: a root path or a
// first-party name. Sign-up has no staff.
func handleReserved(h string) bool { return orgHandleReserved(h, false) }

// orgHandleReserved reports whether the caller may not create an org named
// h: a root path is refused for everyone, a first-party name for everyone
// but platform staff.
func orgHandleReserved(h string, staff bool) bool {
	if pathHandles[h] {
		return true
	}
	return firstPartyHandles[h] && !staff
}

// unreservedHandle returns h, or h with a numeric suffix when h is
// reserved — for handles derived from an email or an IdP claim rather
// than chosen (SSO and social sign-up), where refusing is not an option.
func unreservedHandle(h string) string {
	if !handleReserved(h) {
		return h
	}
	if len(h) > 36 {
		h = h[:36]
	}
	return h + "-1"
}
