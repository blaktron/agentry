package api

// reservedHandles are the names no user or organization may take because
// they are root paths of this server or of the site that fronts it: a
// handle is the first segment of `/<ns>/<name>` pages, and `ui` is the
// server's own surface (DEV-091). The list is the union of both surfaces so
// a handle stays valid whichever fronts a deployment.
var reservedHandles = map[string]bool{
	"ui": true, "api": true, "auth": true, "sso": true, "scim": true, "healthz": true, "readyz": true, "metrics": true,
	"login": true, "logout": true, "signup": true, "settings": true, "dashboard": true, "search": true, "build": true,
	"new": true, "review": true, "staff": true, "orgs": true, "tags": true, "trust": true, "advisories": true,
	"download": true, "downloads": true, "docs": true, "about": true, "contact": true, "privacy": true, "terms": true,
	"cookies": true, "agent-template": true, "admin": true, "static": true, "img": true,
}

func handleReserved(h string) bool { return reservedHandles[h] }

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
