// Package handle is the grammar of an Agentry handle, the name of a person
// or an organization: the first segment of every /<namespace>/<name>
// path, and the namespace of every QuickAgent. A directory that lets
// people choose a username the registry will seed their handle from holds
// its own copy of these rules, and tests its copy against this package.
package handle

import (
	"regexp"
	"slices"
)

// Grammar is a handle's form: one to thirty-nine lower-case ASCII letters,
// digits and hyphens, starting and ending with a letter or a digit.
const Grammar = `^[a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?$`

var grammar = regexp.MustCompile(Grammar)

// Valid reports whether h has a handle's form. A valid handle may still be
// reserved.
func Valid(h string) bool { return grammar.MatchString(h) }

// pathNames are the names no person or organization may take because they
// are root paths of the server or of a site in front of it: a handle is
// the first segment of /<namespace>/<name> pages, and `ui` is the server's
// own surface. Both surfaces are in the list, so a handle stays valid
// whichever fronts a deployment.
var pathNames = []string{
	"about", "aboutus", "account-deleted", "admin", "advisories", "agent-template", "api", "auth", "build",
	"contact", "cookies", "dashboard", "docs", "download", "downloads", "healthz", "img", "invitations",
	"login", "logout", "metrics", "new", "oauth", "orgs", "pricing", "privacy", "readyz", "report-bug",
	"review", "runs", "scheduled", "scim", "search", "settings", "signup", "sso", "staff", "static",
	"tags", "terms", "trust", "ui",
}

// firstPartyNames are the product's own names, reserved so that nobody on a
// public registry can pass their content off as first-party. Unlike the
// path names they are meant to exist: platform staff may create an
// organization with one of them.
var firstPartyNames = []string{"agentry", "secureagentry"}

// IsPath reports whether h is one of the root paths no account or
// organization may ever take, platform staff included.
func IsPath(h string) bool { return slices.Contains(pathNames, h) }

// IsFirstParty reports whether h is one of the product's own names, which
// only platform staff may give an organization.
func IsFirstParty(h string) bool { return slices.Contains(firstPartyNames, h) }

// Reserved reports whether no sign-up may take h: a root path or a
// first-party name.
func Reserved(h string) bool { return IsPath(h) || IsFirstParty(h) }

// PathNames lists the root-path names, sorted.
func PathNames() []string { return slices.Clone(pathNames) }

// FirstPartyNames lists the first-party names, sorted.
func FirstPartyNames() []string { return slices.Clone(firstPartyNames) }
