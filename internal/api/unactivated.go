package api

import (
	"net/http"
	"strings"

	"github.com/blaktron/agentry/internal/auth"
)

// An unactivated account is signed in and may read everything a
// signed-in account may, but it changes
// nothing until it follows the activation link the registry mailed it: an
// account whose sign-in provider did not vouch for its address reaches the
// registry before the address is confirmed, and an address nobody confirmed
// must not own anything.
//
// unactivatedWrites is what it may still do: sign itself in and out,
// ask for another activation mail and follow one, set its display name and
// cookie choice, delete or clear itself, end its sessions and remove its
// remembered browsers, authenticators, tokens and SSH keys, sign the
// desktop app or the CLI in (the grant mints a token, and the token is
// read-only too), and accept an invitation (which confirms an address at
// the organization's domain). A removal is housekeeping, not a write the
// gate refuses: minting a token is.
// Patterns are "METHOD /path" under /api/v1, a {} segment matching one
// path segment; a trailing /* matches the rest.
var unactivatedWrites = []string{
	"POST /auth/verify-email",
	"POST /auth/logout",
	"POST /auth/desktop/exchange",
	"POST /user/email-verification",
	"PATCH /user",
	"POST /user/delete",
	"POST /user/clear-data",
	"DELETE /user/sessions",
	"DELETE /user/sessions/{}",
	"DELETE /user/trusted-devices",
	"DELETE /user/tokens/{}",
	"DELETE /user/ssh-keys/{}",
	"POST /user/tokens/desktop-grant",
	"POST /invitations/{}",
	"POST /orgs/{}/sso/saml/acs",
	"POST /orgs/{}/sso/saml/slo",
}

const apiPrefix = "/api/v1"

// unactivatedMayWrite reports whether an unactivated account may make this
// request. Reads always may; a write may only when it is on the list.
func unactivatedMayWrite(method, path string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	rest, ok := strings.CutPrefix(path, apiPrefix)
	if !ok {
		return false
	}
	for _, pat := range unactivatedWrites {
		m, p, _ := strings.Cut(pat, " ")
		if m == method && pathMatches(p, rest) {
			return true
		}
	}
	return false
}

func pathMatches(pattern, path string) bool {
	if prefix, ok := strings.CutSuffix(pattern, "/*"); ok {
		return strings.HasPrefix(path, prefix+"/")
	}
	ps, xs := strings.Split(pattern, "/"), strings.Split(strings.TrimSuffix(path, "/"), "/")
	if len(ps) != len(xs) {
		return false
	}
	for i := range ps {
		if ps[i] == "{}" {
			if xs[i] == "" {
				return false
			}
			continue
		}
		if ps[i] != xs[i] {
			return false
		}
	}
	return true
}

// refuseUnactivated answers an unactivated account's write that is not on
// the list, and reports whether it did.
func refuseUnactivated(w http.ResponseWriter, r *http.Request, p *auth.Principal) bool {
	if p.Anonymous || !p.Unactivated || unactivatedMayWrite(r.Method, r.URL.Path) {
		return false
	}
	writeProblem(w, r, http.StatusForbidden, "account-unactivated", "Account not activated",
		"Activate your account first: follow the link we emailed you, or send a new one from your account.")
	return true
}
