package api

import "github.com/blaktron/agentry/pkg/handle"

// pathHandles and firstPartyHandles are the handle package's reserved
// names (pkg/handle): the root paths nobody may take, and the product's own
// names only platform staff may give an organization.
var (
	pathHandles       = handleSet(handle.PathNames())
	firstPartyHandles = handleSet(handle.FirstPartyNames())
)

func handleSet(names []string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
}

// firstPartyOrg reports whether an organization handle is one of the
// product's own: the platform-internal security_reviewer role exists only
// there; everywhere else
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
// than chosen (a first sign-in through an IdP), where refusing is not an
// option.
func unreservedHandle(h string) string {
	if !handleReserved(h) {
		return h
	}
	if len(h) > 36 {
		h = h[:36]
	}
	return h + "-1"
}
