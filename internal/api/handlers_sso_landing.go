package api

// The org SSO landing page, `https://…/sso/{org}` (§12.4 endpoint list), and
// the SP-initiated SAML flow behind it.
//
// Until now the SAML SP only ever CONSUMED assertions: an employee had to
// start at their IdP's app portal, because agentry never generated an
// AuthnRequest. The landing endpoint is the "sign in with your company
// account" entry point — it picks whichever method the org has enabled and
// hands the browser to the IdP.
//
// It is mounted at the root, outside /api/v1 and outside the OpenAPI surface,
// because it is a browser destination people paste into an address bar and
// paste into IdP admin consoles — the same reason /scim/v2 is mounted there.

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/blaktron/agentry/internal/httpmux"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// mountSSOLanding registers the root-level SSO landing route.
func (s *Server) mountSSOLanding(mux httpmux.Mux) {
	MountFunc(mux, "GET /sso/{org}", s.ssoLanding)
}

// ssoLanding implements GET /sso/{org}: start the org's configured SSO.
func (s *Server) ssoLanding(w http.ResponseWriter, r *http.Request) {
	if !s.allowLogin(w, r) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	org := strings.ToLower(strings.TrimSpace(r.PathValue("org")))
	if !reHandle.MatchString(org) {
		problemNotFound(w, r)
		return
	}
	orgRow, ok := s.orgOrNotFound(w, r, org)
	if !ok {
		return
	}
	// A tier that does not include SSO has no door here either, and this
	// is the door people paste into an address bar — leaving it open would
	// hand the browser to an IdP for a sign-in the ACS then refuses
	// (agentry#365, D11).
	if !s.ssoIncluded(r.Context(), orgRow.ID) {
		problemNotFound(w, r)
		return
	}
	// Where the browser was going before it was asked to sign in. This is
	// the entry point the product links to, so it is the one place that
	// can put the round trip in browser mode at all: SAML carries it in
	// RelayState, OIDC in the start's `next`, and both are read back
	// through safeNextPath at the other end. Empty means API mode, which
	// is what an IdP-initiated sign-in gets.
	next := safeNextPath(r.URL.Query().Get("next"))

	// SAML first when both are configured: an org that has stood up a SAML
	// connection has told its IdP about this SP, and that is the path its
	// people are provisioned for.
	if _, err := s.q().GetEnabledSSOConnection(r.Context(), storegen.GetEnabledSSOConnectionParams{
		OrgID: orgRow.ID, Kind: "saml",
	}); err == nil {
		sp, _, err := s.samlSPForOrg(r, orgRow)
		if err != nil {
			s.log.WarnContext(r.Context(), "sso landing: saml sp", "org", org, "err", err)
			problemValidation(w, r, "This organization's SAML connection is not usable. Ask an admin to check it.")
			return
		}
		// RelayState carried the org handle, which the ACS never read: it
		// takes the organization from its own path. A same-origin path
		// goes there instead when there is one, and the handle stays the
		// default so an IdP-initiated sign-in looks exactly as it did.
		relay := orgRow.Handle
		if next != "" {
			relay = next
		}
		redirect, err := sp.AuthnRequest(r.Context(), relay)
		if err != nil {
			s.log.WarnContext(r.Context(), "sso landing: authn request", "org", org, "err", err)
			problemValidation(w, r, "The registry could not start SAML login for this organization. Ask an admin to check the connection.")
			return
		}
		http.Redirect(w, r, redirect, http.StatusFound)
		return
	}

	if _, err := s.q().GetEnabledSSOConnection(r.Context(), storegen.GetEnabledSSOConnectionParams{
		OrgID: orgRow.ID, Kind: "oidc",
	}); err == nil {
		start := "/api/v1/orgs/" + orgRow.Handle + "/sso/oidc/start"
		if next != "" {
			start += "?next=" + url.QueryEscape(next)
		}
		http.Redirect(w, r, start, http.StatusFound)
		return
	}

	// No enabled connection: 404 rather than a hint, so the landing URL
	// cannot be used to enumerate which orgs have SSO configured beyond what
	// the org profile already reveals.
	problemNotFound(w, r)
}
