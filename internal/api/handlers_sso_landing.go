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
	"strings"

	samlsp "github.com/blaktron/agentry/internal/auth/saml"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// samlRequests holds the AuthnRequest ids this process has issued, so the ACS
// can match an assertion's InResponseTo to a login we actually started.
//
// It is process-wide rather than a field on Server for the same reason
// saml.MaxClockSkew is a package-level setting in the crewjam library: the
// contents are unguessable opaque ids with a 15-minute TTL, so sharing the
// set between Server instances in one process leaks nothing (accepting an id
// still requires a validly signed assertion for that server's own ACS URL and
// audience). SaaS replaces it with the Redis-backed implementation behind
// samlsp.RequestTracker, exactly as it does the replay cache.
var samlRequests samlsp.RequestTracker = samlsp.NewMemoryRequestTracker()

// mountSSOLanding registers the root-level SSO landing route.
func (s *Server) mountSSOLanding(mux *http.ServeMux) {
	mux.HandleFunc("GET /sso/{org}", s.ssoLanding)
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

	// SAML first when both are configured: an org that has stood up a SAML
	// connection has told its IdP about this SP, and that is the path its
	// people are provisioned for.
	if _, err := s.q().GetEnabledSSOConnection(r.Context(), storegen.GetEnabledSSOConnectionParams{
		OrgID: orgRow.ID, Kind: "saml",
	}); err == nil {
		sp, _, err := s.samlSPForOrg(r, orgRow)
		if err != nil {
			s.log.Warn("sso landing: saml sp", "org", org, "err", err)
			problemValidation(w, r, "This organization's SAML connection is not usable. Ask an owner to check it.")
			return
		}
		redirect, err := sp.AuthnRequest(orgRow.Handle)
		if err != nil {
			s.log.Warn("sso landing: authn request", "org", org, "err", err)
			problemValidation(w, r, "The registry could not start SAML login for this organization. Ask an owner to check the connection.")
			return
		}
		http.Redirect(w, r, redirect, http.StatusFound)
		return
	}

	if _, err := s.q().GetEnabledSSOConnection(r.Context(), storegen.GetEnabledSSOConnectionParams{
		OrgID: orgRow.ID, Kind: "oidc",
	}); err == nil {
		http.Redirect(w, r, "/api/v1/orgs/"+orgRow.Handle+"/sso/oidc/start", http.StatusFound)
		return
	}

	// No enabled connection: 404 rather than a hint, so the landing URL
	// cannot be used to enumerate which orgs have SSO configured beyond what
	// the org profile already reveals.
	problemNotFound(w, r)
}
