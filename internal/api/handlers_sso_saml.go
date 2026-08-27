package api

import (
	"net/http"
)

// GetSamlMetadata implements GET /orgs/{org}/sso/saml/metadata (§12.4). Public:
// IdP administrators fetch it to configure the connection.
func (s *Server) GetSamlMetadata(w http.ResponseWriter, r *http.Request, org OrgHandle) {
	if !s.requireDB(w, r) {
		return
	}
	orgRow, ok := s.orgOrNotFound(w, r, org)
	if !ok {
		return
	}
	sp, _, err := s.samlSPForOrg(r, orgRow)
	if err != nil {
		problemNotFound(w, r)
		return
	}
	xml, err := sp.SPMetadataXML()
	if err != nil {
		problemInternal(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(xml)
}

// SamlAcs implements POST /orgs/{org}/sso/saml/acs (§12.4): the Assertion
// Consumer Service. It requires a signed assertion and validates
// audience/recipient/timestamps/replay inside the SP before establishing an
// SSO session via JIT. No credential is presented by the IdP POST itself, so
// the route is NoAuthz (credential-establishing, like login).
func (s *Server) SamlAcs(w http.ResponseWriter, r *http.Request, org OrgHandle) {
	if !s.requireDB(w, r) {
		return
	}
	orgRow, ok := s.orgOrNotFound(w, r, org)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		problemBadRequest(w, r, "invalid form body")
		return
	}
	samlResponse := r.PostFormValue("SAMLResponse")
	if samlResponse == "" {
		problemValidation(w, r, "SAMLResponse is required")
		return
	}
	sp, connID, err := s.samlSPForOrg(r, orgRow)
	if err != nil {
		problemValidation(w, r, "SAML is not configured for this organization")
		return
	}
	res, err := sp.ParseAndValidate(r.Context(), samlResponse)
	if err != nil {
		s.log.Warn("saml acs rejected", "org", org, "err", err)
		problemUnauthorized(w, r, "SAML assertion rejected")
		return
	}
	displayName := ""
	if v := res.Attributes["displayName"]; len(v) > 0 {
		displayName = v[0]
	}
	s.establishSSOSession(w, r, orgRow, connID, "saml", res.Subject, res.Email, displayName)
}
