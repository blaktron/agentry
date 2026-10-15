package api

import (
	"net/http"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/audit"
	samlsp "github.com/blaktron/agentry/internal/auth/saml"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// GetSamlMetadata implements GET /orgs/{org}/sso/saml/metadata. Public:
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

// SamlAcs implements POST /orgs/{org}/sso/saml/acs: the Assertion
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
	if !s.ssoIncluded(r.Context(), orgRow.ID) {
		problemNotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		problemBadRequest(w, r, "The server could not parse the form body.")
		return
	}
	samlResponse := r.PostFormValue("SAMLResponse")
	if samlResponse == "" {
		problemValidation(w, r, "The POST must carry a SAMLResponse form field.")
		return
	}
	// RelayState is SAML's own way to carry where the browser was going,
	// and the IdP hands it back untouched — so it is the assertion's least
	// trustworthy field and passes through safeNextPath, which admits a
	// same-origin path and nothing else. Empty is API mode.
	next := safeNextPath(r.PostFormValue("RelayState"))
	browserFail := func(msg string) bool { return s.browserFail(w, r, next, msg) }
	sp, connID, err := s.samlSPForOrg(r, orgRow)
	if err != nil {
		const msg = "This organization has no SAML connection enabled."
		if browserFail(msg) {
			return
		}
		problemValidation(w, r, msg)
		return
	}
	res, err := sp.ParseAndValidate(r.Context(), samlResponse)
	if err != nil {
		s.log.WarnContext(r.Context(), "saml acs rejected", "org", org, "err", err)
		const msg = "The registry rejected the SAML assertion. Start sign-in again."
		if browserFail(msg) {
			return
		}
		problemUnauthorized(w, r, msg)
		return
	}
	// This path creates nobody, so the IdP's displayName is not used: an
	// existing member's name is their own to set.
	s.establishSSOSession(w, r, orgRow, connID, "saml", res.Subject, res.Email,
		&samlSessionLink{NameID: res.NameID, SessionIndex: res.SessionIndex}, next,
		res.MFAAsserted())
}

// SamlSloRedirect implements GET /orgs/{org}/sso/saml/slo: the HTTP-Redirect
// binding of the Single Logout endpoint.
func (s *Server) SamlSloRedirect(w http.ResponseWriter, r *http.Request, org OrgHandle) {
	s.samlSlo(w, r, org)
}

// SamlSloPost implements POST /orgs/{org}/sso/saml/slo: the HTTP-POST binding.
func (s *Server) SamlSloPost(w http.ResponseWriter, r *http.Request, org OrgHandle) {
	s.samlSlo(w, r, org)
}

// samlSlo handles both directions of Single Logout on either binding:
//
//   - an IdP-initiated LogoutRequest (signed; XML signature on POST, query
//     signature on Redirect) revokes every session this connection
//     established for the named NameID (and SessionIndex when given), is
//     audited, and is answered with a LogoutResponse to the IdP's SLO
//     endpoint when it publishes one;
//   - the IdP's LogoutResponse to an SP-initiated logout is validated and
//     the browser is sent home.
//
// Like the ACS, the route is NoAuthz: the IdP's signature is the credential.
func (s *Server) samlSlo(w http.ResponseWriter, r *http.Request, org OrgHandle) {
	if !s.requireDB(w, r) {
		return
	}
	orgRow, ok := s.orgOrNotFound(w, r, org)
	if !ok {
		return
	}
	sp, connID, err := s.samlSPForOrg(r, orgRow)
	if err != nil {
		problemValidation(w, r, "This organization has no SAML connection enabled.")
		return
	}
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			problemBadRequest(w, r, "The server could not parse the form body.")
			return
		}
	}
	relayState := r.FormValue("RelayState")

	// The IdP answering our own LogoutRequest.
	if r.FormValue("SAMLResponse") != "" {
		if err := sp.ValidateLogoutResponse(r.URL.RawQuery, r.PostFormValue("SAMLResponse")); err != nil {
			s.log.WarnContext(r.Context(), "saml slo response rejected", "org", org, "err", err)
			problemUnauthorized(w, r, "The registry rejected the SAML LogoutResponse.")
			return
		}
		http.Redirect(w, r, s.webHomeURL(r), http.StatusSeeOther)
		return
	}

	var info *samlsp.LogoutRequestInfo
	if r.Method == http.MethodPost {
		info, err = sp.ParseLogoutRequestPost(r.Context(), r.PostFormValue("SAMLRequest"))
	} else {
		info, err = sp.ParseLogoutRequestRedirect(r.Context(), r.URL.RawQuery)
	}
	if err != nil {
		s.log.WarnContext(r.Context(), "saml slo request rejected", "org", org, "err", err)
		problemUnauthorized(w, r, "The registry rejected the SAML LogoutRequest.")
		return
	}

	var idx *string
	if info.SessionIndex != "" {
		idx = &info.SessionIndex
	}
	cid := connID
	var revoked int64
	err = s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		n, err := q.RevokeSAMLSessions(r.Context(), storegen.RevokeSAMLSessionsParams{
			SsoConnectionID: &cid, SamlNameID: &info.NameID, SamlSessionIndex: idx,
		})
		if err != nil {
			return err
		}
		revoked = n
		e := auditEvent(r, audit.ActionUserLogout)
		e.ActorKind = audit.ActorSystem
		e.OrgID = orgRow.ID
		e.TargetKind = "session"
		e.Detail = map[string]any{"provider": "saml", "slo": "idp-initiated", "sessions": n, "sessionIndexScoped": idx != nil}
		return s.auditW.Write(r.Context(), q, e)
	})
	if err != nil {
		s.log.ErrorContext(r.Context(), "saml slo revoke", "err", err)
		problemInternal(w, r)
		return
	}
	s.log.InfoContext(r.Context(), "saml slo: sessions revoked", "org", org, "sessions", revoked)
	// Clear this browser's cookie too: the request may arrive front-channel
	// through the user's own browser.
	clearCookie(w, sessionCookieName, s.cfg.Auth.CookieSecure)
	if u, ok := sp.LogoutResponseURL(info.ID, relayState); ok {
		http.Redirect(w, r, u, http.StatusSeeOther)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("Signed out.\n"))
}

// webHomeURL is where a completed SP-initiated logout lands: the site's
// home when one fronts this server, else the server's own /ui/ page,
// on the public origin or, failing that, this request's host.
func (s *Server) webHomeURL(r *http.Request) string {
	if u := s.paths.homeURL(); u != "" {
		return u
	}
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	return scheme + "://" + r.Host + "/ui/"
}

// samlLogoutURLForSession returns the IdP logout redirect for a session
// established through a SAML connection whose IdP publishes an SLO
// endpoint; "" otherwise (SP-initiated SLO).
func (s *Server) samlLogoutURLForSession(r *http.Request, sessionID uuid.UUID) string {
	sess, err := s.q().GetSessionByID(r.Context(), sessionID)
	if err != nil || sess.SsoConnectionID == nil || sess.SamlNameID == nil || *sess.SamlNameID == "" {
		return ""
	}
	conn, err := s.q().GetSSOConnectionWithOrg(r.Context(), *sess.SsoConnectionID)
	if err != nil || conn.Kind != "saml" {
		return ""
	}
	sp, err := s.samlSPFromConfig(r, conn.OrgHandle, conn.Config)
	if err != nil || !sp.IDPSupportsSLO() {
		return ""
	}
	u, err := sp.LogoutRequestURL(*sess.SamlNameID, "")
	if err != nil {
		return ""
	}
	return u
}
