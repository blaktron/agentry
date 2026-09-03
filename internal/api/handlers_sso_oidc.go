package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/blaktron/agentry/internal/auth"
)

const oidcStateCookie = "agentry_oidc_state"

// oidcState is sealed into a short-lived cookie between start and callback.
type oidcState struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Org      string `json:"o"`
}

// oidcContext wraps the request context with the configured OIDC HTTP client
// (tests point discovery/JWKS/token at an in-process IdP).
func (s *Server) oidcContext(ctx context.Context) context.Context {
	if s.oidcHTTPClient != nil {
		return coreoidc.ClientContext(ctx, s.oidcHTTPClient)
	}
	return ctx
}

// OidcStart implements GET /orgs/{org}/sso/oidc/start (§12.4): auth-code + PKCE.
func (s *Server) OidcStart(w http.ResponseWriter, r *http.Request, org OrgHandle) {
	if !s.requireDB(w, r) {
		return
	}
	orgRow, ok := s.orgOrNotFound(w, r, org)
	if !ok {
		return
	}
	ctx := s.oidcContext(r.Context())
	rp, _, err := s.oidcRPForOrg(ctx, r, orgRow)
	if err != nil {
		problemValidation(w, r, "OIDC is not configured for this organization")
		return
	}
	state, _ := auth.NewToken("")
	nonce, _ := auth.NewToken("")
	verifier := oauth2.GenerateVerifier()

	blob, err := json.Marshal(oidcState{State: state, Nonce: nonce, Verifier: verifier, Org: orgRow.Handle})
	if err != nil {
		problemInternal(w, r)
		return
	}
	sealed, err := s.sealer.Seal(blob)
	if err != nil {
		problemInternal(w, r)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: oidcStateCookie, Value: base64.RawURLEncoding.EncodeToString(sealed),
		Path: "/", HttpOnly: true, Secure: s.cfg.Auth.CookieSecure,
		SameSite: http.SameSiteLaxMode, MaxAge: 600,
	})
	http.Redirect(w, r, rp.AuthURL(state, nonce, verifier), http.StatusFound)
}

// OidcCallback implements GET /orgs/{org}/sso/oidc/callback (§12.4): exchange
// the code, verify the ID token (signature/issuer/audience/nonce), respect
// email_verified, and establish the SSO session via JIT.
func (s *Server) OidcCallback(w http.ResponseWriter, r *http.Request, org OrgHandle, params OidcCallbackParams) {
	if !s.requireDB(w, r) {
		return
	}
	orgRow, ok := s.orgOrNotFound(w, r, org)
	if !ok {
		return
	}
	c, err := r.Cookie(oidcStateCookie)
	if err != nil || c.Value == "" {
		problemValidation(w, r, "missing OIDC state cookie")
		return
	}
	sealed, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		problemValidation(w, r, "invalid OIDC state")
		return
	}
	blob, err := s.sealer.Open(sealed)
	if err != nil {
		problemUnauthorized(w, r, "invalid OIDC state")
		return
	}
	var st oidcState
	if err := json.Unmarshal(blob, &st); err != nil {
		problemUnauthorized(w, r, "invalid OIDC state")
		return
	}
	// Clear the state cookie regardless of outcome (single use).
	http.SetCookie(w, &http.Cookie{Name: oidcStateCookie, Value: "", Path: "/", MaxAge: -1})

	if params.State == nil || *params.State != st.State || st.Org != orgRow.Handle {
		problemUnauthorized(w, r, "OIDC state mismatch")
		return
	}
	if params.Code == nil || *params.Code == "" {
		problemValidation(w, r, "missing authorization code")
		return
	}

	ctx := s.oidcContext(r.Context())
	rp, connID, err := s.oidcRPForOrg(ctx, r, orgRow)
	if err != nil {
		problemValidation(w, r, "OIDC is not configured for this organization")
		return
	}
	claims, err := rp.Exchange(ctx, *params.Code, st.Verifier, st.Nonce)
	if err != nil {
		s.log.Warn("oidc callback rejected", "org", org, "err", err)
		problemUnauthorized(w, r, "OIDC login failed")
		return
	}
	// Respect email_verified (§12.4): an unverified email must not drive a
	// verified-email JIT link.
	if claims.Email != "" && !claims.EmailVerified {
		problemUnauthorized(w, r, "IdP has not verified this email address")
		return
	}
	s.establishSSOSession(w, r, orgRow, connID, "oidc", claims.Subject, claims.Email, "", nil)
}
