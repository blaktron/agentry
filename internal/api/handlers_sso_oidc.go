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
	// Next is the same-origin path a browser returns to, sealed here
	// rather than carried in the query so the IdP round trip cannot
	// change it (plan organization-subscriptions.md §5.7). Empty is API
	// mode, which answers JSON as before.
	Next string `json:"x,omitempty"`
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
func (s *Server) OidcStart(w http.ResponseWriter, r *http.Request, org OrgHandle, params OidcStartParams) {
	if !s.requireDB(w, r) {
		return
	}
	orgRow, ok := s.orgOrNotFound(w, r, org)
	if !ok {
		return
	}
	// A tier that does not include SSO has no door here, and the
	// organization is not a thing this route will admit to having one: the
	// answer is the same 404 as an organization with no connection at all
	// (D11).
	if !s.ssoIncluded(r.Context(), orgRow.ID) {
		problemNotFound(w, r)
		return
	}
	ctx := s.oidcContext(r.Context())
	rp, _, err := s.oidcRPForOrg(ctx, r, orgRow)
	if err != nil {
		problemValidation(w, r, "This organization has no OIDC connection enabled.")
		return
	}
	state, _ := auth.NewToken("")
	nonce, _ := auth.NewToken("")
	verifier := oauth2.GenerateVerifier()

	next := ""
	if params.Next != nil {
		next = safeNextPath(*params.Next)
	}
	blob, err := json.Marshal(oidcState{
		State: state, Nonce: nonce, Verifier: verifier, Org: orgRow.Handle, Next: next,
	})
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
	if !s.ssoIncluded(r.Context(), orgRow.ID) {
		problemNotFound(w, r)
		return
	}
	c, err := r.Cookie(oidcStateCookie)
	if err != nil || c.Value == "" {
		problemValidation(w, r, "The OIDC state cookie is missing. Start sign-in again.")
		return
	}
	sealed, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		problemValidation(w, r, "The OIDC state cookie could not be read. Start sign-in again.")
		return
	}
	blob, err := s.sealer.Open(sealed)
	if err != nil {
		problemUnauthorized(w, r, "The OIDC state cookie could not be read. Start sign-in again.")
		return
	}
	var st oidcState
	if err := json.Unmarshal(blob, &st); err != nil {
		problemUnauthorized(w, r, "The OIDC state cookie could not be read. Start sign-in again.")
		return
	}
	// Clear the state cookie regardless of outcome (single use).
	http.SetCookie(w, &http.Cookie{Name: oidcStateCookie, Value: "", Path: "/", MaxAge: -1})

	// From here the sealed state is open, so browser mode is known and a
	// failure can land on the login page rather than on a problem document
	// the person cannot read. next was validated by safeNextPath before it
	// was sealed.
	browserFail := func(msg string) bool { return s.browserFail(w, r, st.Next, msg) }
	if params.State == nil || *params.State != st.State || st.Org != orgRow.Handle {
		const msg = "The OIDC state does not match this sign-in. Start again."
		if browserFail(msg) {
			return
		}
		problemUnauthorized(w, r, msg)
		return
	}
	if params.Code == nil || *params.Code == "" {
		const msg = "The IdP returned no authorization code. Start sign-in again."
		if browserFail(msg) {
			return
		}
		problemValidation(w, r, msg)
		return
	}

	ctx := s.oidcContext(r.Context())
	rp, connID, err := s.oidcRPForOrg(ctx, r, orgRow)
	if err != nil {
		const msg = "This organization has no OIDC connection enabled."
		if browserFail(msg) {
			return
		}
		problemValidation(w, r, msg)
		return
	}
	claims, err := rp.Exchange(ctx, *params.Code, st.Verifier, st.Nonce)
	if err != nil {
		s.log.WarnContext(r.Context(), "oidc callback rejected", "org", org, "err", err)
		const msg = "The code exchange with the identity provider failed. Start sign-in again."
		if browserFail(msg) {
			return
		}
		problemUnauthorized(w, r, msg)
		return
	}
	// Respect email_verified (§12.4): an unverified email must not drive a
	// verified-email JIT link.
	if claims.Email != "" && !claims.EmailVerified {
		const msg = "The identity provider reports this email address as unverified. Verify it there, then sign in again."
		if browserFail(msg) {
			return
		}
		problemUnauthorized(w, r, msg)
		return
	}
	s.establishSSOSession(w, r, orgRow, connID, "oidc", claims.Subject, claims.Email, nil, st.Next)
}
