package api

// Social login for individual accounts (§12.1, §9.2
// GET /auth/oidc/{provider}/{start,callback}).
//
// The identity rules are the T-12 account-takeover guard, restated for a
// server-wide provider rather than a per-org one (§12.4's JIT paragraph):
//
//  1. An identities row for this provider+subject wins outright — the link
//     was made deliberately once and is not re-litigated.
//  2. Otherwise, if the provider asserts a VERIFIED email that matches an
//     existing account whose OWN email is verified, link them. Both halves
//     matter: an unverified provider email proves nothing, and an account
//     that never verified its own address is not evidence of ownership
//     either.
//  3. Otherwise, if an account with that email exists, refuse with 409 and
//     make the user link explicitly while signed in.
//  4. Otherwise JIT-create an individual account.
//
// The session issued is an ordinary password-login session: no org
// membership, no SSO freshness tag, and 2FA still applies — an account that
// enabled TOTP does not lose it by signing in with Google.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"golang.org/x/oauth2"

	"github.com/PLACEHOLDER_ORG/agentry/internal/audit"
	"github.com/PLACEHOLDER_ORG/agentry/internal/auth"
	"github.com/PLACEHOLDER_ORG/agentry/internal/auth/social"
	"github.com/PLACEHOLDER_ORG/agentry/internal/config"
	storegen "github.com/PLACEHOLDER_ORG/agentry/internal/store/gen"
)

const (
	socialStateCookie = "agentry_social_state"
	// totpChallengeTTL bounds the second leg of a 2FA social login.
	totpChallengeTTL = 5 * time.Minute
)

// socialState is sealed into a short-lived cookie between start and callback.
type socialState struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Provider string `json:"p"`
}

// totpChallengeBlob is the sealed payload behind a pending 2FA challenge. It
// names the user and expires; possessing it is not authentication, which is
// why the code is still required.
type totpChallengeBlob struct {
	UserID    uuid.UUID `json:"u"`
	ExpiresAt time.Time `json:"e"`
	Provider  string    `json:"p"`
}

// socialProviderConfig returns the configured provider settings, or false.
func (s *Server) socialProviderConfig(name string) (config.SocialProvider, bool) {
	switch name {
	case social.ProviderGoogle:
		return s.cfg.Social.Google, s.cfg.Social.Google.Configured()
	case social.ProviderGitHub:
		return s.cfg.Social.GitHub, s.cfg.Social.GitHub.Configured()
	default:
		return config.SocialProvider{}, false
	}
}

// socialRedirectURL is the provider's registered redirect URI for this server.
func (s *Server) socialRedirectURL(r *http.Request, provider string) string {
	base := strings.TrimRight(s.cfg.BaseURL, "/")
	if base == "" {
		scheme := "https"
		if r.TLS == nil {
			scheme = "http"
		}
		base = scheme + "://" + r.Host
	}
	return base + "/api/v1/auth/oidc/" + provider + "/callback"
}

// socialProvider builds the provider client for one request.
func (s *Server) socialProvider(r *http.Request, name string) (social.Provider, error) {
	pc, ok := s.socialProviderConfig(name)
	if !ok {
		return nil, errors.New("provider not configured")
	}
	return social.New(r.Context(), name, social.Config{
		ClientID: pc.ClientID, ClientSecret: pc.ClientSecret,
		Issuer: pc.Issuer, AuthURL: pc.AuthURL, TokenURL: pc.TokenURL,
		APIBaseURL: pc.APIBaseURL, HTTPClient: s.oidcHTTPClient,
	}, s.socialRedirectURL(r, name))
}

// SocialOidcStart implements GET /auth/oidc/{provider}/start.
func (s *Server) SocialOidcStart(w http.ResponseWriter, r *http.Request, provider SocialOidcStartParamsProvider) {
	if !s.limits.allow("login", clientIP(r), s.classes.login, s.classes.loginBurst) {
		problemTooMany(w, r, "try again later")
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	name := string(provider)
	rp, err := s.socialProvider(r, name)
	if err != nil {
		// An unconfigured provider is genuinely absent from this deployment;
		// 404 rather than 422 so probing cannot distinguish "misconfigured"
		// from "not offered".
		problemNotFound(w, r)
		return
	}
	state, err := auth.NewToken("")
	if err != nil {
		problemInternal(w, r)
		return
	}
	nonce, err := auth.NewToken("")
	if err != nil {
		problemInternal(w, r)
		return
	}
	verifier := oauth2.GenerateVerifier()
	blob, err := json.Marshal(socialState{State: state, Nonce: nonce, Verifier: verifier, Provider: name})
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
		Name: socialStateCookie, Value: base64.RawURLEncoding.EncodeToString(sealed),
		Path: "/", HttpOnly: true, Secure: s.cfg.Auth.CookieSecure,
		SameSite: http.SameSiteLaxMode, MaxAge: 600,
	})
	http.Redirect(w, r, rp.AuthURL(state, nonce, verifier), http.StatusFound)
}

// SocialOidcCallback implements GET /auth/oidc/{provider}/callback.
func (s *Server) SocialOidcCallback(w http.ResponseWriter, r *http.Request, provider SocialOidcCallbackParamsProvider, params SocialOidcCallbackParams) {
	if !s.limits.allow("login", clientIP(r), s.classes.login, s.classes.loginBurst) {
		problemTooMany(w, r, "try again later")
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	name := string(provider)
	st, ok := s.readSocialState(w, r, name)
	if !ok {
		return
	}
	if params.State == nil || *params.State != st.State {
		problemUnauthorized(w, r, "login state mismatch")
		return
	}
	if params.Code == nil || *params.Code == "" {
		problemValidation(w, r, "missing authorization code")
		return
	}
	rp, err := s.socialProvider(r, name)
	if err != nil {
		problemNotFound(w, r)
		return
	}
	id, err := rp.Exchange(r.Context(), *params.Code, st.Verifier, st.Nonce)
	if err != nil {
		s.log.Warn("social login rejected", "provider", name, "err", err)
		problemUnauthorized(w, r, "social login failed")
		return
	}

	userID, err := s.resolveSocialUser(r, id)
	if err != nil {
		if errors.Is(err, errExplicitLinkRequired) {
			writeProblem(w, r, http.StatusConflict, "sso-link-required",
				"Account linking requires confirmation",
				"an account already uses this email address; sign in and link "+name+" from your account settings")
			return
		}
		s.log.Error("social jit", "provider", name, "err", err)
		problemInternal(w, r)
		return
	}

	user, err := s.q().GetUserByID(r.Context(), userID)
	if err != nil {
		problemInternal(w, r)
		return
	}
	if user.State != "active" {
		problemUnauthorized(w, r, "this account is not active")
		return
	}

	// 2FA still applies (§12.1): social login is an authentication method,
	// not an exemption. A redirect callback has nowhere to carry a code, so
	// the session is withheld behind a sealed challenge the client completes
	// at POST /auth/2fa/totp/challenge.
	if user.TotpEnabled {
		challenge, cerr := s.sealTOTPChallenge(userID, name)
		if cerr != nil {
			problemInternal(w, r)
			return
		}
		required := true
		writeJSON(w, http.StatusOK, SocialLoginResult{TotpRequired: required, Challenge: &challenge})
		return
	}

	s.issueSocialSession(w, r, user, name)
}

// readSocialState opens and clears the single-use state cookie.
func (s *Server) readSocialState(w http.ResponseWriter, r *http.Request, provider string) (socialState, bool) {
	c, err := r.Cookie(socialStateCookie)
	if err != nil || c.Value == "" {
		problemValidation(w, r, "missing login state cookie")
		return socialState{}, false
	}
	// Single use regardless of outcome.
	http.SetCookie(w, &http.Cookie{Name: socialStateCookie, Value: "", Path: "/", MaxAge: -1})
	sealed, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		problemValidation(w, r, "invalid login state")
		return socialState{}, false
	}
	blob, err := s.sealer.Open(sealed)
	if err != nil {
		problemUnauthorized(w, r, "invalid login state")
		return socialState{}, false
	}
	var st socialState
	if err := json.Unmarshal(blob, &st); err != nil || st.Provider != provider {
		problemUnauthorized(w, r, "invalid login state")
		return socialState{}, false
	}
	return st, true
}

// resolveSocialUser applies the §12.1/T-12 linking rules and returns the user.
func (s *Server) resolveSocialUser(r *http.Request, id *social.Identity) (uuid.UUID, error) {
	ctx := r.Context()
	q := s.q()

	// 1. Known identity.
	if row, err := q.GetSocialIdentity(ctx, id.NamespacedSubject); err == nil {
		return row.UserID, nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, err
	}

	// 2/3. Existing account by email.
	if id.Email != "" {
		u, err := q.GetUserByEmail(ctx, id.Email)
		switch {
		case err == nil:
			if !id.EmailVerified || u.EmailVerifiedAt == nil {
				return uuid.Nil, errExplicitLinkRequired
			}
			if err := s.st.WithTx(ctx, func(tq *storegen.Queries) error {
				if _, err := tq.CreateIdentity(ctx, storegen.CreateIdentityParams{
					ID: newUUID(), UserID: u.ID, ProviderKind: "social",
					SsoConnectionID: nil, Subject: id.NamespacedSubject,
				}); err != nil {
					return err
				}
				e := auditEvent(r, audit.ActionSocialLogin)
				e.Actor, e.ActorKind = u.ID, audit.ActorUser
				e.TargetKind, e.TargetID = "user", u.ID
				e.Detail = map[string]any{"provider": id.Provider, "linked": true}
				return s.auditW.Write(ctx, tq, e)
			}); err != nil {
				return uuid.Nil, err
			}
			return u.ID, nil
		case !errors.Is(err, pgx.ErrNoRows):
			return uuid.Nil, err
		}
	}

	// 4. JIT-create an individual account.
	newUserID := newUUID()
	handle, err := s.allocateHandle(ctx, id.Email, id.Provider+"-"+id.Subject)
	if err != nil {
		return uuid.Nil, err
	}
	displayName := id.DisplayName
	if strings.TrimSpace(displayName) == "" {
		displayName = handle
	}
	email := id.Email
	if email == "" {
		// No email asserted: a synthetic, unverifiable address keeps the NOT
		// NULL/UNIQUE contract without ever claiming an address is the user's.
		email = handle + "@" + id.Provider + ".social.local"
	}
	err = s.st.WithTx(ctx, func(tq *storegen.Queries) error {
		if err := tq.CreateHandle(ctx, storegen.CreateHandleParams{ID: newUserID, Handle: handle, Kind: "user"}); err != nil {
			return err
		}
		if _, err := tq.CreateUser(ctx, storegen.CreateUserParams{
			ID: newUserID, Email: email, DisplayName: displayName, PasswordHash: nil,
		}); err != nil {
			return err
		}
		if id.EmailVerified && id.Email != "" {
			if err := tq.MarkEmailVerified(ctx, newUserID); err != nil {
				return err
			}
		}
		if _, err := tq.CreateIdentity(ctx, storegen.CreateIdentityParams{
			ID: newUUID(), UserID: newUserID, ProviderKind: "social",
			SsoConnectionID: nil, Subject: id.NamespacedSubject,
		}); err != nil {
			return err
		}
		e := auditEvent(r, audit.ActionSocialLogin)
		e.Actor, e.ActorKind = newUserID, audit.ActorUser
		e.TargetKind, e.TargetID = "user", newUserID
		e.Detail = map[string]any{"provider": id.Provider, "jit": true}
		return s.auditW.Write(ctx, tq, e)
	})
	if err != nil {
		return uuid.Nil, err
	}
	return newUserID, nil
}

// sealTOTPChallenge mints the opaque challenge for a pending 2FA login.
func (s *Server) sealTOTPChallenge(userID uuid.UUID, provider string) (string, error) {
	blob, err := json.Marshal(totpChallengeBlob{
		UserID: userID, ExpiresAt: time.Now().Add(totpChallengeTTL), Provider: provider,
	})
	if err != nil {
		return "", err
	}
	sealed, err := s.sealer.Seal(blob)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

// TotpChallenge implements POST /auth/2fa/totp/challenge.
func (s *Server) TotpChallenge(w http.ResponseWriter, r *http.Request) {
	if !s.limits.allow("login", clientIP(r), s.classes.login, s.classes.loginBurst) {
		problemTooMany(w, r, "try again later")
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	var req TotpChallengeJSONRequestBody
	if !readJSON(w, r, &req) {
		return
	}
	sealed, err := base64.RawURLEncoding.DecodeString(req.Challenge)
	if err != nil {
		problemUnauthorized(w, r, "invalid challenge")
		return
	}
	raw, err := s.sealer.Open(sealed)
	if err != nil {
		problemUnauthorized(w, r, "invalid challenge")
		return
	}
	var blob totpChallengeBlob
	if err := json.Unmarshal(raw, &blob); err != nil || time.Now().After(blob.ExpiresAt) {
		problemUnauthorized(w, r, "challenge expired")
		return
	}
	user, err := s.q().GetUserByID(r.Context(), blob.UserID)
	if err != nil || user.State != "active" || !user.TotpEnabled {
		problemUnauthorized(w, r, "invalid challenge")
		return
	}
	secret, err := s.sealer.Open(user.TotpSecretEnc)
	if err != nil {
		s.log.Error("totp challenge: unseal", "err", err)
		problemInternal(w, r)
		return
	}
	if !auth.ValidateTOTP(req.Code, string(secret)) {
		e := auditEvent(r, audit.ActionUserLoginFailed)
		e.Actor, e.ActorKind = user.ID, audit.ActorUser
		e.Detail = map[string]any{"stage": "totp_challenge", "provider": blob.Provider}
		if werr := s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
			return s.auditW.Write(r.Context(), q, e)
		}); werr != nil {
			s.log.Warn("audit totp challenge failure", "err", werr)
		}
		problemUnauthorized(w, r, "invalid code")
		return
	}
	s.issueSocialSession(w, r, user, blob.Provider)
}

// issueSocialSession opens an ordinary session (no org SSO tag) and writes
// the LoginResult-shaped body both social endpoints return.
func (s *Server) issueSocialSession(w http.ResponseWriter, r *http.Request, user storegen.GetUserByIDRow, provider string) {
	ctx := r.Context()
	sessToken, err := auth.NewToken(auth.SessionPrefix)
	if err != nil {
		problemInternal(w, r)
		return
	}
	csrfToken, err := auth.NewToken("csrf_")
	if err != nil {
		problemInternal(w, r)
		return
	}
	var ipPtr *netip.Addr
	if ip, perr := netip.ParseAddr(clientIP(r)); perr == nil {
		ipPtr = &ip
	}
	ua := r.UserAgent()
	err = s.st.WithTx(ctx, func(q *storegen.Queries) error {
		if _, err := q.CreateSession(ctx, storegen.CreateSessionParams{
			ID: newUUID(), TokenSha256: auth.HashToken(sessToken), UserID: user.ID,
			CsrfToken: csrfToken, Ip: ipPtr, UserAgent: &ua,
			ExpiresAt: time.Now().Add(s.cfg.Auth.SessionTTL),
		}); err != nil {
			return err
		}
		e := auditEvent(r, audit.ActionUserLogin)
		e.Actor, e.ActorKind = user.ID, audit.ActorUser
		e.TargetKind, e.TargetID = "user", user.ID
		e.Detail = map[string]any{"method": "social", "provider": provider}
		return s.auditW.Write(ctx, q, e)
	})
	if err != nil {
		s.log.Error("social session", "err", err)
		problemInternal(w, r)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName, Value: sessToken, Path: "/", HttpOnly: true,
		Secure: s.cfg.Auth.CookieSecure, SameSite: http.SameSiteLaxMode,
		MaxAge: int(s.cfg.Auth.SessionTTL.Seconds()),
	})
	apiUser := User{
		Id: user.ID, Handle: user.Handle, Email: user.Email, DisplayName: user.DisplayName,
		EmailVerified: user.EmailVerifiedAt != nil, TotpEnabled: user.TotpEnabled,
		CreatedAt: user.CreatedAt,
	}
	// Both endpoints answer with the same body shape; TotpChallenge's spec
	// response is LoginResult, which SocialLoginResult is a superset of.
	writeJSON(w, http.StatusOK, SocialLoginResult{
		TotpRequired: false, User: &apiUser, CsrfToken: &csrfToken,
	})
}
