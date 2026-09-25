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
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"golang.org/x/oauth2"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/auth/social"
	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/logevent"
	"github.com/blaktron/agentry/internal/registry"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

const (
	socialStateCookie = "agentry_social_state"
	// socialRestartCookie is the loop guard for the callback's browser-mode
	// restart: it marks "we already restarted this sign-in once", so a
	// browser that cannot hold cookies gets an error page instead of a
	// redirect loop.
	socialRestartCookie = "agentry_social_restart"
	// totpChallengeTTL bounds the second leg of a 2FA social login.
	totpChallengeTTL = 5 * time.Minute
)

// isBrowserNavigation reports whether the request is a top-level browser
// navigation (a person following a redirect), as opposed to an API client.
func isBrowserNavigation(r *http.Request) bool {
	if r.Header.Get("Sec-Fetch-Mode") == "navigate" {
		return true
	}
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

// socialState is sealed into a short-lived cookie between start and callback.
type socialState struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Provider string `json:"p"`
	// Next is the in-app return path when the login began from a front end
	// (browser mode); empty means API mode and a JSON result.
	Next string `json:"x,omitempty"`
}

// safeNextPath admits only a path-absolute reference on this origin — the
// same rule as the site's safeNext (agentry-web, lib/urls.ts), mirrored here because the callback
// is the one that redirects. "//host" (scheme-relative), "/\host" (browsers
// normalize the backslash) and control characters are the open-redirect
// shapes a naive HasPrefix("/") lets through.
func safeNextPath(v string) string {
	if v == "" || v[0] != '/' {
		return ""
	}
	if len(v) > 1 && (v[1] == '/' || v[1] == '\\') {
		return ""
	}
	// A bound, because this value is carried through the round trip: the
	// org OIDC flow seals it into a state cookie, and a long enough path
	// pushes that cookie past what a browser will store, so it is dropped
	// and the callback fails on a missing state. A link alone would then
	// deny someone their organization's sign-in (agentry#365). No real
	// return path is anywhere near this long.
	if len(v) > maxNextPathBytes {
		return ""
	}
	for _, c := range v {
		if c < 0x20 || c == 0x7f {
			return ""
		}
	}
	return v
}

// maxNextPathBytes bounds a return path. The sealed OIDC state also holds
// the state, nonce, verifier and org handle, and browsers cap a cookie
// near 4 KB.
const maxNextPathBytes = 512

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
	case social.ProviderMicrosoft:
		return s.cfg.Social.Microsoft, s.cfg.Social.Microsoft.Configured()
	case social.ProviderOpenAI:
		return s.cfg.Social.OpenAI, s.cfg.Social.OpenAI.Configured()
	case social.ProviderClaude:
		return s.cfg.Social.Claude, s.cfg.Social.Claude.Configured()
	case social.ProviderAuthentik:
		return s.cfg.Social.Authentik, s.cfg.Social.Authentik.Configured()
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
func (s *Server) SocialOidcStart(w http.ResponseWriter, r *http.Request, provider SocialOidcStartParamsProvider, params SocialOidcStartParams) {
	if !s.allowLogin(w, r) {
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
	next := ""
	if params.Next != nil {
		next = safeNextPath(*params.Next)
	}
	blob, err := json.Marshal(socialState{State: state, Nonce: nonce, Verifier: verifier, Provider: name, Next: next})
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
	if !s.allowLogin(w, r) {
		return
	}
	if !s.requireDB(w, r) {
		return
	}
	name := string(provider)

	// A browser can arrive here without a usable state cookie and be
	// entirely legitimate: the sign-up confirmation link was opened on a
	// different device than the one that started the flow, or the ten-minute
	// state cookie expired while the mail sat unread. The IdP session those
	// flows just established is real — only OUR half of the handshake is
	// missing. So for a top-level navigation, restart the flow instead of
	// failing: a fresh /start issues a fresh state and the authorize
	// round-trip completes silently against the existing IdP session. The
	// code in hand is never accepted without its state; it is abandoned.
	// One restart only (guard cookie): a browser that cannot hold cookies
	// gets a message, not a redirect loop. API clients keep the 4xx.
	restartOrFail := func(apiFail func()) {
		if !isBrowserNavigation(r) {
			apiFail()
			return
		}
		if c, err := r.Cookie(socialRestartCookie); err == nil && c.Value != "" {
			http.Redirect(w, r, s.paths.login("Sign-in could not complete: this browser is not keeping cookies for the site. Allow cookies and retry."), http.StatusSeeOther)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name: socialRestartCookie, Value: "1", Path: "/", HttpOnly: true,
			Secure: s.cfg.Auth.CookieSecure, SameSite: http.SameSiteLaxMode, MaxAge: 120,
		})
		http.Redirect(w, r, "/api/v1/auth/oidc/"+name+"/start?next="+url.QueryEscape(s.paths.dashboardPath()), http.StatusSeeOther)
	}

	st, stateErr, stateUnauthorized := s.peekSocialState(w, r, name)
	if stateErr != "" {
		restartOrFail(func() {
			if stateUnauthorized {
				problemUnauthorized(w, r, stateErr)
			} else {
				problemValidation(w, r, stateErr)
			}
		})
		return
	}
	if params.State == nil || *params.State != st.State {
		restartOrFail(func() { problemUnauthorized(w, r, "The sign-in state did not match. Start the sign-in again.") })
		return
	}
	if params.Code == nil || *params.Code == "" {
		problemValidation(w, r, "The provider returned no authorization code. Start the sign-in again.")
		return
	}
	rp, err := s.socialProvider(r, name)
	if err != nil {
		problemNotFound(w, r)
		return
	}
	// Browser mode (DEV-061): a front end (the site, or /ui/login) started this login with a return
	// path, so the browser is the client and a JSON body would be the page
	// it lands on. Failures go back to /login with the message; success is
	// a 303 to `next` once the session cookie is set. API mode is unchanged.
	browserFail := func(msg string) {
		http.Redirect(w, r, s.paths.login(msg), http.StatusSeeOther)
	}
	id, err := rp.Exchange(r.Context(), *params.Code, st.Verifier, st.Nonce)
	if err != nil {
		s.log.WarnContext(r.Context(), "social login rejected", logevent.AuthSocialRejected.Attr(), "provider", name, "err", err)
		if st.Next != "" {
			browserFail("Sign-in with " + name + " failed. Try again.")
			return
		}
		problemUnauthorized(w, r, "Sign-in with the provider failed. Try again.")
		return
	}

	userID, err := s.resolveSocialUser(r, id)
	if err != nil {
		if errors.Is(err, errExplicitLinkRequired) {
			linkMsg := "An account already uses this email address. Sign in, then link " + name + " from account settings."
			if st.Next != "" {
				browserFail(linkMsg)
				return
			}
			writeProblem(w, r, http.StatusConflict, "sso-link-required",
				"Email address already in use", linkMsg)
			return
		}
		s.log.ErrorContext(r.Context(), "social jit", "provider", name, "err", err)
		problemInternal(w, r)
		return
	}
	// Evidence for the public-publish gate (agentry#23): the ID token's
	// `amr` named a second factor, so record it on the account.
	if id.MFAAsserted() {
		if err := s.q().SetUserIdPMFA(r.Context(), userID); err != nil {
			s.log.WarnContext(r.Context(), "social login: record idp mfa", "err", err)
		}
	}
	// Platform staff is membership of the staff organization
	// (agentry#556): recomputed at every sign-in, from facts nobody sets
	// about themselves. The directory group and the domain-alone rule are
	// retired.
	if s.reg != nil {
		actor := auditEvent(r, audit.ActionUserStaffSync)
		actor.Actor, actor.ActorKind = userID, audit.ActorUser
		if err := s.reg.SyncStaff(r.Context(), userID, registry.StaffSyncSignIn, actor); err != nil {
			s.log.ErrorContext(r.Context(), "social login: platform staff sync", "err", err, "user", userID)
		}
	}
	// The fold-in (agentry#364): an account at an organization's domain
	// becomes a pending member of it, once, keyed on this token's email
	// and its verified assertion.
	s.foldInAtSignIn(r, userID, id)

	user, err := s.q().GetUserByID(r.Context(), userID)
	if err != nil {
		problemInternal(w, r)
		return
	}
	if user.State != "active" {
		if st.Next != "" {
			browserFail("This account is not active.")
			return
		}
		problemUnauthorized(w, r, "This account is not active.")
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

	s.issueSocialSession(w, r, user, name, st.Next, id.AMR)
}

// readSocialState opens and clears the single-use state cookie.
// peekSocialState reads and consumes the sealed state cookie. It never
// writes a response body: the caller decides whether a failure is a 4xx
// (API client) or a browser-mode flow restart. failure=="" means st is
// valid; unauthorized says which problem class an API caller should get.
func (s *Server) peekSocialState(w http.ResponseWriter, r *http.Request, provider string) (st socialState, failure string, unauthorized bool) {
	c, err := r.Cookie(socialStateCookie)
	if err != nil || c.Value == "" {
		return socialState{}, "The sign-in state cookie is missing. Start the sign-in again.", false
	}
	// Single use regardless of outcome.
	clearCookie(w, socialStateCookie, s.cfg.Auth.CookieSecure)
	sealed, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return socialState{}, "The sign-in state is invalid. Start the sign-in again.", false
	}
	blob, err := s.sealer.Open(sealed)
	if err != nil {
		return socialState{}, "The sign-in state is invalid. Start the sign-in again.", true
	}
	if err := json.Unmarshal(blob, &st); err != nil || st.Provider != provider {
		return socialState{}, "The sign-in state is invalid. Start the sign-in again.", true
	}
	return st, "", false
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
	handle, err := s.allocateHandle(ctx, id.Username, id.Email, id.Provider+"-"+id.Subject)
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
		for k, v := range handleRequestedDetail(id.Username, handle) {
			e.Detail[k] = v
		}
		return s.auditW.Write(ctx, tq, e)
	})
	if err != nil {
		return uuid.Nil, err
	}
	// The same event the native register handler fires: an extension that
	// provisions something per account (a subscription tier's allowance)
	// hears every new account, whichever door created it (plan
	// subscription-tiers §5.2; under externalOnly this is the door). The
	// email is the IdP's assertion and emailVerified says whether it was
	// asserted verified — a hook must not mail an unverified one.
	payload := map[string]any{
		"handle": handle, "email": email, "emailVerified": id.EmailVerified && id.Email != "",
		"via": "social", "provider": id.Provider,
	}
	for k, v := range handleRequestedDetail(id.Username, handle) {
		payload[k] = v
	}
	s.fireEvent(r.Context(), Event{Kind: "user.registered", UserID: newUserID, Payload: payload})
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
	if !s.allowLogin(w, r) {
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
		problemUnauthorized(w, r, "The two-factor challenge is invalid. Start the sign-in again.")
		return
	}
	raw, err := s.sealer.Open(sealed)
	if err != nil {
		problemUnauthorized(w, r, "The two-factor challenge is invalid. Start the sign-in again.")
		return
	}
	var blob totpChallengeBlob
	if err := json.Unmarshal(raw, &blob); err != nil || time.Now().After(blob.ExpiresAt) {
		problemUnauthorized(w, r, "The two-factor challenge expired. Start the sign-in again.")
		return
	}
	user, err := s.q().GetUserByID(r.Context(), blob.UserID)
	if err != nil || user.State != "active" || !user.TotpEnabled {
		problemUnauthorized(w, r, "The two-factor challenge is invalid. Start the sign-in again.")
		return
	}
	secret, err := s.sealer.Open(user.TotpSecretEnc)
	if err != nil {
		s.log.ErrorContext(r.Context(), "totp challenge: unseal", "err", err)
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
			s.log.WarnContext(r.Context(), "audit totp challenge failure", "err", werr)
		}
		problemUnauthorized(w, r, "That code did not match. Try the current code from the authenticator app.")
		return
	}
	s.issueSocialSession(w, r, user, blob.Provider, "", nil)
}

// issueSocialSession opens an ordinary session (no org SSO tag) and writes
// the LoginResult-shaped body both social endpoints return.
// issueSocialSession creates the session and answers: a 303 to next in
// browser mode (next non-empty, already validated by safeNextPath), else the
// JSON result.
func (s *Server) issueSocialSession(w http.ResponseWriter, r *http.Request, user storegen.GetUserByIDRow, provider, next string, amr []string) {
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
		// What the directory said about the sign-in's factors (agentry#23):
		// the operator reads this row before turning on
		// auth.requireIdpMFA, and an empty value is itself the finding.
		if amr != nil {
			e.Detail["amr"] = amr
		} else {
			e.Detail["amr"] = []string{}
		}
		return s.auditW.Write(ctx, q, e)
	})
	if err != nil {
		s.log.ErrorContext(r.Context(), "social session", "err", err)
		problemInternal(w, r)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName, Value: sessToken, Path: "/", HttpOnly: true,
		Secure: s.cfg.Auth.CookieSecure, SameSite: http.SameSiteLaxMode,
		MaxAge: int(s.cfg.Auth.SessionTTL.Seconds()),
	})
	if next != "" {
		// Browser mode has no JSON body to carry the CSRF token, and the web
		// tier can only echo what it holds: set it as the cookie the web
		// tier's apiSend reads (the same double-submit shape the native
		// login route produces). httpOnly: page script never needs it, and
		// a cross-site page can neither read the cookie nor set the header.
		// Without this every cookie-authenticated mutation from a
		// directory-signed-in browser 403'd (agentry#77).
		http.SetCookie(w, &http.Cookie{
			Name: csrfCookieName, Value: csrfToken, Path: "/", HttpOnly: true,
			Secure: s.cfg.Auth.CookieSecure, SameSite: http.SameSiteLaxMode,
			MaxAge: int(s.cfg.Auth.SessionTTL.Seconds()),
		})
		http.Redirect(w, r, next, http.StatusSeeOther)
		return
	}
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
