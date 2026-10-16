package api

// Social login for individual accounts
// (GET /auth/oidc/{provider}/{start,callback}).
//
// The identity rules are the account-takeover guard, restated for a
// server-wide provider rather than a per-org one:
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
	"context"
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
	// maxTOTPChallengeID bounds a challenge's id as the consumed set's
	// table does; the server mints 52 characters (auth.NewToken).
	maxTOTPChallengeID = 64
	// defaultTOTPConsumeTimeout bounds the consumed set's write, so a
	// database that does not answer refuses the challenge rather than
	// holding the sign-in.
	defaultTOTPConsumeTimeout = 5 * time.Second
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
// same rule as the site's safeNext, mirrored here because the callback
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
	// deny someone their organization's sign-in. No real
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
// why the code is still required. ID is random and is recorded in the
// database when the challenge completes, which is what makes it single use
// at every replica.
type totpChallengeBlob struct {
	ID        string    `json:"i"`
	UserID    uuid.UUID `json:"u"`
	ExpiresAt time.Time `json:"e"`
	Provider  string    `json:"p"`
}

// socialProviderIDs is the closed set of individual sign-in providers, in the
// order the spec's provider enum lists them.
var socialProviderIDs = []string{
	social.ProviderGoogle, social.ProviderGitHub, social.ProviderMicrosoft,
	social.ProviderOpenAI, social.ProviderClaude, social.ProviderAuthentik,
	social.ProviderOIDC,
}

// configuredSocialProviders lists the providers socialProviderConfig accepts,
// which are the ones SocialOidcStart can redirect for. /meta reports it so a
// front end never has to start a flow to learn what is offered.
func (s *Server) configuredSocialProviders() []string {
	out := []string{}
	for _, id := range socialProviderIDs {
		if _, ok := s.socialProviderConfig(id); ok {
			out = append(out, id)
		}
	}
	return out
}

// socialProviderConfig returns a provider's settings, and whether they are
// enough to start a sign-in with (social.Startable: a client id and secret,
// and an issuer where the provider has no default). "authentik" and "oidc"
// are the deployment's one sign-in OpenID provider (config.SignInOIDC),
// answered under whichever of the two ids it has.
func (s *Server) socialProviderConfig(name string) (social.Config, bool) {
	var pc config.SocialProvider
	var scopes []string
	switch name {
	case social.ProviderGoogle:
		pc = s.cfg.Social.Google
	case social.ProviderGitHub:
		pc = s.cfg.Social.GitHub
	case social.ProviderMicrosoft:
		pc = s.cfg.Social.Microsoft
	case social.ProviderOpenAI:
		pc = s.cfg.Social.OpenAI
	case social.ProviderClaude:
		pc = s.cfg.Social.Claude
	case social.ProviderAuthentik, social.ProviderOIDC:
		p, ok := s.cfg.SignInOIDC()
		if !ok || p.ID != name {
			return social.Config{}, false
		}
		pc = config.SocialProvider{ClientID: p.ClientID, ClientSecret: p.ClientSecret, Issuer: p.Issuer}
		scopes = p.Scopes
	default:
		return social.Config{}, false
	}
	c := social.Config{
		ClientID: pc.ClientID, ClientSecret: pc.ClientSecret,
		Issuer: pc.Issuer, AuthURL: pc.AuthURL, TokenURL: pc.TokenURL,
		APIBaseURL: pc.APIBaseURL, Scopes: scopes,
	}
	return c, social.Startable(name, c)
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
	c, ok := s.socialProviderConfig(name)
	if !ok {
		return nil, errors.New("provider not configured")
	}
	c.HTTPClient = s.oidcHTTPClient
	return social.New(r.Context(), name, c, s.socialRedirectURL(r, name))
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
		// A provider that is not configured, or not completely, is absent
		// from this deployment: 404, never 422, so its settings are not
		// probed. /meta lists the configured ones, so a
		// listed provider answering 404 here says only that its issuer
		// could not be reached just now.
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
	// Browser mode: a front end (the site, or /ui/login) started this login with a return
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
	// Evidence for the public-publish gate: the ID token's
	// `amr` named a second factor, so record it on the account.
	if id.MFAAsserted() {
		if err := s.q().SetUserIdPMFA(r.Context(), userID); err != nil {
			s.log.WarnContext(r.Context(), "social login: record idp mfa", "err", err)
		}
	}
	// The directory's own id for the account: every later
	// directory lookup reads the account by it. Only the directory's token
	// is believed, and it is recorded on the identity this token signed in,
	// so it is a directory fact and never one a person sets.
	if dirID := directoryAccountID(id.Claims); name == social.ProviderAuthentik && dirID > 0 {
		if err := s.q().SetSocialIdentityDirectoryAccount(r.Context(), storegen.SetSocialIdentityDirectoryAccountParams{
			Subject: id.NamespacedSubject, DirectoryAccountID: &dirID,
		}); err != nil {
			s.log.WarnContext(r.Context(), "social login: record the directory account id", "err", err)
		}
	}
	// Platform staff is membership of the staff organization,
	// recomputed at every sign-in, from facts nobody sets
	// about themselves.
	if s.reg != nil {
		actor := auditEvent(r, audit.ActionUserStaffSync)
		actor.Actor, actor.ActorKind = userID, audit.ActorUser
		if err := s.reg.SyncStaff(r.Context(), userID, registry.StaffSyncSignIn, actor); err != nil {
			s.log.ErrorContext(r.Context(), "social login: platform staff sync", "err", err, "user", userID)
		}
	}
	// The fold-in: an account at an organization's domain
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

	// 2FA still applies: social login is an authentication method,
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

	s.fireSignIn(r.Context(), SignIn{
		UserID: userID, Provider: name, Subject: id.NamespacedSubject,
		Claims: id.Claims, AMR: id.AMR, AuthTime: id.AuthTime,
		Request: r, SetCookie: func(c *http.Cookie) { http.SetCookie(w, c) },
		RememberBrowser: func(detail map[string]any) (string, time.Duration, error) {
			return s.mintRememberedBrowser(r, userID, id.AMR, id.AuthTime, detail)
		},
	})
	s.issueSocialSession(w, r, user, name, st.Next, id.AMR, s.directoryRemembers(name, id))
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

// resolveSocialUser applies the linking rules and returns the user.
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
		case err == nil && id.EmailVerified && u.EmailVerifiedAt == nil && s.unactivatedSuperseded(ctx, u.ID, u.Email):
			// The address is held by an account that
			// never confirmed it, and the directory account it signed in
			// with is gone, removed by the directory when a trusted
			// provider proved the address. It was read-only and is
			// no organization's last admin (unactivatedSuperseded), so it
			// is erased and the address starts clean.
			if err := s.eraseSuperseded(r, u.ID, u.Email, id.Provider); err != nil {
				return uuid.Nil, err
			}
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
	activation := ""
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
		email = handle + "@" + id.Provider + auth.SyntheticAddressSuffix
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
		} else if id.Email != "" {
			// An address the provider did not vouch for (a self-enrolled
			// directory account): the account starts
			// unactivated, and its first activation link is made here so
			// the five-minute limit counts it.
			var err error
			if activation, _, err = issueActivation(ctx, tq, newUserID, false); err != nil {
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
		if promo := signupPromoCode(id); promo != "" {
			e.Detail["promoCode"] = promo
		}
		return s.auditW.Write(ctx, tq, e)
	})
	if err != nil {
		return uuid.Nil, err
	}
	// The same event the native register handler fires: an extension that
	// provisions something per account (a subscription tier's allowance)
	// hears every new account, whichever door created it (under
	// externalOnly this is the door). The
	// email is the IdP's assertion and emailVerified says whether it was
	// asserted verified — a hook must not mail an unverified one.
	payload := map[string]any{
		"handle": handle, "email": email, "emailVerified": id.EmailVerified && id.Email != "",
		"via": "social", "provider": id.Provider,
	}
	for k, v := range handleRequestedDetail(id.Username, handle) {
		payload[k] = v
	}
	// The promo code typed at sign-up: the core names it and
	// the billing extension decides what it is worth. Only here, on the
	// sign-in that makes the account: the claim rides every later token of
	// the account too, and a linked account or a returning one is not new.
	if promo := signupPromoCode(id); promo != "" {
		payload["promoCode"] = promo
	}
	s.fireEvent(r.Context(), Event{Kind: "user.registered", UserID: newUserID, Payload: payload})
	if activation != "" {
		s.mailActivation(ctx, email, handle, activation)
	}
	return newUserID, nil
}

// signupPromoCode is the promo code a new account's first token carries,
// believed from the directory alone: another provider asserting the claim
// is a claim about nothing it holds.
func signupPromoCode(id *social.Identity) string {
	if id.Provider != social.ProviderAuthentik {
		return ""
	}
	return PromoCodeClaim(id.Claims[claimPromoCode])
}

// sealTOTPChallenge mints the opaque challenge for a pending 2FA login.
func (s *Server) sealTOTPChallenge(userID uuid.UUID, provider string) (string, error) {
	return s.sealTOTPChallengeAt(userID, provider, time.Now().Add(totpChallengeTTL))
}

func (s *Server) sealTOTPChallengeAt(userID uuid.UUID, provider string, expiresAt time.Time) (string, error) {
	id, err := auth.NewToken("")
	if err != nil {
		return "", err
	}
	blob, err := json.Marshal(totpChallengeBlob{
		ID: id, UserID: userID, ExpiresAt: expiresAt, Provider: provider,
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
	if err := json.Unmarshal(raw, &blob); err != nil || blob.ID == "" || len(blob.ID) > maxTOTPChallengeID {
		// A challenge that carries no id cannot be held to single use: it is
		// refused, and the sign-in starts again.
		problemUnauthorized(w, r, "The two-factor challenge is invalid. Start the sign-in again.")
		return
	}
	expired := time.Now().After(blob.ExpiresAt)
	user, err := s.q().GetUserByID(r.Context(), blob.UserID)
	if err != nil || user.State != "active" || !user.TotpEnabled {
		if expired {
			// The expiry is answered the same either way; only an account that
			// still signs in has the refusal written to its audit trail.
			writeProblem(w, r, http.StatusUnauthorized, "totp-challenge-expired", "Two-factor challenge expired",
				"The two-factor challenge expired. Start the sign-in again.")
			return
		}
		problemUnauthorized(w, r, "The two-factor challenge is invalid. Start the sign-in again.")
		return
	}
	if expired {
		s.auditTOTPChallengeFailure(r, user.ID, blob.Provider, "expired")
		writeProblem(w, r, http.StatusUnauthorized, "totp-challenge-expired", "Two-factor challenge expired",
			"The two-factor challenge expired. Start the sign-in again.")
		return
	}
	secret, err := s.sealer.Open(user.TotpSecretEnc)
	if err != nil {
		s.log.ErrorContext(r.Context(), "totp challenge: unseal", "err", err)
		problemInternal(w, r)
		return
	}
	if !auth.ValidateTOTP(req.Code, string(secret)) {
		s.auditTOTPChallengeFailure(r, user.ID, blob.Provider, "code")
		problemUnauthorized(w, r, "That code did not match. Try the current code from the authenticator app.")
		return
	}
	// The challenge is consumed only once its code is right, so a mistyped
	// code can be tried again; a second completion is refused. A store that
	// cannot record it refuses the challenge, as the SAML consumed set does.
	consumed, err := s.consumeTOTPChallenge(r.Context(), blob)
	if err != nil {
		// A request that had already ended is a refusal, not an outage: a
		// rolling deploy must not emit a burst of the alert's line.
		if r.Context().Err() != nil {
			s.log.WarnContext(r.Context(), "totp challenge: the sign-in ended while recording it as consumed", "err", err)
		} else {
			s.log.ErrorContext(r.Context(), "totp challenge: recording it as consumed", logevent.TOTPChallengeUnavailable.Attr(), "err", err)
		}
		problemUnavailable(w, r, "The sign-in cannot be completed right now. Try again in a moment.")
		return
	}
	if !consumed {
		s.auditTOTPChallengeFailure(r, user.ID, blob.Provider, "replayed")
		writeProblem(w, r, http.StatusUnauthorized, "totp-challenge-used", "Two-factor challenge already used",
			"This two-factor challenge was already used. Start the sign-in again.")
		return
	}
	s.issueSocialSession(w, r, user, blob.Provider, "", nil, false)
}

// consumeTOTPChallenge records the challenge's id in the consumed set every
// replica reads, and says whether this was its first completion. The row is
// kept a TTL past the challenge's own expiry, a margin for the replicas'
// clocks, then swept here.
func (s *Server) consumeTOTPChallenge(reqCtx context.Context, blob totpChallengeBlob) (bool, error) {
	ctx, cancel := context.WithTimeout(reqCtx, s.totpConsumeTimeout)
	defer cancel()
	q := s.q()
	n, err := q.ConsumeTOTPChallenge(ctx, storegen.ConsumeTOTPChallengeParams{
		ID: blob.ID, ExpiresAt: blob.ExpiresAt.Add(totpChallengeTTL),
	})
	if err != nil {
		return false, err
	}
	if _, err := q.DeleteExpiredTOTPChallenges(ctx); err != nil {
		s.log.WarnContext(ctx, "totp challenge: dropping expired consumed challenges", "err", err)
	}
	return n == 1, nil
}

// auditTOTPChallengeFailure records a refused second leg; reason tells a
// wrong code, an expired challenge and a replayed one apart.
func (s *Server) auditTOTPChallengeFailure(r *http.Request, userID uuid.UUID, provider, reason string) {
	e := auditEvent(r, audit.ActionUserLoginFailed)
	e.Actor, e.ActorKind = userID, audit.ActorUser
	e.Detail = map[string]any{"stage": "totp_challenge", "provider": provider, "reason": reason}
	if werr := s.st.WithTx(r.Context(), func(q *storegen.Queries) error {
		return s.auditW.Write(r.Context(), q, e)
	}); werr != nil {
		s.log.WarnContext(r.Context(), "audit totp challenge failure", "err", werr)
	}
}

// issueSocialSession opens an ordinary session (no org SSO tag) and answers:
// a 303 to next in browser mode (next non-empty, already validated by
// safeNextPath), else the LoginResult-shaped body both social endpoints
// return. remember mints a remembered browser in the same transaction
// (directoryRemembers decided it).
func (s *Server) issueSocialSession(w http.ResponseWriter, r *http.Request, user storegen.GetUserByIDRow, provider, next string, amr []string, remember bool) {
	ctx := r.Context()
	var cookieDomain string
	if remember {
		// Validated at start-up, so this cannot fail in a running server; if
		// it somehow did, the sign-in still completes and simply is not
		// remembered, rather than minting a cookie the directory never sees.
		d, derr := s.cfg.DirectoryTrustCookieDomain()
		if derr != nil {
			s.log.WarnContext(ctx, "directory sign-in: not remembering the browser", "err", derr)
			remember = false
		}
		cookieDomain = d
	}
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
	var deviceToken string
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
		// What the directory said about the sign-in's factors:
		// the operator reads this row before turning on
		// auth.requireIdpMFA, and an empty value is itself the finding.
		if amr != nil {
			e.Detail["amr"] = amr
		} else {
			e.Detail["amr"] = []string{}
		}
		if err := s.auditW.Write(ctx, q, e); err != nil {
			return err
		}
		if remember {
			// Inside the session's transaction, like the native mint: a
			// sign-in that asked to be remembered is remembered or fails.
			tok, err := s.createTrustedDevice(ctx, q, r, user.ID, map[string]any{"via": "directory", "provider": provider})
			if err != nil {
				return err
			}
			deviceToken = tok
		}
		return nil
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
	if deviceToken != "" {
		setDirectoryTrustedDeviceCookie(w, deviceToken, s.cfg.Auth.TrustedDeviceTTL, s.cfg.Auth.CookieSecure, cookieDomain)
	}
	if next != "" {
		// Browser mode has no JSON body to carry the CSRF token, and the web
		// tier can only echo what it holds: set it as the cookie the web
		// tier's apiSend reads (the same double-submit shape the native
		// login route produces). httpOnly: page script never needs it, and
		// a cross-site page can neither read the cookie nor set the header.
		// Without this every cookie-authenticated mutation from a
		// directory-signed-in browser would 403.
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
