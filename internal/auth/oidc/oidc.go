// Package oidc implements the OpenID Connect Relying Party side of enterprise
// SSO (§12.4): authorization-code flow with PKCE, issuer pinning (the
// discovery document's issuer must match the configured issuer), and
// email_verified respected. Built on github.com/coreos/go-oidc/v3 and
// golang.org/x/oauth2 (Appendix B: both active).
package oidc

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Config is the per-org OIDC connection configuration (stored in
// sso_connections.config; the client secret is sealed at rest by the caller).
type Config struct {
	Issuer       string   `json:"issuer"`
	ClientID     string   `json:"clientId"`
	ClientSecret string   `json:"clientSecret,omitempty"`
	RedirectURL  string   `json:"redirectUrl,omitempty"`
	Scopes       []string `json:"scopes,omitempty"`
}

// RP is a configured Relying Party for one org connection.
type RP struct {
	provider *coreoidc.Provider
	oauth    *oauth2.Config
	verifier *coreoidc.IDTokenVerifier
	cfg      Config
}

// Claims is the subset of ID-token claims the JIT flow consumes.
type Claims struct {
	Subject       string
	Email         string
	EmailVerified bool
	Issuer        string
	// AMR is the token's Authentication Methods References (RFC 8176) as
	// the IdP sent them, e.g. ["pwd","mfa"]; nil when absent. ACR is the
	// Authentication Context Class Reference, if any. The registry uses
	// AMR as evidence that a second factor was used (agentry#23).
	AMR []string
	ACR string
	// Groups is the token's `groups` claim (authentik's profile scope puts
	// the user's group names there); nil when absent. The registry maps
	// one configured group onto platform staff (agentry#51).
	Groups []string
	// PreferredUsername is the `preferred_username` claim: the name the
	// person chose at the IdP (authentik's profile scope puts the
	// directory's username there); "" when absent. It is a seed for a new
	// account's handle, never an identifier: OIDC Core §5.7 does not make
	// it unique or stable, so nothing is looked up by it (agentry#517).
	PreferredUsername string
	// RememberDevice is the directory's `agentry_remember_device` claim
	// (agentry#670, DEV-163): the person ticked "Remember this device for 30
	// days" on the directory's code page, in the sign-in this token closes.
	// True only for a JSON true. It asks for a remembered browser; it proves
	// nothing about a factor, which is AMR's to say.
	RememberDevice bool
	// AuthTime is the `auth_time` claim: when the person last actually
	// authenticated at the IdP, zero when absent. A token minted silently
	// against a live IdP session carries the original time, which is how
	// the registry tells a fresh sign-in from a replayed session
	// (agentry#670).
	AuthTime time.Time
	// DirectoryAccountID is the directory's `agentry_directory_id` claim
	// (agentry#727): the directory's own id for the account signing in, sent
	// by the same `agentry` scope. It lets the registry read that account
	// without narrowing by an address the directory does not keep unique.
	// Zero when absent or not a positive whole number.
	DirectoryAccountID int64
}

// New builds the RP. coreoidc.NewProvider performs discovery and pins the
// issuer: it returns an error when the discovery document's issuer differs
// from cfg.Issuer (issuer pinning, §12.4). Pass a context carrying a custom
// *http.Client via coreoidc.ClientContext to reach a private/test IdP.
func New(ctx context.Context, cfg Config, redirectURL string) (*RP, error) {
	if cfg.Issuer == "" || cfg.ClientID == "" {
		return nil, fmt.Errorf("oidc: issuer and clientId are required")
	}
	provider, err := coreoidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc: provider discovery/issuer pin: %w", err)
	}
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{coreoidc.ScopeOpenID, "email", "profile"}
	}
	rURL := redirectURL
	if rURL == "" {
		rURL = cfg.RedirectURL
	}
	oauthCfg := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  rURL,
		Scopes:       scopes,
	}
	return &RP{
		provider: provider,
		oauth:    oauthCfg,
		verifier: provider.Verifier(&coreoidc.Config{ClientID: cfg.ClientID}),
		cfg:      cfg,
	}, nil
}

// AuthURL returns the IdP authorization URL for an auth-code + PKCE flow. The
// caller must persist state, nonce, and verifier (in a short-lived sealed
// cookie or server-side) and supply them to Exchange.
//
// It asks for no offline access: the registry keeps its own sessions and
// never uses a refresh token, so asking an IdP to mint one (access_type=
// offline, a Google convention some IdPs honour) would only create a
// long-lived credential nobody holds on purpose (agentry#494).
func (rp *RP) AuthURL(state, nonce, verifier string) string {
	return rp.oauth.AuthCodeURL(state,
		oauth2.S256ChallengeOption(verifier),
		coreoidc.Nonce(nonce),
	)
}

// Exchange completes the flow: it exchanges the code (sending the PKCE
// verifier), extracts and verifies the ID token (signature, issuer, audience,
// expiry), checks the nonce, and returns the claims. email_verified is
// surfaced verbatim for the JIT decision (§12.4, T-12).
func (rp *RP) Exchange(ctx context.Context, code, verifier, expectedNonce string) (*Claims, error) {
	tok, err := rp.oauth.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, fmt.Errorf("oidc: code exchange: %w", err)
	}
	rawID, ok := tok.Extra("id_token").(string)
	if !ok || rawID == "" {
		return nil, fmt.Errorf("oidc: token response has no id_token")
	}
	idToken, err := rp.verifier.Verify(ctx, rawID)
	if err != nil {
		return nil, fmt.Errorf("oidc: id_token verification: %w", err)
	}
	if expectedNonce != "" && idToken.Nonce != expectedNonce {
		return nil, fmt.Errorf("oidc: id_token nonce mismatch")
	}
	var raw struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified any    `json:"email_verified"`
		AMR           any    `json:"amr"`
		ACR           string `json:"acr"`
		Groups        any    `json:"groups"`
		PreferredUser string `json:"preferred_username"`
		RememberDev   any    `json:"agentry_remember_device"`
		DirectoryID   any    `json:"agentry_directory_id"`
		AuthTime      int64  `json:"auth_time"`
	}
	if err := idToken.Claims(&raw); err != nil {
		return nil, fmt.Errorf("oidc: decode claims: %w", err)
	}
	c := &Claims{
		Subject:       idToken.Subject,
		Email:         strings.ToLower(strings.TrimSpace(raw.Email)),
		EmailVerified: asBool(raw.EmailVerified),
		Issuer:        idToken.Issuer,
		AMR:           asStrings(raw.AMR),
		ACR:           raw.ACR,
		Groups:        asStrings(raw.Groups),
		// Trimmed only: the handle grammar is the caller's to apply.
		PreferredUsername: strings.TrimSpace(raw.PreferredUser),
	}
	// Strictly the boolean: this claim is half of what mints a credential,
	// so nothing that merely looks like yes counts.
	if v, ok := raw.RememberDev.(bool); ok && v {
		c.RememberDevice = true
	}
	if raw.AuthTime > 0 {
		c.AuthTime = time.Unix(raw.AuthTime, 0)
	}
	c.DirectoryAccountID = asAccountID(raw.DirectoryID)
	if c.Subject == "" {
		c.Subject = raw.Sub
	}
	if c.Subject == "" {
		return nil, fmt.Errorf("oidc: id_token has no subject")
	}
	return c, nil
}

// asAccountID reads a directory account id: a JSON number that is a
// positive whole number a float64 holds exactly. Anything else is 0, which
// the registry treats as "not sent".
func asAccountID(v any) int64 {
	f, ok := v.(float64)
	if !ok || f < 1 || f > 1<<53 || f != math.Trunc(f) {
		return 0
	}
	return int64(f)
}

// asStrings reads amr as the JSON array RFC 8176 specifies, tolerating a
// single string (seen in the wild) and dropping anything else.
func asStrings(v any) []string {
	switch x := v.(type) {
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		if x == "" {
			return nil
		}
		return []string{x}
	}
	return nil
}

// asBool tolerates providers that encode email_verified as a JSON bool or a
// string ("true"/"false") — both occur in the wild.
func asBool(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return strings.EqualFold(x, "true")
	default:
		return false
	}
}

// Description is what discovery established for a connection test
// (agentry#50): the issuer that answered and its endpoints.
type Description struct {
	Issuer      string
	AuthURL     string
	TokenURL    string
	UserInfoURL string
	JWKSURL     string
}

// Describe reports the discovered endpoints. Constructing the RP already
// performed discovery against the configured issuer, so this is the
// evidence that the issuer is reachable and self-consistent.
func (rp *RP) Describe() Description {
	ep := rp.provider.Endpoint()
	var claims struct {
		UserInfo string `json:"userinfo_endpoint"`
		JWKS     string `json:"jwks_uri"`
	}
	_ = rp.provider.Claims(&claims)
	return Description{Issuer: rp.cfg.Issuer, AuthURL: ep.AuthURL, TokenURL: ep.TokenURL, UserInfoURL: claims.UserInfo, JWKSURL: claims.JWKS}
}
