// Package social implements sign-in for individual accounts through the
// deployment's OpenID provider (linked via identities; no password), on the
// relying party in internal/auth/oidc. It admits anyone with an account at
// the provider, grants an individual session and is configured server-wide.
package social

import (
	"context"
	"fmt"
	"net/http"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"

	oidcrp "github.com/blaktron/agentry/internal/auth/oidc"
)

// Provider ids. Closed set: an unknown id is a 404, never a guess.
const (
	// ProviderAuthentik is the deployment's generic sign-in provider under
	// the id authentik, where its accounts are linked under that id: the
	// same provider as ProviderOIDC, with no defaults.
	ProviderAuthentik = "authentik"
	// ProviderOIDC is the deployment's generic sign-in provider: any OpenID
	// Connect issuer the operator points it at, with no defaults.
	ProviderOIDC = "oidc"
)

// Providers lists the supported provider ids, in the order the sign-in
// page offers them. The API layer validates provider names against its
// generated enum, so this is a listing for tooling and tests, not a gate.
func Providers() []string {
	return []string{ProviderAuthentik, ProviderOIDC}
}

// Identity is what a completed sign-in asserts about the caller.
type Identity struct {
	// Provider is the provider id ("oidc", "authentik").
	Provider string
	// Subject is the provider's stable id for this account, NOT namespaced.
	Subject string
	// NamespacedSubject is what goes in identities.subject: "<provider>:<sub>".
	// Namespacing keeps one provider's subject 42 apart from another's in a
	// single-column, provider-agnostic identity table.
	NamespacedSubject string
	Email             string
	EmailVerified     bool
	DisplayName       string
	// AMR/ACR carry the ID token's authentication-method claims. See
	// oidc.Claims.
	AMR []string
	ACR string
	// Groups is the ID token's `groups` claim (directory group names).
	Groups []string
	// Username is the ID token's `preferred_username`: the name chosen at the
	// IdP, which seeds a new account's handle. Never used to find an account.
	Username string
	// AuthTime is the ID token's `auth_time`: when the person last actually
	// authenticated at the IdP (zero when absent). A remembered browser is
	// minted only from a fresh one.
	AuthTime time.Time
	// Claims is every claim of the ID token, for a reader of an IdP's own
	// claims: an extension reads them through the sign-in hook.
	Claims map[string]any
}

// MFAAsserted reports whether AMR names a second factor, by the relying
// party's rule (oidcrp.AMRNamesSecondFactor).
func (id *Identity) MFAAsserted() bool {
	return oidcrp.AMRNamesSecondFactor(id.AMR)
}

// Config configures the provider.
type Config struct {
	ClientID     string
	ClientSecret string
	// Issuer is the OpenID provider's issuer; its discovery document names
	// every endpoint.
	Issuer string
	Scopes []string
	// HTTPClient is used for discovery, token exchange, and API calls.
	HTTPClient *http.Client
}

// Provider is the configured sign-in provider.
type Provider interface {
	// Name is the provider id.
	Name() string
	// UsesPKCE reports whether Exchange expects a PKCE verifier.
	UsesPKCE() bool
	// AuthURL builds the provider's authorization URL.
	AuthURL(state, nonce, verifier string) string
	// Exchange completes the flow and returns the asserted identity.
	Exchange(ctx context.Context, code, verifier, nonce string) (*Identity, error)
}

// New builds the provider named by name.
func New(ctx context.Context, name string, cfg Config, redirectURL string) (Provider, error) {
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, fmt.Errorf("social: %s is not configured", name)
	}
	switch name {
	case ProviderAuthentik, ProviderOIDC:
		// Whatever issuer the operator names, asked for the scopes they
		// configured or the standard three.
		return newOIDC(ctx, name, cfg, redirectURL)
	default:
		return nil, fmt.Errorf("social: unknown provider %q", name)
	}
}

// Startable reports whether a provider's settings are enough for New to build
// it: a client id, a secret and an issuer. It needs no network, so it can
// answer for a provider whose issuer is down; New can still fail then.
func Startable(name string, cfg Config) bool {
	if cfg.ClientID == "" || cfg.ClientSecret == "" || cfg.Issuer == "" {
		return false
	}
	return name == ProviderAuthentik || name == ProviderOIDC
}

// oidcProvider is a standard OpenID Connect relying party, good for any
// issuer with a discovery document.
type oidcProvider struct {
	name string
	rp   *oidcrp.RP
	// client is Config.HTTPClient, nil for the default. Discovery used it
	// through New's context; the token exchange runs on the request's
	// context and needs it passed again, or it quietly falls back to the
	// default client.
	client *http.Client
}

func newOIDC(ctx context.Context, name string, cfg Config, redirectURL string) (Provider, error) {
	issuer := cfg.Issuer
	if issuer == "" {
		return nil, fmt.Errorf("social: %s has no issuer; configure one or leave it unoffered", name)
	}
	if cfg.HTTPClient != nil {
		ctx = coreoidc.ClientContext(ctx, cfg.HTTPClient)
	}
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{coreoidc.ScopeOpenID, "email", "profile"}
	}
	rp, err := oidcrp.New(ctx, oidcrp.Config{
		Issuer: issuer, ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret, Scopes: scopes,
	}, redirectURL)
	if err != nil {
		return nil, err
	}
	return &oidcProvider{name: name, rp: rp, client: cfg.HTTPClient}, nil
}

func (p *oidcProvider) Name() string   { return p.name }
func (p *oidcProvider) UsesPKCE() bool { return true }

func (p *oidcProvider) AuthURL(state, nonce, verifier string) string {
	return p.rp.AuthURL(state, nonce, verifier)
}

func (p *oidcProvider) Exchange(ctx context.Context, code, verifier, nonce string) (*Identity, error) {
	if p.client != nil {
		ctx = coreoidc.ClientContext(ctx, p.client)
	}
	claims, err := p.rp.Exchange(ctx, code, verifier, nonce)
	if err != nil {
		return nil, err
	}
	return &Identity{
		Provider:          p.name,
		Subject:           claims.Subject,
		NamespacedSubject: p.name + ":" + claims.Subject,
		Email:             claims.Email,
		EmailVerified:     claims.EmailVerified,
		AMR:               claims.AMR,
		ACR:               claims.ACR,
		Groups:            claims.Groups,
		Username:          claims.PreferredUsername,
		AuthTime:          claims.AuthTime,
		Claims:            claims.Raw,
	}, nil
}
