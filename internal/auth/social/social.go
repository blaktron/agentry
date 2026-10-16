// Package social implements social login for individual accounts
// (GitHub, Google and others, linked via identities; no password required).
// It is deliberately separate from internal/auth/oidc, which serves per-org
// enterprise SSO: the two flows differ in who they
// admit (anyone with an account at the provider vs. members of one org's
// IdP), what they grant (an individual session vs. org membership with an
// SSO freshness tag), and how they are configured (server-wide vs. per org).
//
// The providers fall into two kinds:
//
//	google — OpenID Connect proper, through the same RP as enterprise OIDC
//	         (discovery, issuer pinning, PKCE, id_token verification).
//	github — an OAuth 2.0 shim. GitHub is NOT an OIDC issuer: it publishes no
//	         discovery document and returns no id_token, so there is nothing
//	         to verify a signature over. The shim exchanges the code and then
//	         asks the API who the token belongs to, taking the identity from
//	         GitHub's answer over an authenticated channel. Email comes from
//	         /user/emails and is accepted ONLY when GitHub reports it primary
//	         AND verified — an unverified provider email must never satisfy the
//	         rule that links a login to an existing account by email.
package social

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	oidcrp "github.com/blaktron/agentry/internal/auth/oidc"
)

// Provider ids. Closed set: an unknown id is a 404, never a guess.
const (
	ProviderGoogle    = "google"
	ProviderGitHub    = "github"
	ProviderMicrosoft = "microsoft"
	ProviderOpenAI    = "openai"
	ProviderClaude    = "claude"
	// ProviderAuthentik is the deployment's own directory service:
	// an Authentik instance shipped with the stack. OIDC proper, no default
	// issuer — the operator points it at their instance's application slug
	// (e.g. https://auth.example/application/o/agentry/).
	ProviderAuthentik = "authentik"
	// ProviderOIDC is the deployment's generic sign-in provider: any OpenID
	// Connect issuer the operator points it at, with no defaults.
	ProviderOIDC = "oidc"
)

// ScopeAgentry is the scope the directory's `agentry_remember_device`
// mapping answers to. Only the directory is asked for it: no other provider
// has such a mapping, and one that invented the claim would still not be
// the directory the registry trusts it from. authentik drops a requested scope its provider has no mapping for, so asking before
// the directory's flow carries the mapping is harmless.
const ScopeAgentry = "agentry"

// Providers lists the supported provider ids, in the order the sign-in
// page offers them. The API layer validates provider names against its
// generated enum, so this is a listing for tooling and tests, not a gate.
func Providers() []string {
	return []string{ProviderGoogle, ProviderGitHub, ProviderMicrosoft, ProviderOpenAI, ProviderClaude, ProviderAuthentik, ProviderOIDC}
}

// Identity is what a completed social login asserts about the caller.
type Identity struct {
	// Provider is the provider id ("google", "github").
	Provider string
	// Subject is the provider's stable id for this account, NOT namespaced.
	Subject string
	// NamespacedSubject is what goes in identities.subject: "<provider>:<sub>".
	// Namespacing is what keeps GitHub user 42 and Google user 42 apart in a
	// single-column, provider-agnostic identity table.
	NamespacedSubject string
	Email             string
	EmailVerified     bool
	DisplayName       string
	// AMR/ACR carry the ID token's authentication-method claims (OIDC
	// providers only; the GitHub shim has no ID token). See oidc.Claims.
	AMR []string
	ACR string
	// Groups is the ID token's `groups` claim (directory group names).
	Groups []string
	// Username is the ID token's `preferred_username` (OIDC providers only):
	// the name chosen at the IdP, which seeds a new account's handle. Never
	// used to find an account.
	Username string
	// AuthTime is the ID token's `auth_time`: when the person last actually
	// authenticated at the IdP (zero when absent). A remembered browser is
	// minted only from a fresh one.
	AuthTime time.Time
	// Claims is every claim of the ID token (OIDC providers only; nil for
	// the GitHub shim), for a reader of an IdP's own claims: the
	// deployment's directory sends some, which the registry reads from its
	// token alone (the API's directory claims), and an extension reads
	// through the sign-in hook.
	Claims map[string]any
}

// MFAAsserted reports whether AMR names a second factor, by the rule the
// organization OIDC callback shares (oidcrp.AMRNamesSecondFactor).
func (id *Identity) MFAAsserted() bool {
	return oidcrp.AMRNamesSecondFactor(id.AMR)
}

// Config configures one provider. The URL overrides exist so tests can point
// a provider at an in-process server; production leaves them empty
// and gets the real endpoints.
type Config struct {
	ClientID     string
	ClientSecret string
	// Issuer overrides the OIDC issuer (google).
	Issuer string
	// AuthURL/TokenURL/APIBaseURL override the OAuth2 shim endpoints (github).
	AuthURL    string
	TokenURL   string
	APIBaseURL string
	Scopes     []string
	// HTTPClient is used for discovery, token exchange, and API calls.
	HTTPClient *http.Client
}

// Provider is a configured social login provider.
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
	case ProviderGoogle:
		return newOIDC(ctx, ProviderGoogle, googleIssuer, cfg, redirectURL)
	case ProviderMicrosoft:
		return newOIDC(ctx, ProviderMicrosoft, microsoftIssuer, cfg, redirectURL)
	case ProviderOpenAI:
		// OpenAI and Claude publish no fixed consumer sign-in endpoints, so
		// there are no baked-in defaults: the operator points the provider
		// at an OIDC issuer, or it stays unconfigured and is not offered.
		return newOIDC(ctx, ProviderOpenAI, "", cfg, redirectURL)
	case ProviderClaude:
		return newOIDC(ctx, ProviderClaude, "", cfg, redirectURL)
	case ProviderAuthentik:
		// The stack's own directory service. No default issuer:
		// every deployment's Authentik lives at its own URL. It is also the
		// one provider asked for the agentry scope (ScopeAgentry).
		if len(cfg.Scopes) == 0 {
			cfg.Scopes = []string{coreoidc.ScopeOpenID, "email", "profile", ScopeAgentry}
		}
		return newOIDC(ctx, ProviderAuthentik, "", cfg, redirectURL)
	case ProviderOIDC:
		// Whatever issuer the operator names, asked for the scopes they
		// configured or the standard three.
		return newOIDC(ctx, ProviderOIDC, "", cfg, redirectURL)
	case ProviderGitHub:
		return newGitHub(cfg, redirectURL), nil
	default:
		return nil, fmt.Errorf("social: unknown provider %q", name)
	}
}

// Startable reports whether a provider's settings are enough for New to build
// it: a client id and secret, and an issuer for an OIDC provider that has no
// default endpoints (openai, claude, authentik, oidc). It needs no network, so it
// can answer for a provider whose issuer is down; New can still fail then.
func Startable(name string, cfg Config) bool {
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return false
	}
	switch name {
	case ProviderGoogle, ProviderMicrosoft, ProviderGitHub:
		return true
	case ProviderOpenAI, ProviderClaude, ProviderAuthentik, ProviderOIDC:
		return cfg.Issuer != ""
	default:
		return false
	}
}

// ---- OIDC proper (google, microsoft, and any operator-configured issuer) ----

const (
	googleIssuer    = "https://accounts.google.com"
	microsoftIssuer = "https://login.microsoftonline.com/common/v2.0"
)

// oidcProvider is a standard OpenID Connect relying party, good for any
// issuer with a discovery document: Google and Microsoft by default, and
// OpenAI or Claude when an operator points one at an OIDC issuer.
type oidcProvider struct {
	name string
	rp   *oidcrp.RP
	// client is Config.HTTPClient, nil for the default. Discovery used it
	// through New's context; the token exchange runs on the request's
	// context and needs it passed again, or it quietly falls back to the
	// default client.
	client *http.Client
}

func newOIDC(ctx context.Context, name, defaultIssuer string, cfg Config, redirectURL string) (Provider, error) {
	issuer := cfg.Issuer
	if issuer == "" {
		issuer = defaultIssuer
	}
	if issuer == "" {
		return nil, fmt.Errorf("social: %s has no default endpoints; configure an issuer or leave it unoffered", name)
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

// ---- github (OAuth2 shim) ----

const (
	githubAuthURL  = "https://github.com/login/oauth/authorize"
	githubTokenURL = "https://github.com/login/oauth/access_token"
	githubAPIBase  = "https://api.github.com"
)

type githubProvider struct {
	oauth   *oauth2.Config
	apiBase string
	client  *http.Client
}

func newGitHub(cfg Config, redirectURL string) Provider {
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"read:user", "user:email"}
	}
	authURL, tokenURL, apiBase := cfg.AuthURL, cfg.TokenURL, cfg.APIBaseURL
	if authURL == "" {
		authURL = githubAuthURL
	}
	if tokenURL == "" {
		tokenURL = githubTokenURL
	}
	if apiBase == "" {
		apiBase = githubAPIBase
	}
	client := cfg.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	return &githubProvider{
		oauth: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     oauth2.Endpoint{AuthURL: authURL, TokenURL: tokenURL, AuthStyle: oauth2.AuthStyleInParams},
			RedirectURL:  redirectURL,
			Scopes:       scopes,
		},
		apiBase: strings.TrimRight(apiBase, "/"),
		client:  client,
	}
}

func (p *githubProvider) Name() string { return ProviderGitHub }

// UsesPKCE is false: GitHub's OAuth app flow does not implement PKCE. The
// state cookie (sealed, single-use) is what binds the callback to the browser
// that started it, and the client secret is what binds the code exchange to
// this server.
func (p *githubProvider) UsesPKCE() bool { return false }

func (p *githubProvider) AuthURL(state, _, _ string) string {
	return p.oauth.AuthCodeURL(state)
}

func (p *githubProvider) Exchange(ctx context.Context, code, _, _ string) (*Identity, error) {
	ctx = context.WithValue(ctx, oauth2.HTTPClient, p.client)
	tok, err := p.oauth.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("social: github code exchange: %w", err)
	}
	if tok.AccessToken == "" {
		return nil, fmt.Errorf("social: github returned no access token")
	}

	var user struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
		Name  string `json:"name"`
	}
	if err := p.get(ctx, tok.AccessToken, "/user", &user); err != nil {
		return nil, err
	}
	if user.ID == 0 {
		return nil, fmt.Errorf("social: github user response has no id")
	}
	sub := strconv.FormatInt(user.ID, 10)
	id := &Identity{
		Provider:          ProviderGitHub,
		Subject:           sub,
		NamespacedSubject: ProviderGitHub + ":" + sub,
		DisplayName:       firstNonEmpty(user.Name, user.Login),
	}

	// Email: primary AND verified only. A GitHub account can carry several
	// addresses in any verification state; treating an unverified one as
	// proof of ownership is precisely the account-takeover path this closes.
	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := p.get(ctx, tok.AccessToken, "/user/emails", &emails); err == nil {
		for _, e := range emails {
			if e.Primary && e.Verified && e.Email != "" {
				id.Email = strings.ToLower(strings.TrimSpace(e.Email))
				id.EmailVerified = true
				break
			}
		}
	}
	return id, nil
}

func (p *githubProvider) get(ctx context.Context, token, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.apiBase+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "agentry")
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("social: github %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("social: github %s: %w", path, err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("social: github %s: status %d", path, resp.StatusCode)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("social: github %s: decode: %w", path, err)
	}
	return nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
