// Package social implements social login for individual accounts (§12.1
// "Social/OIDC login (GitHub, Google) — linked via identities; no password
// required"). It is deliberately separate from internal/auth/oidc, which
// serves per-org enterprise SSO (§12.4): the two flows differ in who they
// admit (anyone with an account at the provider vs. members of one org's
// IdP), what they grant (an individual session vs. org membership with an
// SSO freshness tag), and how they are configured (server-wide vs. per org).
//
// v1 ships two providers:
//
//	google — OpenID Connect proper, through the same RP as enterprise OIDC
//	         (discovery, issuer pinning, PKCE, id_token verification).
//	github — an OAuth 2.0 shim. GitHub is NOT an OIDC issuer: it publishes no
//	         discovery document and returns no id_token, so there is nothing
//	         to verify a signature over. The shim exchanges the code and then
//	         asks the API who the token belongs to, taking the identity from
//	         GitHub's answer over an authenticated channel. Email comes from
//	         /user/emails and is accepted ONLY when GitHub reports it primary
//	         AND verified — an unverified provider email must never satisfy
//	         the T-12 auto-link rule.
package social

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	oidcrp "github.com/PLACEHOLDER_ORG/agentry/internal/auth/oidc"
)

// Provider ids (§12.1). Closed set: an unknown id is a 404, never a guess.
const (
	ProviderGoogle = "google"
	ProviderGitHub = "github"
)

// Providers lists the supported provider ids.
func Providers() []string { return []string{ProviderGoogle, ProviderGitHub} }

// Known reports whether name is a supported provider id.
func Known(name string) bool {
	for _, p := range Providers() {
		if p == name {
			return true
		}
	}
	return false
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
}

// Config configures one provider. The URL overrides exist so tests can point
// a provider at an in-process server (DEV-009); production leaves them empty
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
		return newGoogle(ctx, cfg, redirectURL)
	case ProviderGitHub:
		return newGitHub(cfg, redirectURL), nil
	default:
		return nil, fmt.Errorf("social: unknown provider %q", name)
	}
}

// ---- google (OIDC proper) ----

const googleIssuer = "https://accounts.google.com"

type googleProvider struct{ rp *oidcrp.RP }

func newGoogle(ctx context.Context, cfg Config, redirectURL string) (Provider, error) {
	issuer := cfg.Issuer
	if issuer == "" {
		issuer = googleIssuer
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
	return &googleProvider{rp: rp}, nil
}

func (p *googleProvider) Name() string   { return ProviderGoogle }
func (p *googleProvider) UsesPKCE() bool { return true }

func (p *googleProvider) AuthURL(state, nonce, verifier string) string {
	return p.rp.AuthURL(state, nonce, verifier)
}

func (p *googleProvider) Exchange(ctx context.Context, code, verifier, nonce string) (*Identity, error) {
	claims, err := p.rp.Exchange(ctx, code, verifier, nonce)
	if err != nil {
		return nil, err
	}
	return &Identity{
		Provider:          ProviderGoogle,
		Subject:           claims.Subject,
		NamespacedSubject: ProviderGoogle + ":" + claims.Subject,
		Email:             claims.Email,
		EmailVerified:     claims.EmailVerified,
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
	// proof of ownership is precisely the account-takeover path T-12 closes.
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
