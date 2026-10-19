package social

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc/oidctest"
)

// idp is an in-process TLS OpenID provider: discovery, keys and a token
// endpoint that signs an ID token with the claims it is given. Its server
// certificate is trusted only by its own client, so a provider that did not
// use the configured HTTP client could not reach it.
type idp struct {
	srv    *httptest.Server
	key    *rsa.PrivateKey
	claims map[string]any // merged over the standard claims

	mu       sync.Mutex
	tokenReq url.Values // the form of the last token request
	user     string     // its basic-auth user and password, when sent
	pass     string
}

// lastCredentials is the client id and secret the last token request carried,
// in its basic-auth header or its form.
func (p *idp) lastCredentials() (id, secret string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	id, secret = p.user, p.pass
	if id == "" {
		id = p.tokenReq.Get("client_id")
	}
	if secret == "" {
		secret = p.tokenReq.Get("client_secret")
	}
	return id, secret
}

const idpClient, idpSecret, idpCode = "client-abc", "s3cret", "auth-code-1"

// One signing key serves every fake provider of the package's tests.
var sharedKey = sync.OnceValues(func() (*rsa.PrivateKey, error) { return rsa.GenerateKey(rand.Reader, 2048) })

func newIDP(t *testing.T) *idp {
	t.Helper()
	key, err := sharedKey()
	if err != nil {
		t.Fatal(err)
	}
	p := &idp{key: key, claims: map[string]any{}}
	mux := http.NewServeMux()
	write := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		write(w, map[string]any{
			"issuer": p.srv.URL, "authorization_endpoint": p.srv.URL + "/authorize",
			"token_endpoint": p.srv.URL + "/token", "jwks_uri": p.srv.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		write(w, map[string]any{"keys": []map[string]any{{
			"kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		p.mu.Lock()
		p.tokenReq = r.PostForm
		p.user, p.pass, _ = r.BasicAuth()
		p.mu.Unlock()
		if r.FormValue("code") != idpCode || r.FormValue("code_verifier") == "" {
			http.Error(w, "bad code", http.StatusBadRequest)
			return
		}
		claims := map[string]any{
			"iss": p.srv.URL, "aud": idpClient, "sub": "subject-42",
			"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
			"nonce": "nonce-1", "email": "person@acme.example", "email_verified": true,
		}
		for k, v := range p.claims {
			claims[k] = v
		}
		cb, _ := json.Marshal(claims)
		write(w, map[string]any{
			"access_token": "at", "token_type": "Bearer", "expires_in": 3600,
			"id_token": oidctest.SignIDToken(key, "k1", "RS256", string(cb)),
		})
	})
	p.srv = httptest.NewTLSServer(mux)
	t.Cleanup(p.srv.Close)
	return p
}

func (p *idp) config() Config {
	return Config{ClientID: idpClient, ClientSecret: idpSecret, Issuer: p.srv.URL, HTTPClient: p.srv.Client()}
}

// TestProvidersIsTheOneOpenIDProvider pins the provider list: the ids the
// start/callback routes accept, which are the one sign-in OpenID provider
// under either of its two ids. Adding a provider is a deliberate change, not
// a drive-by.
func TestProvidersIsTheOneOpenIDProvider(t *testing.T) {
	if ProviderAuthentik != "authentik" || ProviderOIDC != "oidc" {
		t.Fatalf("provider ids are %q and %q, want authentik and oidc: accounts are linked under them", ProviderAuthentik, ProviderOIDC)
	}
	want := []string{ProviderAuthentik, ProviderOIDC}
	got := Providers()
	if len(got) != len(want) {
		t.Fatalf("Providers() = %v, want %v", got, want)
	}
	for i, w := range want {
		if got[i] != w {
			t.Fatalf("Providers()[%d] = %q, want %q", i, got[i], w)
		}
	}
}

// TestAProviderNeedsAnIssuer: the provider has no default endpoints, so a
// configured client without an issuer is a configuration error, surfaced at
// provider construction and by Startable.
func TestAProviderNeedsAnIssuer(t *testing.T) {
	for _, name := range Providers() {
		if Startable(name, Config{ClientID: "id", ClientSecret: "secret"}) {
			t.Errorf("%s without an issuer is startable", name)
		}
		_, err := New(context.Background(), name, Config{
			ClientID: "id", ClientSecret: "secret",
		}, "https://registry.example/cb")
		if err == nil {
			t.Errorf("%s without an issuer must fail to construct", name)
		} else if !strings.Contains(err.Error(), "has no issuer") {
			t.Errorf("%s without an issuer: %v, want the no-issuer error", name, err)
		}
	}

	// Startable wants all three settings, and neither it nor New builds a
	// provider from fewer: the missing client id or secret is reported as
	// an unconfigured provider before any network is touched.
	for _, name := range Providers() {
		full := Config{ClientID: "id", ClientSecret: "secret", Issuer: "https://issuer.example"}
		if !Startable(name, full) {
			t.Errorf("%s with a client id, a secret and an issuer is not startable", name)
		}
		for what, cfg := range map[string]Config{
			"no client id": {ClientSecret: "secret", Issuer: "https://issuer.example"},
			"no secret":    {ClientID: "id", Issuer: "https://issuer.example"},
			"no issuer":    {ClientID: "id", ClientSecret: "secret"},
			"nothing":      {},
			"id only":      {ClientID: "id"},
			"secret only":  {ClientSecret: "secret"},
			"issuer only":  {Issuer: "https://issuer.example"},
		} {
			if Startable(name, cfg) {
				t.Errorf("%s with %s is startable", name, what)
			}
		}
		for what, cfg := range map[string]Config{
			"no client id": {ClientSecret: "secret", Issuer: "https://issuer.example"},
			"no secret":    {ClientID: "id", Issuer: "https://issuer.example"},
			"nothing":      {},
		} {
			if _, err := New(context.Background(), name, cfg, "https://registry.example/cb"); err == nil || !strings.Contains(err.Error(), "is not configured") {
				t.Errorf("%s with %s: %v, want the not-configured error", name, what, err)
			}
		}
	}
}

// TestRetiredProvidersAreUnknown: the individual social providers the
// server once had are not providers any more, whatever their settings.
func TestRetiredProvidersAreUnknown(t *testing.T) {
	cfg := Config{ClientID: "id", ClientSecret: "secret", Issuer: "https://issuer.example"}
	for _, name := range []string{"google", "github", "microsoft", "openai", "claude"} {
		if Startable(name, cfg) {
			t.Errorf("%s is startable", name)
		}
		if _, err := New(context.Background(), name, cfg, "https://registry.example/cb"); err == nil {
			t.Errorf("%s constructs", name)
		} else if !strings.Contains(err.Error(), "unknown provider") {
			t.Errorf("%s: %v, want an unknown-provider error (not a failed discovery)", name, err)
		}
	}
	for _, name := range []string{"", "OIDC", "Authentik", " oidc", "oidc ", "oidc2"} {
		if Startable(name, cfg) {
			t.Errorf("%q is startable", name)
		}
		if _, err := New(context.Background(), name, cfg, "https://registry.example/cb"); err == nil || !strings.Contains(err.Error(), "unknown provider") {
			t.Errorf("%q: %v, want an unknown-provider error", name, err)
		}
	}
}

// A provider built under either id signs a person in through the configured
// issuer, using the configured HTTP client for discovery, the token exchange
// and the keys, and asserts the person as the ID token states them, under the
// provider's own id.
func TestProviderSignsInThroughTheConfiguredIssuer(t *testing.T) {
	const verifier = "verifier-abcdefabcdefabcdefabcdefabcdef1234"
	for _, name := range Providers() {
		t.Run(name, func(t *testing.T) {
			idp := newIDP(t)
			idp.claims["amr"] = []string{"pwd", "otp"}
			idp.claims["acr"] = "urn:mfa"
			idp.claims["groups"] = []string{"staff"}
			idp.claims["preferred_username"] = " ada "
			idp.claims["auth_time"] = 1_790_000_000
			idp.claims["x_custom"] = "kept"
			// A context with no client: only the configuration carries it.
			p, err := New(context.Background(), name, idp.config(), "https://registry.example/cb")
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if p.Name() != name || !p.UsesPKCE() {
				t.Errorf("Name() = %q, UsesPKCE() = %v, want %q and true", p.Name(), p.UsesPKCE(), name)
			}
			u, err := url.Parse(p.AuthURL("state-1", "nonce-1", verifier))
			if err != nil {
				t.Fatal(err)
			}
			q := u.Query()
			for k, want := range map[string]string{
				"client_id": idpClient, "redirect_uri": "https://registry.example/cb", "state": "state-1",
				"nonce": "nonce-1", "scope": "openid email profile", "response_type": "code", "code_challenge_method": "S256",
			} {
				if got := q.Get(k); got != want {
					t.Errorf("auth url %s = %q, want %q", k, got, want)
				}
			}
			if !strings.HasPrefix(u.String(), idp.srv.URL+"/authorize?") || q.Get("code_challenge") == "" {
				t.Errorf("auth url = %s, want the discovered endpoint with a PKCE challenge", u)
			}

			id, err := p.Exchange(context.Background(), idpCode, verifier, "nonce-1")
			if err != nil {
				t.Fatalf("Exchange: %v", err)
			}
			want := Identity{
				Provider: name, Subject: "subject-42", NamespacedSubject: name + ":subject-42",
				Email: "person@acme.example", EmailVerified: true,
				AMR: []string{"pwd", "otp"}, ACR: "urn:mfa", Groups: []string{"staff"},
				Username: "ada", AuthTime: time.Unix(1_790_000_000, 0),
			}
			if gotID, gotSecret := idp.lastCredentials(); gotID != idpClient || gotSecret != idpSecret {
				t.Errorf("the token request carried client %q and secret %q, want the configured ones", gotID, gotSecret)
			}
			if got := idp.tokenReq.Get("redirect_uri"); got != "https://registry.example/cb" {
				t.Errorf("the token request named redirect %q, want the one the provider was built with", got)
			}
			gotClaims := id.Claims
			id.Claims = nil
			if !reflect.DeepEqual(*id, want) {
				t.Errorf("identity = %+v, want %+v", *id, want)
			}
			if gotClaims["x_custom"] != "kept" || gotClaims["sub"] != "subject-42" {
				t.Errorf("claims = %v, want every claim of the token", gotClaims)
			}

			// The nonce and the code are held to what the sign-in started with.
			if _, err := p.Exchange(context.Background(), idpCode, verifier, "another-nonce"); err == nil || !strings.Contains(err.Error(), "nonce mismatch") {
				t.Errorf("a wrong nonce: %v, want a nonce mismatch", err)
			}
			if _, err := p.Exchange(context.Background(), "another-code", verifier, "nonce-1"); err == nil {
				t.Error("a code the provider refuses was accepted")
			}
			if _, err := p.Exchange(context.Background(), idpCode, "", "nonce-1"); err == nil {
				t.Error("an exchange without a PKCE verifier was accepted")
			}
		})
	}

	t.Run("configured scopes", func(t *testing.T) {
		idp := newIDP(t)
		cfg := idp.config()
		cfg.Scopes = []string{"openid", "groups"}
		p, err := New(context.Background(), ProviderOIDC, cfg, "https://registry.example/cb")
		if err != nil {
			t.Fatal(err)
		}
		u, err := url.Parse(p.AuthURL("s", "n", verifier))
		if err != nil {
			t.Fatal(err)
		}
		if got := u.Query().Get("scope"); got != "openid groups" {
			t.Errorf("scope = %q, want the configured scopes", got)
		}
	})

	t.Run("an unverified address stays unverified", func(t *testing.T) {
		idp := newIDP(t)
		idp.claims["email_verified"] = false
		p, err := New(context.Background(), ProviderOIDC, idp.config(), "https://registry.example/cb")
		if err != nil {
			t.Fatal(err)
		}
		id, err := p.Exchange(context.Background(), idpCode, verifier, "nonce-1")
		if err != nil {
			t.Fatal(err)
		}
		if id.EmailVerified || id.Email != "person@acme.example" {
			t.Errorf("identity = %+v, want the address as sent and not verified", *id)
		}
	})

	t.Run("a token for another client is refused", func(t *testing.T) {
		idp := newIDP(t)
		idp.claims["aud"] = "another-client"
		p, err := New(context.Background(), ProviderOIDC, idp.config(), "https://registry.example/cb")
		if err != nil {
			t.Fatal(err)
		}
		if id, err := p.Exchange(context.Background(), idpCode, verifier, "nonce-1"); err == nil {
			t.Fatalf("a token for another client was accepted: %+v", id)
		}
	})

	t.Run("another issuer than the configured one is refused", func(t *testing.T) {
		idp := newIDP(t)
		cfg := idp.config()
		cfg.Issuer += "/other"
		if _, err := New(context.Background(), ProviderOIDC, cfg, "https://registry.example/cb"); err == nil {
			t.Fatal("a provider was built for an issuer the discovery document does not name")
		}
	})
}

// Only the relying party's rule makes an identity a second-factor sign-in: an
// authentication-method list that names one, not its absence and not a class.
func TestIdentityMFAAsserted(t *testing.T) {
	for name, tc := range map[string]struct {
		id   Identity
		want bool
	}{
		"no claims":             {Identity{}, false},
		"password only":         {Identity{AMR: []string{"pwd"}}, false},
		"password and a code":   {Identity{AMR: []string{"pwd", "otp"}}, true},
		"mfa":                   {Identity{AMR: []string{"MFA"}}, true},
		"hardware key":          {Identity{AMR: []string{"hwk"}}, true},
		"a class and no method": {Identity{ACR: "mfa"}, false},
		"a class and password":  {Identity{AMR: []string{"pwd"}, ACR: "otp"}, false},
		"a group named mfa":     {Identity{Groups: []string{"mfa"}}, false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := tc.id.MFAAsserted(); got != tc.want {
				t.Fatalf("MFAAsserted() = %v, want %v", got, tc.want)
			}
		})
	}
}
