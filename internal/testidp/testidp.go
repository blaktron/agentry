// Package testidp is a stand-in OpenID provider for tests: discovery, a
// signing key, an authorization endpoint and a token endpoint that hold a
// relying party to the parts of the protocol the registry depends on (the
// registered client, PKCE, single-use codes, the nonce), and sign real ID
// tokens for whoever a test says is signing in. A test signs people in
// through it the way a deployment's own OpenID provider would, with no
// directory and no password anywhere.
package testidp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc/oidctest"
)

// Person is who the next sign-in is for, and what the ID token says of
// them.
type Person struct {
	// Subject is the token's `sub`.
	Subject string
	// Email and EmailVerified are `email` and `email_verified`.
	Email         string
	EmailVerified bool
	// Username is `preferred_username`, omitted when empty.
	Username string
	// AMR is `amr`, omitted when nil.
	AMR []string
	// AuthTime is `auth_time`, omitted when zero.
	AuthTime time.Time
	// Claims ride the token as given, over the ones above.
	Claims map[string]any
}

// IdP is one running stand-in provider. Its issuer is URL; the registry is
// registered as ClientID with ClientSecret.
type IdP struct {
	URL          string
	ClientID     string
	ClientSecret string

	srv *httptest.Server
	key *rsa.PrivateKey

	mu    sync.Mutex
	next  Person
	codes map[string]grant
}

// grant is what an authorization code stands for until it is redeemed.
type grant struct {
	person      Person
	nonce       string
	challenge   string
	redirectURI string
}

// New starts a provider for the test's lifetime.
func New(t testing.TB) *IdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &IdP{ClientID: "testidp-client", ClientSecret: "testidp-secret-" + randHex(8), key: key, codes: map[string]grant{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("GET /jwks", p.jwks)
	mux.HandleFunc("GET /authorize", p.authorize)
	mux.HandleFunc("POST /token", p.token)
	p.srv = httptest.NewServer(mux)
	p.URL = p.srv.URL
	t.Cleanup(p.srv.Close)
	return p
}

// SignInAs makes person the one the next authorization is for.
func (p *IdP) SignInAs(person Person) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.next = person
}

// Client reaches the provider; hand it to the relying party for discovery
// and the code exchange.
func (p *IdP) Client() *http.Client { return p.srv.Client() }

// Authorize is the browser's visit to the authorization URL the relying
// party redirected to: it returns the code and the state the provider
// sends back to the redirect URI, for the person SignInAs named. An
// authorization the provider refuses fails the test.
func (p *IdP) Authorize(t testing.TB, authURL string) (code, state string) {
	t.Helper()
	client := *p.srv.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res, err := client.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("testidp: authorize answered %d", res.StatusCode)
	}
	loc, err := url.Parse(res.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return loc.Query().Get("code"), loc.Query().Get("state")
}

func (p *IdP) discovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                p.URL,
		"authorization_endpoint":                p.URL + "/authorize",
		"token_endpoint":                        p.URL + "/token",
		"jwks_uri":                              p.URL + "/jwks",
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"code_challenge_methods_supported":      []string{"S256"},
	})
}

func (p *IdP) jwks(w http.ResponseWriter, _ *http.Request) {
	n := base64.RawURLEncoding.EncodeToString(p.key.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(p.key.E)).Bytes())
	writeJSON(w, http.StatusOK, map[string]any{"keys": []map[string]any{
		{"kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig", "n": n, "e": e},
	}})
}

// authorize issues a code for the next person to the client's redirect
// URI. It refuses another client, a response type other than code, and a
// request without an S256 PKCE challenge.
func (p *IdP) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	redirect := q.Get("redirect_uri")
	if q.Get("client_id") != p.ClientID || q.Get("response_type") != "code" || redirect == "" ||
		q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		http.Error(w, "testidp: not an authorization request this provider accepts", http.StatusBadRequest)
		return
	}
	code := randHex(16)
	p.mu.Lock()
	p.codes[code] = grant{person: p.next, nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), redirectURI: redirect}
	p.mu.Unlock()
	to, err := url.Parse(redirect)
	if err != nil {
		http.Error(w, "testidp: bad redirect_uri", http.StatusBadRequest)
		return
	}
	v := to.Query()
	v.Set("code", code)
	v.Set("state", q.Get("state"))
	to.RawQuery = v.Encode()
	http.Redirect(w, r, to.String(), http.StatusFound)
}

// token redeems a code once, for the client that holds the secret, with
// the PKCE verifier the challenge was made from, and answers with an ID
// token for the person the code was issued for.
func (p *IdP) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "testidp: bad form", http.StatusBadRequest)
		return
	}
	id, secret, ok := r.BasicAuth()
	if !ok {
		id, secret = r.PostFormValue("client_id"), r.PostFormValue("client_secret")
	}
	if id != p.ClientID || secret != p.ClientSecret {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}
	code := r.PostFormValue("code")
	p.mu.Lock()
	g, found := p.codes[code]
	delete(p.codes, code)
	p.mu.Unlock()
	sum := sha256.Sum256([]byte(r.PostFormValue("code_verifier")))
	if !found || r.PostFormValue("grant_type") != "authorization_code" || r.PostFormValue("redirect_uri") != g.redirectURI ||
		base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}
	now := time.Now()
	claims := map[string]any{
		"iss": p.URL, "aud": p.ClientID, "sub": g.person.Subject,
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		"email": g.person.Email, "email_verified": g.person.EmailVerified,
	}
	if g.nonce != "" {
		claims["nonce"] = g.nonce
	}
	if g.person.Username != "" {
		claims["preferred_username"] = g.person.Username
	}
	if g.person.AMR != nil {
		claims["amr"] = g.person.AMR
	}
	if !g.person.AuthTime.IsZero() {
		claims["auth_time"] = g.person.AuthTime.Unix()
	}
	for k, v := range g.person.Claims {
		claims[k] = v
	}
	raw, err := json.Marshal(claims)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": "at-" + randHex(8), "token_type": "Bearer", "expires_in": 3600,
		"id_token": oidctest.SignIDToken(p.key, "k1", "RS256", string(raw)),
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
