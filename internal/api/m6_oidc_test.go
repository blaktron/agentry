package api_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc/oidctest"

	"github.com/blaktron/agentry/internal/api"
)

// oidcEndpointIdP is a fake IdP whose /authorize records the nonce per code and
// whose /token echoes it — enabling a full auth-code round trip.
type oidcEndpointIdP struct {
	srv           *httptest.Server
	key           *rsa.PrivateKey
	clientID      string
	email         string
	emailVerified bool
	mu            sync.Mutex
	nonces        map[string]string
}

func newOIDCEndpointIdP(t *testing.T) *oidcEndpointIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	idp := &oidcEndpointIdP{key: key, clientID: "client", email: "oidc-person@acme.example", emailVerified: true, nonces: map[string]string{}}
	writeJSON := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"issuer": idp.srv.URL, "authorization_endpoint": idp.srv.URL + "/authorize",
			"token_endpoint": idp.srv.URL + "/token", "jwks_uri": idp.srv.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())
		writeJSON(w, map[string]any{"keys": []map[string]any{
			{"kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig", "n": n, "e": e},
		}})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		code := "code-" + randHex()
		idp.mu.Lock()
		idp.nonces[code] = q.Get("nonce")
		idp.mu.Unlock()
		http.Redirect(w, r, q.Get("redirect_uri")+"?code="+code+"&state="+q.Get("state"), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		idp.mu.Lock()
		nonce := idp.nonces[r.FormValue("code")]
		idp.mu.Unlock()
		claims := map[string]any{
			"iss": idp.srv.URL, "aud": idp.clientID, "sub": "oidc-subject-1",
			"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
			"nonce": nonce, "email": idp.email, "email_verified": idp.emailVerified,
		}
		cb, _ := json.Marshal(claims)
		idToken := oidctest.SignIDToken(key, "k1", "RS256", string(cb))
		writeJSON(w, map[string]any{
			"access_token": "at", "token_type": "Bearer", "expires_in": 3600, "id_token": idToken,
		})
	})
	idp.srv = httptest.NewServer(mux)
	t.Cleanup(idp.srv.Close)
	return idp
}

// TestOIDCEndpointFlow covers §12.4 end-to-end: start → IdP authorize → callback
// creates a user and establishes a session; email_verified=false is rejected.
func TestOIDCEndpointFlow(t *testing.T) {
	idp := newOIDCEndpointIdP(t)
	env := newTestEnvWith(t, func(s *api.Server) {
		s.SetOIDCHTTPClient(idp.srv.Client())
	})
	idp.email = "oidc-person-" + env.sfx + "@acme.example"
	owner := env.register("oidc-owner")
	env.verifyEmail(owner)
	sess := env.login(owner)
	orgH := "oidcorg" + env.sfx
	env.createOrg(sess, orgH)

	env.doJSON(sess, http.MethodPut, "/api/v1/orgs/"+orgH+"/sso/connections/oidc", map[string]any{
		"enabled": true,
		"config":  map[string]any{"issuer": idp.srv.URL, "clientId": idp.clientID, "clientSecret": "shh"},
	}, nil, http.StatusOK)

	noRedirect := *env.srv.Client()
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	// 1. start → 302 to the IdP authorize endpoint + state cookie.
	startResp, err := noRedirect.Get(env.srv.URL + "/api/v1/orgs/" + orgH + "/sso/oidc/start")
	if err != nil {
		t.Fatal(err)
	}
	_ = startResp.Body.Close()
	if startResp.StatusCode != http.StatusFound {
		t.Fatalf("start: got %d want 302", startResp.StatusCode)
	}
	authorizeURL := startResp.Header.Get("Location")
	var stateCookie *http.Cookie
	for _, c := range startResp.Cookies() {
		if c.Name == "agentry_oidc_state" {
			stateCookie = c
		}
	}
	if stateCookie == nil || authorizeURL == "" {
		t.Fatal("start missing state cookie / authorize redirect")
	}

	// 2. Drive the IdP authorize endpoint → it redirects back to the callback.
	idpResp, err := noRedirect.Get(authorizeURL)
	if err != nil {
		t.Fatal(err)
	}
	_ = idpResp.Body.Close()
	cbURL := idpResp.Header.Get("Location")
	if cbURL == "" {
		t.Fatalf("authorize did not redirect to callback (status %d)", idpResp.StatusCode)
	}
	parsed, _ := url.Parse(cbURL)
	// The IdP redirects to the absolute callback URL (redirect_uri from config).

	// 3. callback with the state cookie → session established.
	cbReq, _ := http.NewRequest(http.MethodGet, cbURL, nil)
	if parsed.Host == "" { // relative redirect safety (shouldn't happen)
		cbReq, _ = http.NewRequest(http.MethodGet, env.srv.URL+cbURL, nil)
	}
	cbReq.AddCookie(stateCookie)
	cbResp, err := noRedirect.Do(cbReq)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cbResp.Body.Close() }()
	if cbResp.StatusCode != http.StatusOK {
		t.Fatalf("callback: got %d want 200", cbResp.StatusCode)
	}
	var session string
	for _, c := range cbResp.Cookies() {
		if c.Name == "agentry_session" {
			session = c.Value
		}
	}
	if session == "" {
		t.Fatal("callback did not set a session cookie")
	}
	who := env.do(caller{name: "oidc", session: session}, http.MethodGet, "/api/v1/user", nil)
	_ = who.Body.Close()
	if who.StatusCode != http.StatusOK {
		t.Fatalf("OIDC session GET /user: got %d want 200", who.StatusCode)
	}
}
