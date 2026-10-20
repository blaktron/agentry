package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/coreos/go-oidc/v3/oidc/oidctest"
)

// fakeIDP is an in-process OIDC provider: discovery + JWKS + a token endpoint
// that mints a signed ID token.
type fakeIDP struct {
	srv            *httptest.Server
	key            *rsa.PrivateKey
	keyID          string
	clientID       string
	sub            string
	email          string
	emailVerified  bool
	nonce          string
	code           string
	issuerOverride string         // discovery reports this issuer (for issuer-pin test)
	preferredUser  string         // rides the ID token as preferred_username when set
	extra          map[string]any // more claims for the ID token, set as given

	// What the token endpoint hands out, when it should not be a clean token.
	aud          any           // the aud claim; the client id when nil
	tokenIssuer  string        // the iss claim; the discovered issuer when empty
	expiresIn    time.Duration // the token's lifetime; an hour when zero (negative: already expired)
	signWith     *rsa.PrivateKey
	noIDToken    bool // the token response carries no id_token
	emptyIDToken bool // the token response carries "id_token": ""

	// What the token endpoint was asked, for the last request.
	mu       sync.Mutex
	form     url.Values
	basicID  string
	basicSec string
	hasBasic bool
}

func (idp *fakeIDP) lastTokenRequest() (url.Values, string, string, bool) {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	return idp.form, idp.basicID, idp.basicSec, idp.hasBasic
}

// The provider's signing key is generated once: every fake provider uses it,
// and the tests that need a second key make their own.
var sharedKey = sync.OnceValues(func() (*rsa.PrivateKey, error) { return rsa.GenerateKey(rand.Reader, 2048) })

func newFakeIDP(t *testing.T) *fakeIDP {
	t.Helper()
	key, err := sharedKey()
	if err != nil {
		t.Fatal(err)
	}
	idp := &fakeIDP{
		key: key, keyID: "test-key-1", clientID: "client-abc",
		sub: "idp-subject-1", email: "person@acme.example", emailVerified: true,
		nonce: "nonce-xyz", code: "auth-code-1",
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		iss := idp.srv.URL
		if idp.issuerOverride != "" {
			iss = idp.issuerOverride
		}
		writeJSON(w, map[string]any{
			"issuer":                                iss,
			"authorization_endpoint":                idp.srv.URL + "/authorize",
			"token_endpoint":                        idp.srv.URL + "/token",
			"jwks_uri":                              idp.srv.URL + "/jwks",
			"userinfo_endpoint":                     idp.srv.URL + "/userinfo",
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, jwksFor(key, idp.keyID))
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		idp.mu.Lock()
		idp.form = r.PostForm
		idp.basicID, idp.basicSec, idp.hasBasic = r.BasicAuth()
		idp.mu.Unlock()
		if r.FormValue("code") != idp.code {
			http.Error(w, "bad code", http.StatusBadRequest)
			return
		}
		iss := idp.srv.URL
		if idp.tokenIssuer != "" {
			iss = idp.tokenIssuer
		}
		var aud any = idp.clientID
		if idp.aud != nil {
			aud = idp.aud
		}
		life := time.Hour
		if idp.expiresIn != 0 {
			life = idp.expiresIn
		}
		claims := map[string]any{
			"iss": iss, "aud": aud, "sub": idp.sub,
			"iat": time.Now().Unix(), "exp": time.Now().Add(life).Unix(),
			"nonce": idp.nonce, "email": idp.email, "email_verified": idp.emailVerified,
		}
		if idp.preferredUser != "" {
			claims["preferred_username"] = idp.preferredUser
		}
		for k, v := range idp.extra {
			if _, drop := v.(omitClaim); drop {
				delete(claims, k)
				continue
			}
			claims[k] = v
		}
		cb, _ := json.Marshal(claims)
		signer := idp.key
		if idp.signWith != nil {
			signer = idp.signWith
		}
		idToken := oidctest.SignIDToken(signer, idp.keyID, "RS256", string(cb))
		resp := map[string]any{"access_token": "at-1", "token_type": "Bearer", "expires_in": 3600}
		switch {
		case idp.noIDToken:
		case idp.emptyIDToken:
			resp["id_token"] = ""
		default:
			resp["id_token"] = idToken
		}
		writeJSON(w, resp)
	})
	idp.srv = httptest.NewServer(mux)
	t.Cleanup(idp.srv.Close)
	return idp
}

// omitClaim, as the value of an extra claim, takes the claim out of the token.
type omitClaim struct{}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func jwksFor(key *rsa.PrivateKey, kid string) map[string]any {
	n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())
	return map[string]any{"keys": []map[string]any{
		{"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig", "n": n, "e": e},
	}}
}

func (idp *fakeIDP) ctx() context.Context {
	return coreoidc.ClientContext(context.Background(), idp.srv.Client())
}

func TestOIDC_ExchangeCreatesClaims(t *testing.T) {
	idp := newFakeIDP(t)
	rp, err := New(idp.ctx(), Config{Issuer: idp.srv.URL, ClientID: idp.clientID, ClientSecret: "s3cret"}, idp.srv.URL+"/callback")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// AuthURL must carry PKCE + nonce.
	const verifier = "verifier-abcdefabcdefabcdefabcdefabcdef1234"
	authURL := rp.AuthURL("state-1", idp.nonce, verifier)
	if !strings.Contains(authURL, "code_challenge=") || !strings.Contains(authURL, "nonce=") {
		t.Fatalf("auth url missing pkce/nonce: %s", authURL)
	}
	// No refresh token is ever used, so none is asked for.
	if strings.Contains(authURL, "access_type=") || strings.Contains(authURL, "offline") {
		t.Fatalf("auth url asks for offline access: %s", authURL)
	}
	// The request names this client, this redirect, this state and this
	// nonce, asks for the authorization-code flow with the standard scopes,
	// and its PKCE challenge is the S256 of the verifier.
	au, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(verifier))
	for k, want := range map[string]string{
		"client_id": idp.clientID, "redirect_uri": idp.srv.URL + "/callback", "response_type": "code",
		"state": "state-1", "nonce": idp.nonce, "scope": "openid email profile",
		"code_challenge": base64.RawURLEncoding.EncodeToString(sum[:]), "code_challenge_method": "S256",
	} {
		if got := au.Query().Get(k); got != want {
			t.Errorf("auth url %s = %q, want %q", k, got, want)
		}
	}
	if au.Path != "/authorize" {
		t.Errorf("auth url path = %q, want the discovered /authorize", au.Path)
	}
	claims, err := rp.Exchange(idp.ctx(), idp.code, verifier, idp.nonce)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if claims.Subject != idp.sub || claims.Email != idp.email || !claims.EmailVerified {
		t.Fatalf("unexpected claims: %+v", claims)
	}
	if claims.Issuer != idp.srv.URL {
		t.Errorf("Issuer = %q, want the token's issuer %q", claims.Issuer, idp.srv.URL)
	}
	// The token request proves the code with the PKCE verifier, names the
	// redirect, and authenticates the client with its own id and secret.
	form, user, pass, basic := idp.lastTokenRequest()
	if form.Get("code_verifier") != verifier || form.Get("code") != idp.code || form.Get("grant_type") != "authorization_code" {
		t.Errorf("token request = %v, want the code, its grant type and the PKCE verifier", form)
	}
	if form.Get("redirect_uri") != idp.srv.URL+"/callback" {
		t.Errorf("token request redirect_uri = %q", form.Get("redirect_uri"))
	}
	if gotID := firstNonEmpty(user, form.Get("client_id")); gotID != idp.clientID {
		t.Errorf("token request client id = %q, want %q", gotID, idp.clientID)
	}
	if gotSecret := firstNonEmpty(pass, form.Get("client_secret")); gotSecret != "s3cret" {
		t.Errorf("token request client secret = %q (basic auth %v), want the configured secret", gotSecret, basic)
	}

	// Scopes and redirect: configured scopes replace the standard three, a
	// redirect passed in beats the configured one, and the configured one
	// stands in when none is passed.
	t.Run("configured scopes and redirect", func(t *testing.T) {
		idp := newFakeIDP(t)
		cfg := Config{Issuer: idp.srv.URL, ClientID: idp.clientID, Scopes: []string{"openid", "groups"}, RedirectURL: "https://cfg.example/cb"}
		for name, tc := range map[string]struct{ arg, want string }{
			"configured redirect when none is passed": {"", "https://cfg.example/cb"},
			"the passed redirect wins":                {"https://arg.example/cb", "https://arg.example/cb"},
		} {
			rp, err := New(idp.ctx(), cfg, tc.arg)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			u, err := url.Parse(rp.AuthURL("s", "n", verifier))
			if err != nil {
				t.Fatal(err)
			}
			if got := u.Query().Get("redirect_uri"); got != tc.want {
				t.Errorf("%s: redirect_uri = %q, want %q", name, got, tc.want)
			}
			if got := u.Query().Get("scope"); got != "openid groups" {
				t.Errorf("%s: scope = %q, want the configured scopes", name, got)
			}
		}
	})

	// The authentication-method claims reach the caller as the token sent
	// them: a list, a lone string tolerated, and anything else dropped.
	t.Run("authentication and group claims", func(t *testing.T) {
		for name, tc := range map[string]struct {
			extra             map[string]any
			amr, groups       []string
			amrNil, groupsNil bool
			acr               string
		}{
			"absent":              {map[string]any{"amr": omitClaim{}, "groups": omitClaim{}, "acr": omitClaim{}}, nil, nil, true, true, ""},
			"lists":               {map[string]any{"amr": []any{"pwd", "otp"}, "acr": "urn:mfa", "groups": []any{"staff", "ops"}}, []string{"pwd", "otp"}, []string{"staff", "ops"}, false, false, "urn:mfa"},
			"lone strings":        {map[string]any{"amr": "mfa", "groups": "staff"}, []string{"mfa"}, []string{"staff"}, false, false, ""},
			"empty lone strings":  {map[string]any{"amr": "", "groups": ""}, nil, nil, true, true, ""},
			"empty lists":         {map[string]any{"amr": []any{}, "groups": []any{}}, []string{}, []string{}, false, false, ""},
			"mixed entries":       {map[string]any{"amr": []any{"pwd", 5, "", "otp", nil, true, []any{"x"}}, "groups": []any{"a", 1}}, []string{"pwd", "otp"}, []string{"a"}, false, false, ""},
			"numbers and objects": {map[string]any{"amr": 5, "groups": map[string]any{"a": "b"}}, nil, nil, true, true, ""},
			"null":                {map[string]any{"amr": nil, "groups": nil, "acr": nil}, nil, nil, true, true, ""},
		} {
			t.Run(name, func(t *testing.T) {
				idp := newFakeIDP(t)
				idp.extra = tc.extra
				rp, err := New(idp.ctx(), Config{Issuer: idp.srv.URL, ClientID: idp.clientID}, idp.srv.URL+"/callback")
				if err != nil {
					t.Fatal(err)
				}
				c, err := rp.Exchange(idp.ctx(), idp.code, verifier, idp.nonce)
				if err != nil {
					t.Fatal(err)
				}
				if !slices.Equal(c.AMR, tc.amr) || (tc.amrNil && c.AMR != nil) {
					t.Errorf("AMR = %#v, want %#v", c.AMR, tc.amr)
				}
				if !slices.Equal(c.Groups, tc.groups) || (tc.groupsNil && c.Groups != nil) {
					t.Errorf("Groups = %#v, want %#v", c.Groups, tc.groups)
				}
				if c.ACR != tc.acr {
					t.Errorf("ACR = %q, want %q", c.ACR, tc.acr)
				}
			})
		}
	})

	// The email is the lower-cased, trimmed address.
	t.Run("email normalised", func(t *testing.T) {
		idp := newFakeIDP(t)
		idp.email = "  Person@Acme.EXAMPLE \t"
		rp, err := New(idp.ctx(), Config{Issuer: idp.srv.URL, ClientID: idp.clientID}, idp.srv.URL+"/callback")
		if err != nil {
			t.Fatal(err)
		}
		c, err := rp.Exchange(idp.ctx(), idp.code, verifier, idp.nonce)
		if err != nil {
			t.Fatal(err)
		}
		if c.Email != "person@acme.example" {
			t.Errorf("Email = %q, want person@acme.example", c.Email)
		}
	})
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}

func TestOIDC_IssuerPinning(t *testing.T) {
	idp := newFakeIDP(t)
	idp.issuerOverride = "https://evil.example/issuer"
	// Discovery advertises a different issuer than the one we pin → New fails.
	_, err := New(idp.ctx(), Config{Issuer: idp.srv.URL, ClientID: idp.clientID}, idp.srv.URL+"/callback")
	if err == nil {
		t.Fatal("issuer mismatch must fail provider construction (issuer pinning)")
	}
	if !strings.Contains(err.Error(), "issuer pin") || !strings.Contains(err.Error(), "did not match the issuer URL returned by provider") {
		t.Fatalf("New: %v, want the issuer-pin failure", err)
	}

	// An issuer and a client id are both required before any discovery.
	good := newFakeIDP(t)
	for name, cfg := range map[string]Config{
		"no client id": {Issuer: good.srv.URL},
		"no issuer":    {ClientID: good.clientID},
		"neither":      {},
	} {
		if _, err := New(good.ctx(), cfg, good.srv.URL+"/callback"); err == nil || !strings.Contains(err.Error(), "issuer and clientId are required") {
			t.Errorf("%s: New: %v, want the required-settings error", name, err)
		}
	}
}

func TestOIDC_NonceMismatchRejected(t *testing.T) {
	idp := newFakeIDP(t)
	rp, err := New(idp.ctx(), Config{Issuer: idp.srv.URL, ClientID: idp.clientID}, idp.srv.URL+"/callback")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rp.Exchange(idp.ctx(), idp.code, "verifier-abcdefabcdefabcdefabcdefabcdef1234", "wrong-nonce"); err == nil {
		t.Fatal("nonce mismatch must be rejected")
	}

	// Only the exact nonce the sign-in started with is accepted.
	for name, expected := range map[string]string{
		"another nonce":                "wrong-nonce",
		"a different case":             "NONCE-XYZ",
		"a prefix of the token's":      "nonce",
		"the token's with a suffix":    "nonce-xyz-2",
		"the token's with white space": "nonce-xyz ",
	} {
		_, err := rp.Exchange(idp.ctx(), idp.code, "verifier-abcdefabcdefabcdefabcdefabcdef1234", expected)
		if err == nil || !strings.Contains(err.Error(), "nonce mismatch") {
			t.Errorf("%s: Exchange: %v, want a nonce mismatch", name, err)
		}
	}
	// A token with no nonce claim does not answer a request that sent one.
	idp.nonce = ""
	if _, err := rp.Exchange(idp.ctx(), idp.code, "verifier-abcdefabcdefabcdefabcdefabcdef1234", "nonce-xyz"); err == nil || !strings.Contains(err.Error(), "nonce mismatch") {
		t.Errorf("a token without a nonce: Exchange: %v, want a nonce mismatch", err)
	}
	idp.nonce = "nonce-xyz"
	if _, err := rp.Exchange(idp.ctx(), idp.code, "verifier-abcdefabcdefabcdefabcdefabcdef1234", "nonce-xyz"); err != nil {
		t.Errorf("the matching nonce was refused: %v", err)
	}
}

// With no nonce to compare, Exchange refuses before it exchanges anything: an
// empty expected nonce is a caller's mistake, never a reason to skip the check.
func TestOIDC_EmptyExpectedNonceRefused(t *testing.T) {
	idp := newFakeIDP(t)
	rp, err := New(idp.ctx(), Config{Issuer: idp.srv.URL, ClientID: idp.clientID}, idp.srv.URL+"/callback")
	if err != nil {
		t.Fatal(err)
	}
	for _, tokenNonce := range []string{"nonce-xyz", ""} {
		idp.nonce = tokenNonce
		if _, err := rp.Exchange(idp.ctx(), idp.code, "verifier-abcdefabcdefabcdefabcdefabcdef1234", ""); err == nil || !strings.Contains(err.Error(), "no nonce") {
			t.Errorf("token nonce %q, expected nonce empty: Exchange: %v, want a refusal", tokenNonce, err)
		}
	}
}

func TestOIDC_EmailVerifiedSurfaced(t *testing.T) {
	idp := newFakeIDP(t)
	idp.emailVerified = false
	rp, err := New(idp.ctx(), Config{Issuer: idp.srv.URL, ClientID: idp.clientID}, idp.srv.URL+"/callback")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := rp.Exchange(idp.ctx(), idp.code, "verifier-abcdefabcdefabcdefabcdefabcdef1234", idp.nonce)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if claims.EmailVerified {
		t.Fatal("email_verified=false must be surfaced (respected by the caller)")
	}

	// Providers send it as a JSON bool or as the string "true"/"false"; any
	// other shape, or none, is not a verified address.
	for name, tc := range map[string]struct {
		claim any
		want  bool
	}{
		"bool true":          {true, true},
		"bool false":         {false, false},
		"string true":        {"true", true},
		"string TRUE":        {"TRUE", true},
		"string True":        {"True", true},
		"string false":       {"false", false},
		"string yes":         {"yes", false},
		"string 1":           {"1", false},
		"empty string":       {"", false},
		"string with spaces": {" true ", false},
		"number 1":           {1, false},
		"list":               {[]any{true}, false},
		"object":             {map[string]any{"v": true}, false},
		"null":               {nil, false},
	} {
		t.Run(name, func(t *testing.T) {
			idp := newFakeIDP(t)
			idp.extra = map[string]any{"email_verified": tc.claim}
			rp, err := New(idp.ctx(), Config{Issuer: idp.srv.URL, ClientID: idp.clientID}, idp.srv.URL+"/callback")
			if err != nil {
				t.Fatal(err)
			}
			c, err := rp.Exchange(idp.ctx(), idp.code, "verifier-abcdefabcdefabcdefabcdefabcdef1234", idp.nonce)
			if err != nil {
				t.Fatal(err)
			}
			if c.EmailVerified != tc.want {
				t.Fatalf("email_verified %#v surfaced as %v, want %v", tc.claim, c.EmailVerified, tc.want)
			}
		})
	}
	t.Run("claim absent", func(t *testing.T) {
		idp := newFakeIDP(t)
		idp.extra = map[string]any{"email_verified": omitClaim{}}
		rp, err := New(idp.ctx(), Config{Issuer: idp.srv.URL, ClientID: idp.clientID}, idp.srv.URL+"/callback")
		if err != nil {
			t.Fatal(err)
		}
		c, err := rp.Exchange(idp.ctx(), idp.code, "verifier-abcdefabcdefabcdefabcdefabcdef1234", idp.nonce)
		if err != nil {
			t.Fatal(err)
		}
		if c.EmailVerified {
			t.Fatal("a token without email_verified surfaced a verified address")
		}
	})
}

// TestOIDC_PreferredUsernameSurfaced: the directory's username reaches the
// caller, which seeds a new account's handle from it.
func TestOIDC_PreferredUsernameSurfaced(t *testing.T) {
	idp := newFakeIDP(t)
	idp.preferredUser = " blaktron "
	rp, err := New(idp.ctx(), Config{Issuer: idp.srv.URL, ClientID: idp.clientID}, idp.srv.URL+"/callback")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := rp.Exchange(idp.ctx(), idp.code, "verifier-abcdefabcdefabcdefabcdefabcdef1234", idp.nonce)
	if err != nil {
		t.Fatal(err)
	}
	if claims.PreferredUsername != "blaktron" {
		t.Fatalf("PreferredUsername = %q, want blaktron", claims.PreferredUsername)
	}
}

// TestOIDC_RawCarriesEveryClaim: claims this package does not name reach
// the caller as the token sent them, so a reader that knows its IdP's own
// claims decides what they mean; nothing is coerced on the way.
func TestOIDC_RawCarriesEveryClaim(t *testing.T) {
	idp := newFakeIDP(t)
	idp.extra = map[string]any{"x_flag": true, "x_count": 7, "x_name": "seven", "x_list": []any{"a", "b"}}
	rp, err := New(idp.ctx(), Config{Issuer: idp.srv.URL, ClientID: idp.clientID}, idp.srv.URL+"/callback")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := rp.Exchange(idp.ctx(), idp.code, "verifier-abcdefabcdefabcdefabcdefabcdef1234", idp.nonce)
	if err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]any{"x_flag": true, "x_count": float64(7), "x_name": "seven", "sub": claims.Subject} {
		if got := claims.Raw[k]; got != want {
			t.Errorf("Raw[%q] = %#v, want %#v", k, got, want)
		}
	}
	if l, ok := claims.Raw["x_list"].([]any); !ok || len(l) != 2 {
		t.Errorf("Raw[x_list] = %#v, want the list as sent", claims.Raw["x_list"])
	}
}

// TestOIDC_AuthTimeSurfaced: the directory's auth_time reaches the caller,
// which refuses to mint a remembered browser from a stale one.
func TestOIDC_AuthTimeSurfaced(t *testing.T) {
	for name, tc := range map[string]struct {
		set  bool
		at   int64
		want time.Time
	}{
		"present":  {true, 1_790_000_000, time.Unix(1_790_000_000, 0)},
		"absent":   {false, 0, time.Time{}},
		"zero":     {true, 0, time.Time{}},
		"negative": {true, -5, time.Time{}},
		"one":      {true, 1, time.Unix(1, 0)},
	} {
		t.Run(name, func(t *testing.T) {
			idp := newFakeIDP(t)
			if tc.set {
				idp.extra = map[string]any{"auth_time": tc.at}
			}
			rp, err := New(idp.ctx(), Config{Issuer: idp.srv.URL, ClientID: idp.clientID}, idp.srv.URL+"/callback")
			if err != nil {
				t.Fatal(err)
			}
			claims, err := rp.Exchange(idp.ctx(), idp.code, "verifier-abcdefabcdefabcdefabcdefabcdef1234", idp.nonce)
			if err != nil {
				t.Fatal(err)
			}
			if !claims.AuthTime.Equal(tc.want) {
				t.Fatalf("AuthTime = %v, want %v", claims.AuthTime, tc.want)
			}
		})
	}
}

// An ID token is accepted only when it is signed by the provider's key, is
// for this client, from this issuer, unexpired and about a subject; every
// other token is refused with the reason that applies.
func TestOIDC_IDTokenVerificationRefusals(t *testing.T) {
	const verifier = "verifier-abcdefabcdefabcdefabcdefabcdef1234"
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		set     func(*fakeIDP)
		wantErr string // "" accepts the token
	}{
		"a clean token":                    {func(*fakeIDP) {}, ""},
		"signed by another key":            {func(i *fakeIDP) { i.signWith = otherKey }, "id_token verification"},
		"for another client":               {func(i *fakeIDP) { i.aud = "another-client" }, "id_token verification"},
		"for several other clients":        {func(i *fakeIDP) { i.aud = []string{"a", "b"} }, "id_token verification"},
		"for us among other clients":       {func(i *fakeIDP) { i.aud = []string{"another-client", i.clientID} }, ""},
		"for no one":                       {func(i *fakeIDP) { i.aud = "" }, "id_token verification"},
		"expired an hour ago":              {func(i *fakeIDP) { i.expiresIn = -time.Hour }, "id_token verification"},
		"expired a minute ago":             {func(i *fakeIDP) { i.expiresIn = -time.Minute }, "id_token verification"},
		"from another issuer":              {func(i *fakeIDP) { i.tokenIssuer = "https://evil.example" }, "id_token verification"},
		"from the issuer with a slash":     {func(i *fakeIDP) { i.tokenIssuer = i.srv.URL + "/" }, "id_token verification"},
		"without a subject":                {func(i *fakeIDP) { i.sub = "" }, "id_token has no subject"},
		"not in the token response":        {func(i *fakeIDP) { i.noIDToken = true }, "no id_token"},
		"empty in the token response":      {func(i *fakeIDP) { i.emptyIDToken = true }, "no id_token"},
		"answering a code the IdP refuses": {func(i *fakeIDP) { i.code = "another-code" }, "code exchange"},
	} {
		t.Run(name, func(t *testing.T) {
			idp := newFakeIDP(t)
			rp, err := New(idp.ctx(), Config{Issuer: idp.srv.URL, ClientID: idp.clientID}, idp.srv.URL+"/callback")
			if err != nil {
				t.Fatal(err)
			}
			presented := idp.code
			tc.set(idp) // a case may make the IdP expect another code than the one presented
			c, err := rp.Exchange(idp.ctx(), presented, verifier, "nonce-xyz")
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("a token that should be accepted was refused: %v", err)
			case tc.wantErr == "" && c.Subject != idp.sub:
				t.Fatalf("Subject = %q, want %q", c.Subject, idp.sub)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("Exchange: %v, want an error containing %q", err, tc.wantErr)
			case tc.wantErr != "" && c != nil:
				t.Fatalf("a refused token still returned claims: %+v", c)
			}
		})
	}
}

// What discovery established: the issuer the connection is pinned to and the
// four endpoints the provider's discovery document names.
func TestOIDC_DescribeReportsDiscovery(t *testing.T) {
	idp := newFakeIDP(t)
	rp, err := New(idp.ctx(), Config{Issuer: idp.srv.URL, ClientID: idp.clientID}, idp.srv.URL+"/callback")
	if err != nil {
		t.Fatal(err)
	}
	want := Description{
		Issuer: idp.srv.URL, AuthURL: idp.srv.URL + "/authorize", TokenURL: idp.srv.URL + "/token",
		UserInfoURL: idp.srv.URL + "/userinfo", JWKSURL: idp.srv.URL + "/jwks",
	}
	if got := rp.Describe(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Describe() = %+v, want %+v", got, want)
	}
}
