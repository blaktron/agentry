package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
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
}

func newFakeIDP(t *testing.T) *fakeIDP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
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
		if r.FormValue("code") != idp.code {
			http.Error(w, "bad code", http.StatusBadRequest)
			return
		}
		claims := map[string]any{
			"iss": idp.srv.URL, "aud": idp.clientID, "sub": idp.sub,
			"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
			"nonce": idp.nonce, "email": idp.email, "email_verified": idp.emailVerified,
		}
		if idp.preferredUser != "" {
			claims["preferred_username"] = idp.preferredUser
		}
		for k, v := range idp.extra {
			claims[k] = v
		}
		cb, _ := json.Marshal(claims)
		idToken := oidctest.SignIDToken(idp.key, idp.keyID, "RS256", string(cb))
		writeJSON(w, map[string]any{
			"access_token": "at-1", "token_type": "Bearer", "expires_in": 3600, "id_token": idToken,
		})
	})
	idp.srv = httptest.NewServer(mux)
	t.Cleanup(idp.srv.Close)
	return idp
}

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
	rp, err := New(idp.ctx(), Config{Issuer: idp.srv.URL, ClientID: idp.clientID}, idp.srv.URL+"/callback")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// AuthURL must carry PKCE + nonce.
	url := rp.AuthURL("state-1", idp.nonce, "verifier-abcdefabcdefabcdefabcdefabcdef1234")
	if !strings.Contains(url, "code_challenge=") || !strings.Contains(url, "nonce=") {
		t.Fatalf("auth url missing pkce/nonce: %s", url)
	}
	// No refresh token is ever used, so none is asked for.
	if strings.Contains(url, "access_type=") || strings.Contains(url, "offline") {
		t.Fatalf("auth url asks for offline access: %s", url)
	}
	claims, err := rp.Exchange(idp.ctx(), idp.code, "verifier-abcdefabcdefabcdefabcdefabcdef1234", idp.nonce)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if claims.Subject != idp.sub || claims.Email != idp.email || !claims.EmailVerified {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

func TestOIDC_IssuerPinning(t *testing.T) {
	idp := newFakeIDP(t)
	idp.issuerOverride = "https://evil.example/issuer"
	// Discovery advertises a different issuer than the one we pin → New fails.
	if _, err := New(idp.ctx(), Config{Issuer: idp.srv.URL, ClientID: idp.clientID}, idp.srv.URL+"/callback"); err == nil {
		t.Fatal("issuer mismatch must fail provider construction (issuer pinning)")
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

// TestOIDC_RememberDeviceIsOnlyAJSONTrue: the directory's
// `agentry_remember_device` claim is half of what mints a credential, so
// only the JSON boolean its scope mapping emits counts. A string, a number
// or an absent claim is "not asked", never a guess.
func TestOIDC_RememberDeviceIsOnlyAJSONTrue(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value any
		set   bool
		want  bool
	}{
		{"true", true, true, true},
		{"false", false, true, false},
		{"absent", nil, false, false},
		{"the string true", "true", true, false},
		{"one", 1, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			idp := newFakeIDP(t)
			if tc.set {
				idp.extra = map[string]any{"agentry_remember_device": tc.value}
			}
			rp, err := New(idp.ctx(), Config{Issuer: idp.srv.URL, ClientID: idp.clientID}, idp.srv.URL+"/callback")
			if err != nil {
				t.Fatal(err)
			}
			claims, err := rp.Exchange(idp.ctx(), idp.code, "verifier-abcdefabcdefabcdefabcdefabcdef1234", idp.nonce)
			if err != nil {
				t.Fatal(err)
			}
			if claims.RememberDevice != tc.want {
				t.Fatalf("RememberDevice = %v for %#v, want %v", claims.RememberDevice, tc.value, tc.want)
			}
		})
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
		"present": {true, 1_790_000_000, time.Unix(1_790_000_000, 0)},
		"absent":  {false, 0, time.Time{}},
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

// TestPromoCodeClaim: the directory's agentry_promo_code claim is read as a
// string inside the billing extension's grammar, upper-cased, and as nothing
// otherwise.
func TestPromoCodeClaim(t *testing.T) {
	for in, want := range map[any]string{
		"LAUNCH-2026":           "LAUNCH-2026",
		" launch-2026 ":         "LAUNCH-2026",
		"a1b2":                  "A1B2",
		strings.Repeat("a", 32): strings.Repeat("A", 32),
		"":                      "",
		"abc":                   "",
		"-abcd":                 "",
		"ab cd":                 "",
		"ab_cd":                 "",
		strings.Repeat("a", 33): "",
		"Ünicode":               "",
		"ſale":                  "",
		"ıdea":                  "",
		1234:                    "",
		true:                    "",
	} {
		if got := PromoCodeClaim(in); got != want {
			t.Errorf("PromoCodeClaim(%#v) = %q, want %q", in, got, want)
		}
	}
	if got := PromoCodeClaim(nil); got != "" {
		t.Errorf("PromoCodeClaim(nil) = %q", got)
	}
}
