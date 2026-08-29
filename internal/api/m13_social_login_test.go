package api_test

// Social login for individual accounts (§12.1, M-13). The providers are
// in-process (DEV-009's pattern): a scripted GitHub OAuth app and an OIDC
// provider signing real ID tokens, so the handler chain — state cookie, code
// exchange, identity linking, session issue — runs exactly as in production.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/coreos/go-oidc/v3/oidc/oidctest"

	"github.com/PLACEHOLDER_ORG/agentry/internal/api"
	"github.com/PLACEHOLDER_ORG/agentry/internal/config"
)

// ---- in-process GitHub OAuth app ----

type fakeGitHub struct {
	srv      *httptest.Server
	userID   int64
	login    string
	name     string
	email    string
	verified bool
}

func newFakeGitHub(t *testing.T) *fakeGitHub {
	t.Helper()
	// A distinct provider user id per test: identities are keyed on the
	// namespaced subject in one shared database, so a fixed id would make
	// each test resolve to the previous one's account.
	gh := &fakeGitHub{userID: randInt63(), login: "octo", name: "Octo Cat", verified: true}
	mux := http.NewServeMux()
	mux.HandleFunc("/login/oauth/authorize", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK) // the browser lands here; the test never follows it
	})
	mux.HandleFunc("/login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.FormValue("code") == "" {
			http.Error(w, "missing code", http.StatusBadRequest)
			return
		}
		writeTestJSON(w, map[string]any{"access_token": "gho_test", "token_type": "bearer"})
	})
	mux.HandleFunc("/user", func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(w, map[string]any{"id": gh.userID, "login": gh.login, "name": gh.name})
	})
	mux.HandleFunc("/user/emails", func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(w, []map[string]any{
			{"email": "secondary@example.test", "primary": false, "verified": true},
			{"email": gh.email, "primary": true, "verified": gh.verified},
		})
	})
	gh.srv = httptest.NewServer(mux)
	t.Cleanup(gh.srv.Close)
	return gh
}

func (gh *fakeGitHub) configure(cfg *config.Config) {
	cfg.Social.GitHub = config.SocialProvider{
		ClientID: "gh-client", ClientSecret: "gh-secret",
		AuthURL:    gh.srv.URL + "/login/oauth/authorize",
		TokenURL:   gh.srv.URL + "/login/oauth/access_token",
		APIBaseURL: gh.srv.URL,
	}
}

func writeTestJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// ---- driving the two-leg flow ----

// socialStart hits the start endpoint and returns the provider authorization
// URL the browser would follow, the state parameter, and the sealed cookie.
func (env *testEnv) socialStart(t *testing.T, provider string) (authURL *url.URL, state string, cookie *http.Cookie) {
	t.Helper()
	client := *env.srv.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res, err := client.Get(env.srv.URL + "/api/v1/auth/oidc/" + provider + "/start")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("start %s: got %d want 302", provider, res.StatusCode)
	}
	authURL, err = url.Parse(res.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	state = authURL.Query().Get("state")
	if state == "" {
		t.Fatalf("start %s: authorization URL carries no state", provider)
	}
	for _, c := range res.Cookies() {
		if c.Name == "agentry_social_state" {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatalf("start %s: no sealed state cookie", provider)
	}
	return authURL, state, cookie
}

// socialCallback completes the flow with the state cookie in hand.
func (env *testEnv) socialCallback(t *testing.T, provider, state string, cookie *http.Cookie) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet,
		env.srv.URL+"/api/v1/auth/oidc/"+provider+"/callback?code=test-code&state="+url.QueryEscape(state), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(cookie)
	client := *env.srv.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func (env *testEnv) socialLogin(t *testing.T, provider string) *http.Response {
	t.Helper()
	_, state, cookie := env.socialStart(t, provider)
	return env.socialCallback(t, provider, state, cookie)
}

// ---- tests ----

func TestSocialLoginJITCreatesAccount(t *testing.T) {
	gh := newFakeGitHub(t)
	gh.email = "jit-" + randSuffix() + "@github.test"
	env := newTestEnvCfg(t, gh.configure)

	res := env.socialLogin(t, "github")
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("social callback: got %d want 200", res.StatusCode)
	}
	var out struct {
		TotpRequired bool `json:"totpRequired"`
		User         struct {
			Id            string `json:"id"`
			Email         string `json:"email"`
			EmailVerified bool   `json:"emailVerified"`
		} `json:"user"`
		CsrfToken string `json:"csrfToken"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.TotpRequired || out.CsrfToken == "" {
		t.Fatalf("expected a session, got %+v", out)
	}
	if out.User.Email != gh.email {
		t.Fatalf("email = %q, want %q", out.User.Email, gh.email)
	}
	if !out.User.EmailVerified {
		t.Fatal("a provider-verified email must land verified")
	}

	// The session works, and the identity is recorded as social with a
	// provider-namespaced subject.
	var session string
	for _, c := range res.Cookies() {
		if c.Name == "agentry_session" {
			session = c.Value
		}
	}
	if session == "" {
		t.Fatal("no session cookie")
	}
	who := env.do(caller{name: "social", session: session}, http.MethodGet, "/api/v1/user", nil)
	_ = who.Body.Close()
	if who.StatusCode != http.StatusOK {
		t.Fatalf("social session GET /user: got %d want 200", who.StatusCode)
	}

	var kind, subject string
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT provider_kind, subject FROM identities WHERE user_id = $1::uuid`, out.User.Id,
	).Scan(&kind, &subject); err != nil {
		t.Fatal(err)
	}
	wantSubject := "github:" + strconv.FormatInt(gh.userID, 10)
	if kind != "social" || subject != wantSubject {
		t.Fatalf("identity = %s/%s, want social/%s", kind, subject, wantSubject)
	}

	// A second login through the same provider reuses the account rather than
	// creating another.
	res2 := env.socialLogin(t, "github")
	_ = res2.Body.Close()
	if res2.StatusCode != http.StatusOK {
		t.Fatalf("repeat social login: got %d want 200", res2.StatusCode)
	}
	var accounts int64
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM users WHERE email = $1`, gh.email).Scan(&accounts); err != nil {
		t.Fatal(err)
	}
	if accounts != 1 {
		t.Fatalf("%d accounts for one provider identity", accounts)
	}
}

func TestSocialLoginAutoLinksVerifiedEmail(t *testing.T) {
	gh := newFakeGitHub(t)
	env := newTestEnvCfg(t, gh.configure)

	// An existing account whose OWN email is verified.
	handle := env.register("soc-link")
	env.verifyEmail(handle)
	gh.email = handle + "@example.test"
	gh.verified = true

	res := env.socialLogin(t, "github")
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("auto-link: got %d want 200", res.StatusCode)
	}
	var out struct {
		User struct {
			Handle string `json:"handle"`
		} `json:"user"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.User.Handle != handle {
		t.Fatalf("auto-link produced %q, want the existing account %q", out.User.Handle, handle)
	}
}

func TestSocialLoginRefusesUnverifiedLink(t *testing.T) {
	// T-12: an email match is only evidence of ownership when BOTH sides are
	// verified. Either half missing means an explicit link, not a takeover.
	t.Run("provider has not verified the address", func(t *testing.T) {
		gh := newFakeGitHub(t)
		env := newTestEnvCfg(t, gh.configure)
		handle := env.register("soc-unv1")
		env.verifyEmail(handle)
		gh.email = handle + "@example.test"
		gh.verified = false

		res := env.socialLogin(t, "github")
		_ = res.Body.Close()
		// With no verified provider email the identity is anonymous to us, so
		// this JIT-creates a separate account rather than touching the
		// existing one — never a silent takeover.
		if res.StatusCode != http.StatusOK {
			t.Fatalf("got %d want 200 (JIT with a synthetic address)", res.StatusCode)
		}
		var linked int64
		if err := env.st.Pool().QueryRow(context.Background(),
			`SELECT count(*) FROM identities i JOIN handles h ON h.id = i.user_id WHERE h.handle = $1`,
			handle).Scan(&linked); err != nil {
			t.Fatal(err)
		}
		if linked != 0 {
			t.Fatal("an unverified provider email must never link to an existing account")
		}
	})

	t.Run("account has not verified its own address", func(t *testing.T) {
		gh := newFakeGitHub(t)
		env := newTestEnvCfg(t, gh.configure)
		handle := env.register("soc-unv2") // deliberately NOT verified
		gh.email = handle + "@example.test"
		gh.verified = true

		res := env.socialLogin(t, "github")
		_ = res.Body.Close()
		if res.StatusCode != http.StatusConflict {
			t.Fatalf("got %d want 409 (explicit link required)", res.StatusCode)
		}
	})
}

func TestSocialLoginStillRequiresTOTP(t *testing.T) {
	gh := newFakeGitHub(t)
	env := newTestEnvCfg(t, gh.configure)

	handle := env.register("soc-totp")
	env.verifyEmail(handle)
	sess := env.login(handle)
	var setup struct {
		Secret string `json:"secret"`
	}
	env.doJSON(sess, http.MethodPost, "/api/v1/auth/2fa/totp/setup", nil, &setup, http.StatusOK)
	code, err := totpCode(setup.Secret)
	if err != nil {
		t.Fatal(err)
	}
	env.doJSON(sess, http.MethodPost, "/api/v1/auth/2fa/totp/verify",
		map[string]any{"code": code}, nil, http.StatusNoContent)

	gh.email = handle + "@example.test"
	gh.verified = true

	res := env.socialLogin(t, "github")
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("social callback: got %d want 200", res.StatusCode)
	}
	var out struct {
		TotpRequired bool    `json:"totpRequired"`
		Challenge    *string `json:"challenge"`
		CsrfToken    *string `json:"csrfToken"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if !out.TotpRequired || out.Challenge == nil {
		t.Fatalf("2FA account got a social login without a challenge: %+v", out)
	}
	if out.CsrfToken != nil {
		t.Fatal("no session may be issued before the second factor")
	}
	for _, c := range res.Cookies() {
		if c.Name == "agentry_session" && c.Value != "" {
			t.Fatal("a session cookie was set before the second factor")
		}
	}

	// A wrong code does not open the session.
	bad := env.do(anonymous, http.MethodPost, "/api/v1/auth/2fa/totp/challenge",
		map[string]any{"challenge": *out.Challenge, "code": "000000"})
	_ = bad.Body.Close()
	if bad.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong TOTP code: got %d want 401", bad.StatusCode)
	}

	// The right one does.
	good, err := totpCode(setup.Secret)
	if err != nil {
		t.Fatal(err)
	}
	done := env.do(anonymous, http.MethodPost, "/api/v1/auth/2fa/totp/challenge",
		map[string]any{"challenge": *out.Challenge, "code": good})
	defer func() { _ = done.Body.Close() }()
	if done.StatusCode != http.StatusOK {
		t.Fatalf("completing the challenge: got %d want 200", done.StatusCode)
	}
	session := ""
	for _, c := range done.Cookies() {
		if c.Name == "agentry_session" {
			session = c.Value
		}
	}
	if session == "" {
		t.Fatal("completing the challenge issued no session")
	}

	// A forged challenge is refused: the blob is sealed, not merely opaque.
	forged := env.do(anonymous, http.MethodPost, "/api/v1/auth/2fa/totp/challenge",
		map[string]any{"challenge": base64.RawURLEncoding.EncodeToString([]byte("not sealed")), "code": good})
	_ = forged.Body.Close()
	if forged.StatusCode != http.StatusUnauthorized {
		t.Fatalf("forged challenge: got %d want 401", forged.StatusCode)
	}
}

func TestSocialLoginUnconfiguredProviderIs404(t *testing.T) {
	gh := newFakeGitHub(t)
	env := newTestEnvCfg(t, gh.configure) // github only

	res := env.do(anonymous, http.MethodGet, "/api/v1/auth/oidc/google/start", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("unconfigured provider: got %d want 404", res.StatusCode)
	}
	// The path parameter is a closed enum, so an unknown provider never
	// reaches the handler.
	res = env.do(anonymous, http.MethodGet, "/api/v1/auth/oidc/evilcorp/start", nil)
	_ = res.Body.Close()
	if res.StatusCode == http.StatusFound {
		t.Fatal("an unknown provider must not start a login")
	}
}

func TestSocialLoginRejectsStateMismatch(t *testing.T) {
	gh := newFakeGitHub(t)
	gh.email = "state-" + randSuffix() + "@github.test"
	env := newTestEnvCfg(t, gh.configure)

	_, _, cookie := env.socialStart(t, "github")
	res := env.socialCallback(t, "github", "not-the-state", cookie)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("state mismatch: got %d want 401", res.StatusCode)
	}

	// And without the sealed cookie at all.
	_, state, _ := env.socialStart(t, "github")
	req, _ := http.NewRequest(http.MethodGet,
		env.srv.URL+"/api/v1/auth/oidc/github/callback?code=c&state="+state, nil)
	bare, err := env.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = bare.Body.Close()
	if bare.StatusCode == http.StatusOK {
		t.Fatal("a callback without the state cookie must not establish a session")
	}
}

// ---- google (OIDC proper) ----

// fakeOIDC is an in-process OIDC provider signing real ID tokens. Its
// /authorize endpoint records the nonce, as a real IdP does, so the ID token
// can echo it back — which is what makes the RP's nonce check meaningful.
type fakeOIDC struct {
	srv      *httptest.Server
	key      *rsa.PrivateKey
	clientID string
	sub      string
	email    string
	nonce    string
}

func newFakeOIDC(t *testing.T) *fakeOIDC {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &fakeOIDC{key: key, clientID: "google-client", sub: "g-" + randSuffix()}
	p.email = "google-" + randSuffix() + "@gmail.test"
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(w, map[string]any{
			"issuer":                                p.srv.URL,
			"authorization_endpoint":                p.srv.URL + "/authorize",
			"token_endpoint":                        p.srv.URL + "/token",
			"jwks_uri":                              p.srv.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())
		writeTestJSON(w, map[string]any{"keys": []map[string]any{
			{"kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig", "n": n, "e": e},
		}})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		p.nonce = r.URL.Query().Get("nonce")
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		// PKCE: the RP must send the verifier it committed to at /authorize.
		if r.FormValue("code_verifier") == "" {
			http.Error(w, "missing PKCE verifier", http.StatusBadRequest)
			return
		}
		claims, _ := json.Marshal(map[string]any{
			"iss": p.srv.URL, "aud": p.clientID, "sub": p.sub,
			"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
			"email": p.email, "email_verified": true,
			"nonce": p.nonce,
		})
		writeTestJSON(w, map[string]any{
			"access_token": "at", "token_type": "Bearer", "expires_in": 3600,
			"id_token": oidctest.SignIDToken(p.key, "k1", "RS256", string(claims)),
		})
	})
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	return p
}

// TestSocialLoginGoogleOIDC exercises the OIDC-proper provider end to end —
// discovery, issuer pinning, PKCE (the token endpoint refuses a request with
// no verifier), and the nonce round trip.
func TestSocialLoginGoogleOIDC(t *testing.T) {
	idp := newFakeOIDC(t)
	env := newTestEnvCfg(t, func(cfg *config.Config) {
		cfg.Social.Google = config.SocialProvider{
			ClientID: idp.clientID, ClientSecret: "google-secret", Issuer: idp.srv.URL,
		}
	}, func(s *api.Server) {
		s.SetOIDCHTTPClient(idp.srv.Client())
	})

	authURL, state, cookie := env.socialStart(t, "google")
	if authURL.Query().Get("code_challenge") == "" {
		t.Fatal("the authorization URL carries no PKCE challenge")
	}
	// The browser leg: this is where a real IdP learns the nonce.
	visit, err := idp.srv.Client().Get(authURL.String())
	if err != nil {
		t.Fatal(err)
	}
	_ = visit.Body.Close()

	res := env.socialCallback(t, "google", state, cookie)
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("google callback: got %d want 200", res.StatusCode)
	}
	var out struct {
		User struct {
			Id    string `json:"id"`
			Email string `json:"email"`
		} `json:"user"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.User.Email != idp.email {
		t.Fatalf("email = %q, want %q", out.User.Email, idp.email)
	}
	var subject string
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT subject FROM identities WHERE user_id = $1::uuid`, out.User.Id).Scan(&subject); err != nil {
		t.Fatal(err)
	}
	if subject != "google:"+idp.sub {
		t.Fatalf("subject = %q, want google:%s", subject, idp.sub)
	}
}

// TestSocialLoginGoogleNonceMismatch: an ID token whose nonce does not match
// the one this login committed to is refused, so a token minted for another
// session cannot be replayed into ours.
func TestSocialLoginGoogleNonceMismatch(t *testing.T) {
	idp := newFakeOIDC(t)
	idp.nonce = "a-different-login's-nonce"
	env := newTestEnvCfg(t, func(cfg *config.Config) {
		cfg.Social.Google = config.SocialProvider{
			ClientID: idp.clientID, ClientSecret: "google-secret", Issuer: idp.srv.URL,
		}
	}, func(s *api.Server) {
		s.SetOIDCHTTPClient(idp.srv.Client())
	})

	// Deliberately skip the /authorize leg so the IdP never learns our nonce.
	res := env.socialLogin(t, "google")
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("nonce mismatch: got %d want 401", res.StatusCode)
	}
}

// randSuffix is lowercase hex: emails and handles are case-insensitive
// (citext), so a mixed-case suffix would not survive the round trip.
func randSuffix() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func randInt63() int64 {
	n, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		panic(err)
	}
	return n.Int64() + 1
}

var _ = coreoidc.ScopeOpenID
