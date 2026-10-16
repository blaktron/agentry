package api_test

// Accounts made the way a person makes one on a deployment with no
// directory: signing in through the deployment's OpenID provider, here a
// stand-in (internal/testidp). No password and no directory takes part, so
// a test built on these fixtures keeps its coverage whichever of them the
// server stops shipping.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/testidp"
)

// newOIDCTestEnv is a test server whose sign-in OpenID provider is a fresh
// stand-in, served as "oidc". cfgFn and opts are newTestEnvCfg's.
func newOIDCTestEnv(t *testing.T, cfgFn func(*config.Config), opts ...func(*api.Server)) (*testEnv, *testidp.IdP) {
	t.Helper()
	idp := testidp.New(t)
	env := newTestEnvCfg(t, func(c *config.Config) {
		c.Auth.OIDC = config.OIDCProvider{Issuer: idp.URL, ClientID: idp.ClientID, ClientSecret: idp.ClientSecret}
		if cfgFn != nil {
			cfgFn(c)
		}
	}, append([]func(*api.Server){func(s *api.Server) { s.SetOIDCHTTPClient(idp.Client()) }}, opts...)...)
	return env, idp
}

// oidcSignIn is one sign-in's outcome: the caller it made (zero when the
// sign-in made no session), the account, and the response, body read.
type oidcSignIn struct {
	caller  caller
	userID  string
	handle  string
	status  int
	body    []byte
	cookies []*http.Cookie
}

// signInOIDC signs person in through provider (the id the server serves
// its sign-in provider under) against idp: the start route, the browser's
// visit to the provider, the callback. It fails the test only when the
// flow itself breaks; a refused sign-in comes back in status and body.
func (env *testEnv) signInOIDC(t *testing.T, idp *testidp.IdP, provider string, person testidp.Person) oidcSignIn {
	t.Helper()
	idp.SignInAs(person)
	authURL, state, cookie := env.socialStart(t, provider)
	code, back := idp.Authorize(t, authURL.String())
	if back != state {
		t.Fatalf("the provider returned state %q, want %q", back, state)
	}
	req, err := http.NewRequest(http.MethodGet, env.srv.URL+"/api/v1/auth/oidc/"+provider+"/callback?code="+
		url.QueryEscape(code)+"&state="+url.QueryEscape(state), nil)
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
	defer func() { _ = res.Body.Close() }()
	out := oidcSignIn{status: res.StatusCode, cookies: res.Cookies()}
	out.body, _ = io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		return out
	}
	var body struct {
		CsrfToken string `json:"csrfToken"`
		User      struct {
			ID     string `json:"id"`
			Handle string `json:"handle"`
		} `json:"user"`
	}
	if err := json.Unmarshal(out.body, &body); err != nil {
		t.Fatalf("callback body: %v (%s)", err, out.body)
	}
	out.userID, out.handle = body.User.ID, body.User.Handle
	out.caller = caller{name: body.User.Handle, csrf: body.CsrfToken}
	for _, c := range out.cookies {
		if c.Name == "agentry_session" {
			out.caller.session = c.Value
		}
	}
	return out
}

// mintAccount makes an account for handle by its first sign-in through the
// stand-in provider (newOIDCTestEnv's), with a verified address at
// example.test, and returns its session. The handle is seeded from the
// username, as a new account's is, and carries the env's suffix.
func (env *testEnv) mintAccount(t *testing.T, idp *testidp.IdP, handle string) caller {
	t.Helper()
	h := handle + env.sfx
	in := env.signInOIDC(t, idp, config.OIDCProviderID, testidp.Person{
		Subject: "sub-" + h, Email: h + "@example.test", EmailVerified: true, Username: h,
	})
	if in.status != http.StatusOK || in.caller.session == "" {
		t.Fatalf("mint %s: %d %s", h, in.status, in.body)
	}
	if in.handle != h {
		t.Fatalf("mint %s: the account is %q", h, in.handle)
	}
	return in.caller
}
