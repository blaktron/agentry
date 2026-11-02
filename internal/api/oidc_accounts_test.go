package api_test

// Accounts made the way a person makes one on a deployment with no
// directory: signing in through the deployment's OpenID provider, here a
// stand-in (internal/testidp). No password and no directory takes part, so
// a test built on these fixtures keeps its coverage whichever of them the
// server stops shipping.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/auth"
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

// TestAnAssertedPlaceholderAddressIsNoAddress: an address carrying the
// registry's own placeholder suffix, which marks an account signed in with
// no address, is not taken from a provider. The account gets the registry's
// placeholder instead, and no activation link is made for an address nobody
// could confirm.
func TestAnAssertedPlaceholderAddressIsNoAddress(t *testing.T) {
	var mu sync.Mutex
	var registered []api.Event
	env, idp := newOIDCTestEnv(t, nil, func(s *api.Server) {
		s.AddEventHook(func(_ context.Context, ev api.Event) {
			if ev.Kind == "user.registered" {
				mu.Lock()
				registered = append(registered, ev)
				mu.Unlock()
			}
		})
	})
	h := "phold" + env.sfx
	asserted := "someone" + env.sfx + "@oidc" + auth.SyntheticAddressSuffix
	in := env.signInOIDC(t, idp, config.OIDCProviderID, testidp.Person{
		Subject: "sub-" + h, Email: asserted, EmailVerified: false, Username: h,
	})
	if in.status != http.StatusOK {
		t.Fatalf("sign-in: %d %s", in.status, in.body)
	}
	var email string
	var links int
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT u.email::text, (SELECT count(*) FROM email_verifications v WHERE v.user_id = u.id) FROM users u WHERE u.id = $1::uuid`,
		in.userID).Scan(&email, &links); err != nil {
		t.Fatal(err)
	}
	if email == asserted || !auth.SyntheticAddress(email) || links != 0 {
		t.Fatalf("account address %q with %d activation links, want the registry's own placeholder and none", email, links)
	}

	// The suffix is the registry's whatever its case, and a provider's claim
	// that such an address is verified makes it no more of an address.
	upper := "phup" + env.sfx
	shouted := "SOMEONE" + env.sfx + "@OIDC" + strings.ToUpper(auth.SyntheticAddressSuffix)
	in = env.signInOIDC(t, idp, config.OIDCProviderID, testidp.Person{
		Subject: "sub-" + upper, Email: shouted, EmailVerified: true, Username: upper,
	})
	if in.status != http.StatusOK {
		t.Fatalf("sign-in with a shouted placeholder: %d %s", in.status, in.body)
	}
	var verified bool
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT u.email::text, u.email_verified_at IS NOT NULL, (SELECT count(*) FROM email_verifications v WHERE v.user_id = u.id) FROM users u WHERE u.id = $1::uuid`,
		in.userID).Scan(&email, &verified, &links); err != nil {
		t.Fatal(err)
	}
	if strings.EqualFold(email, shouted) || !auth.SyntheticAddress(email) || verified || links != 0 {
		t.Fatalf("account address %q (verified %v) with %d activation links, want the registry's own placeholder, unverified, and no link", email, verified, links)
	}

	// The registration event says whether the address was vouched for: a
	// provider that calls an address verified when it gave none vouched for
	// nothing.
	none := "phnone" + env.sfx
	in = env.signInOIDC(t, idp, config.OIDCProviderID, testidp.Person{
		Subject: "sub-" + none, Email: "", EmailVerified: true, Username: none,
	})
	if in.status != http.StatusOK {
		t.Fatalf("sign-in with no address: %d %s", in.status, in.body)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(registered) != 3 {
		t.Fatalf("user.registered events: %d, want one for each of the three accounts", len(registered))
	}
	for i, ev := range registered {
		addr, _ := ev.Payload["email"].(string)
		if ev.UserID == uuid.Nil {
			t.Errorf("event %d names no user", i)
		}
		if ev.Payload["emailVerified"] != false {
			t.Errorf("event %d says emailVerified %v for %q, want false: no address of the provider's was vouched for", i, ev.Payload["emailVerified"], addr)
		}
		if h, _ := ev.Payload["handle"].(string); h == "" {
			t.Errorf("event %d names no handle", i)
		}
	}
}
