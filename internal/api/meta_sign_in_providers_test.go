package api_test

import (
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/config"
)

// /meta names the sign-in providers this registry has configured, so a front
// end learns them without starting an OIDC flow for each (agentry#694). The
// site used to call /auth/oidc/{id}/start six times per sign-in page, all from
// its own address, and once the anonymous class refused one it told every
// visitor that no identity provider was configured (agentry#680). The list and
// the start route must agree: listed means start redirects, and unlisted means
// start answers 404.

// specSignInProviders is the provider enum of /auth/oidc/{provider}/start, so
// a provider added there and forgotten here fails these tests.
func specSignInProviders(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile("../../schemas/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Components struct {
			Parameters struct {
				SocialProvider struct {
					Schema struct {
						Enum []string `yaml:"enum"`
					} `yaml:"schema"`
				} `yaml:"SocialProvider"`
			} `yaml:"parameters"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	ids := spec.Components.Parameters.SocialProvider.Schema.Enum
	if len(ids) == 0 {
		t.Fatal("the spec's SocialProvider parameter has no enum")
	}
	return ids
}

// metaAgreesWithStart asserts /meta lists want, and that start redirects for
// exactly the providers /meta lists.
func metaAgreesWithStart(t *testing.T, env *testEnv, want []string) {
	t.Helper()
	var meta api.Meta
	env.doJSON(anonymous, http.MethodGet, "/api/v1/meta", nil, &meta, http.StatusOK)
	if meta.SignInProviders == nil {
		t.Fatal("/meta has no signInProviders")
	}
	listed := *meta.SignInProviders
	if !slices.Equal(listed, want) {
		t.Fatalf("signInProviders = %v, want %v", listed, want)
	}
	client := *env.srv.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	for _, p := range specSignInProviders(t) {
		res, err := client.Get(env.srv.URL + "/api/v1/auth/oidc/" + p + "/start")
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		if isListed, redirects := slices.Contains(listed, p), res.StatusCode == http.StatusFound; isListed != redirects {
			t.Errorf("%s: listed=%v, but start answered %d", p, isListed, res.StatusCode)
		}
	}
}

func TestMetaListsTheSignInProvidersStartRedirectsFor(t *testing.T) {
	gh := newFakeGitHub(t)
	idp := newFakeOIDC(t)
	env := newTestEnvCfg(t, func(cfg *config.Config) {
		gh.configure(cfg)
		cfg.Social.Authentik = config.SocialProvider{
			ClientID: idp.clientID, ClientSecret: "authentik-secret", Issuer: idp.srv.URL,
		}
		// A client without the issuer it needs cannot start, so it is not
		// offered either.
		cfg.Social.OpenAI = config.SocialProvider{ClientID: "openai-client", ClientSecret: "openai-secret"}
	}, func(s *api.Server) { s.SetOIDCHTTPClient(idp.srv.Client()) })
	metaAgreesWithStart(t, env, []string{"github", "authentik"})

	// The core's own sign-in page offers the same providers: no button that
	// would answer 404.
	res := env.do(anonymous, http.MethodGet, "/ui/login", nil)
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	for _, p := range specSignInProviders(t) {
		offered := strings.Contains(string(body), "/api/v1/auth/oidc/"+p+"/start")
		if want := p == "github" || p == "authentik"; offered != want {
			t.Errorf("/ui/login offers %s: %v, want %v", p, offered, want)
		}
	}
}

// Every provider the spec names can be listed, in the spec's order.
func TestMetaListsEveryConfiguredSignInProvider(t *testing.T) {
	gh := newFakeGitHub(t)
	idp := newFakeOIDC(t)
	env := newTestEnvCfg(t, func(cfg *config.Config) {
		gh.configure(cfg)
		oidc := config.SocialProvider{ClientID: idp.clientID, ClientSecret: "secret", Issuer: idp.srv.URL}
		cfg.Social.Google, cfg.Social.Microsoft, cfg.Social.OpenAI = oidc, oidc, oidc
		cfg.Social.Claude, cfg.Social.Authentik = oidc, oidc
	}, func(s *api.Server) { s.SetOIDCHTTPClient(idp.srv.Client()) })
	metaAgreesWithStart(t, env, specSignInProviders(t))
}

// A registry with no provider says so with an empty list, not an absent
// field, so a front end can tell "none configured" from an older registry
// that does not report them.
func TestMetaListsNoSignInProviderWhenNoneIsConfigured(t *testing.T) {
	metaAgreesWithStart(t, newTestEnv(t), []string{})
}
