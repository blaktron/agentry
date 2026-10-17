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
// end learns them without starting an OIDC flow for each. A page that
// called /auth/oidc/{id}/start once per provider, all from its own address,
// would tell every visitor that no identity provider was configured once
// the anonymous class refused one. The list and the start route must agree: listed means start redirects, and unlisted means
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
	idp := newFakeOIDC(t)
	env := newTestEnvCfg(t, func(cfg *config.Config) {
		cfg.Auth.OIDC = config.OIDCProvider{
			ID: config.AuthentikProviderID, ClientID: idp.clientID, ClientSecret: "authentik-secret", Issuer: idp.srv.URL,
		}
	}, func(s *api.Server) { s.SetOIDCHTTPClient(idp.srv.Client()) })
	metaAgreesWithStart(t, env, []string{"authentik"})

	// The core's own sign-in page offers the same provider: no button that
	// would answer 404.
	res := env.do(anonymous, http.MethodGet, "/ui/login?error=x", nil)
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	for _, p := range specSignInProviders(t) {
		offered := strings.Contains(string(body), "/api/v1/auth/oidc/"+p+"/start")
		if want := p == "authentik"; offered != want {
			t.Errorf("/ui/login offers %s: %v, want %v", p, offered, want)
		}
	}
}

// Every id the spec names can be listed. The sign-in OpenID provider is one
// provider under one of two ids, "authentik" where its accounts are linked
// under that id and "oidc" otherwise, so each is listed in a deployment of
// its own, and the other id is not.
func TestMetaListsEveryConfiguredSignInProvider(t *testing.T) {
	for _, id := range []string{"authentik", "oidc"} {
		t.Run(id, func(t *testing.T) {
			idp := newFakeOIDC(t)
			env := newTestEnvCfg(t, func(cfg *config.Config) {
				cfg.Auth.OIDC = config.OIDCProvider{ID: id, Issuer: idp.srv.URL, ClientID: idp.clientID, ClientSecret: "secret"}
			}, func(s *api.Server) { s.SetOIDCHTTPClient(idp.srv.Client()) })
			metaAgreesWithStart(t, env, []string{id})
		})
	}
	if ids := specSignInProviders(t); !slices.Equal(ids, []string{"authentik", "oidc"}) {
		t.Fatalf("the spec's provider ids are %v, want the one provider's two ids", ids)
	}
}

// A registry with no provider says so with an empty list, not an absent
// field, so a front end can tell "none configured" from an older registry
// that does not report them.
func TestMetaListsNoSignInProviderWhenNoneIsConfigured(t *testing.T) {
	metaAgreesWithStart(t, newTestEnv(t), []string{})
}
