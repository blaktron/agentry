package api_test

import (
	"net/http"
	"testing"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/config"
)

// /meta names the deployment and says whether it serves its own browser
// pages, so a client can call it by name and open the
// device-authorize page wherever it lives.
func TestMetaReportsBrandAndUI(t *testing.T) {
	type meta struct {
		Brand struct {
			Name string `json:"name"`
		} `json:"brand"`
		Ui struct {
			Mode         string  `json:"mode"`
			AuthorizeUrl *string `json:"authorizeUrl"`
		} `json:"ui"`
	}
	t.Run("defaults name the public host and serve the full UI", func(t *testing.T) {
		env := newTestEnvCfg(t, func(c *config.Config) { c.BaseURL = "https://reg.example" })
		var m meta
		env.doJSON(anonymous, http.MethodGet, "/api/v1/meta", nil, &m, http.StatusOK)
		if m.Brand.Name != "reg.example" || m.Ui.Mode != "full" || m.Ui.AuthorizeUrl == nil || *m.Ui.AuthorizeUrl != "https://reg.example/ui/authorize" {
			t.Fatalf("meta = %+v", m)
		}
	})
	t.Run("a named deployment with the UI off", func(t *testing.T) {
		env := newTestEnvCfg(t, func(c *config.Config) { c.Brand.Name = "Acme Registry"; c.UI.Mode = "off" })
		var m meta
		env.doJSON(anonymous, http.MethodGet, "/api/v1/meta", nil, &m, http.StatusOK)
		if m.Brand.Name != "Acme Registry" || m.Ui.Mode != "off" || m.Ui.AuthorizeUrl != nil {
			t.Fatalf("meta = %+v", m)
		}
	})
	t.Run("authorize mode serves the authorize page alone", func(t *testing.T) {
		env := newTestEnvCfg(t, func(c *config.Config) { c.BaseURL = "https://reg.example"; c.UI.Mode = "authorize" })
		var m meta
		env.doJSON(anonymous, http.MethodGet, "/api/v1/meta", nil, &m, http.StatusOK)
		if m.Ui.Mode != "authorize" || m.Ui.AuthorizeUrl == nil || *m.Ui.AuthorizeUrl != "https://reg.example/ui/authorize" {
			t.Fatalf("meta = %+v", m)
		}
	})
	t.Run("a logo, a support address and a minimum CLI are served when configured and absent otherwise", func(t *testing.T) {
		env := newTestEnvCfg(t, func(c *config.Config) {
			c.Brand.LogoURL = "https://cdn.example/logo.svg"
			c.Brand.SupportEmail = "help@example.test"
			c.MinCLIVersion = "0.6.100"
		})
		var m api.Meta
		env.doJSON(anonymous, http.MethodGet, "/api/v1/meta", nil, &m, http.StatusOK)
		if m.Brand == nil || m.Brand.LogoUrl == nil || *m.Brand.LogoUrl != "https://cdn.example/logo.svg" ||
			m.Brand.SupportEmail == nil || *m.Brand.SupportEmail != "help@example.test" ||
			m.MinCLIVersion == nil || *m.MinCLIVersion != "0.6.100" {
			t.Fatalf("meta = %+v brand %+v", m, m.Brand)
		}
		plain := newTestEnv(t)
		var p api.Meta
		plain.doJSON(anonymous, http.MethodGet, "/api/v1/meta", nil, &p, http.StatusOK)
		if p.Brand == nil || p.Brand.LogoUrl != nil || p.Brand.SupportEmail != nil || p.MinCLIVersion != nil {
			t.Fatalf("a deployment that configured none serves: %+v brand %+v", p, p.Brand)
		}
	})
	t.Run("the name falls back from the brand to the public host to the product", func(t *testing.T) {
		for _, c := range []struct{ base, want string }{
			{"https://reg.example:8443/base", "reg.example:8443"},
			{"registry", "registry"},
			{"", "Agentry"},
		} {
			env := newTestEnvCfg(t, func(cfg *config.Config) { cfg.BaseURL = c.base })
			var m meta
			env.doJSON(anonymous, http.MethodGet, "/api/v1/meta", nil, &m, http.StatusOK)
			if m.Brand.Name != c.want {
				t.Fatalf("baseURL %q: brand name %q, want %q", c.base, m.Brand.Name, c.want)
			}
		}
		env := newTestEnvCfg(t, func(cfg *config.Config) { cfg.BaseURL = "https://reg.example"; cfg.Brand.Name = "Chosen" })
		var m meta
		env.doJSON(anonymous, http.MethodGet, "/api/v1/meta", nil, &m, http.StatusOK)
		if m.Brand.Name != "Chosen" {
			t.Fatalf("a configured name yields to the host: %q", m.Brand.Name)
		}
	})
}
