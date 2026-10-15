package api_test

import (
	"net/http"
	"testing"

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
}
