package api_test

import (
	"net/http"
	"testing"

	"github.com/blaktron/agentry/internal/config"
)

// /meta tells the web tier whether accounts live in a directory service
// (agentry#21), so it can stop offering TOTP and password forms that 410.
func TestMetaReportsExternalOnly(t *testing.T) {
	for _, ext := range []bool{false, true} {
		env := newTestEnvCfg(t, func(c *config.Config) { c.Auth.ExternalOnly = ext })
		var meta struct {
			Features map[string]bool `json:"features"`
		}
		env.doJSON(anonymous, http.MethodGet, "/api/v1/meta", nil, &meta, http.StatusOK)
		if got, ok := meta.Features["externalOnly"]; !ok || got != ext {
			t.Fatalf("externalOnly=%v: meta.features.externalOnly = %v (present %v)", ext, got, ok)
		}
	}
}
