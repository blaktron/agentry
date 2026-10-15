package api_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/blaktron/agentry/internal/config"
)

// /meta tells the web tier whether accounts live in a directory service,
// so it can stop offering TOTP and password forms that 410.
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

// /meta reports whether the public-publish second-factor gate is enforced:
// the site says "publishing requires one" only when it is.
// The gate is off in dev mode, off under externalOnly, and back on under
// externalOnly with requireIdpMFA.
func TestMetaReportsPublicPublish2FA(t *testing.T) {
	cases := []struct {
		name          string
		dev, ext, mfa bool
		want          bool
	}{
		{"native accounts", false, false, false, true},
		{"directory only", false, true, false, false},
		{"directory with IdP MFA evidence", false, true, true, true},
		{"dev mode", true, false, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env := newTestEnvCfg(t, func(cfg *config.Config) {
				cfg.DevMode = c.dev
				if !c.dev {
					// Outside dev mode the server insists on a sealing key
					// and a real signing key; the flag is what is under test.
					cfg.Auth.SealingKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
					cfg.Signing.Kind, cfg.Signing.KeyFile = "file", writeTestSigningKey(t)
				}
				cfg.Auth.ExternalOnly = c.ext
				cfg.Auth.RequireIdPMFA = c.mfa
			})
			var meta struct {
				Features map[string]bool `json:"features"`
			}
			env.doJSON(anonymous, http.MethodGet, "/api/v1/meta", nil, &meta, http.StatusOK)
			if got, ok := meta.Features["publicPublish2FA"]; !ok || got != c.want {
				t.Fatalf("meta.features.publicPublish2FA = %v (present %v), want %v", got, ok, c.want)
			}
		})
	}
}

// writeTestSigningKey writes a throwaway P-256 key for a non-dev test server.
func writeTestSigningKey(t *testing.T) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "signing.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
