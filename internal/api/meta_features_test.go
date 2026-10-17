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

// /meta advertises no native credential surface: there is none, so there
// is no flag a client could read to decide whether to offer a password or
// TOTP form.
func TestMetaAdvertisesNoNativeCredentials(t *testing.T) {
	env := newTestEnv(t)
	var meta struct {
		Features map[string]bool `json:"features"`
	}
	env.doJSON(anonymous, http.MethodGet, "/api/v1/meta", nil, &meta, http.StatusOK)
	if _, ok := meta.Features["externalOnly"]; ok {
		t.Fatalf("meta.features carries externalOnly: %v", meta.Features)
	}
}

// /meta reports whether the public-publish second-factor gate is enforced:
// the site says "publishing requires one" only when it is.
// The gate is on under requireIdpMFA, and never in dev mode.
func TestMetaReportsPublicPublish2FA(t *testing.T) {
	cases := []struct {
		name     string
		dev, mfa bool
		want     bool
	}{
		{"no IdP evidence asked for", false, false, false},
		{"IdP MFA evidence required", false, true, true},
		{"dev mode", true, false, false},
		{"dev mode with IdP MFA evidence required", true, true, false},
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
