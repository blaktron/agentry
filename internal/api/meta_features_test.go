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

// /meta says which optional parts a deployment has: a signing key, a Redis,
// a judge. A bare deployment has none of them; each one configured is
// reported, and only that one.
func TestMetaReportsWhichFeaturesTheDeploymentHas(t *testing.T) {
	features := func(cfgFn func(*config.Config)) map[string]bool {
		t.Helper()
		env := newTestEnvCfg(t, cfgFn)
		var meta struct {
			Features map[string]bool `json:"features"`
		}
		env.doJSON(anonymous, http.MethodGet, "/api/v1/meta", nil, &meta, http.StatusOK)
		return meta.Features
	}
	bare := features(nil)
	for _, flag := range []string{"redis", "signing", "judge", "s3"} {
		if on, ok := bare[flag]; !ok || on {
			t.Fatalf("a bare deployment reports %s = %v (present %v), want false", flag, on, ok)
		}
	}
	for flag, set := range map[string]func(*config.Config){
		"redis":   func(c *config.Config) { c.Redis.URL = "redis://127.0.0.1:6379" },
		"signing": func(c *config.Config) { c.Signing.Kind, c.Signing.KeyFile = "file", writeTestSigningKey(t) },
		"judge":   func(c *config.Config) { c.Judge.Provider = "static" },
	} {
		got := features(set)
		if !got[flag] {
			t.Fatalf("with %s configured, features = %v", flag, got)
		}
		for _, other := range []string{"redis", "signing", "judge", "s3"} {
			if other != flag && got[other] {
				t.Fatalf("with only %s configured, %s is reported too: %v", flag, other, got)
			}
		}
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
