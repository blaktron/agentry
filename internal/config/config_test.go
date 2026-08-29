package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "nonexistent-means-defaults-only.yaml"))
	if err == nil {
		t.Fatalf("expected error for explicit missing file")
	}
	// Empty path with no agentry.yaml in cwd yields pure defaults.
	cfg, err = Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Env != "dev" || !cfg.DevMode {
		t.Errorf("defaults wrong: %+v", cfg)
	}
	if cfg.HTTP.Addr != ":8080" {
		t.Errorf("default addr: %q", cfg.HTTP.Addr)
	}
}

func TestLoadFileAndEnvPrecedence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agentry.yaml")
	if err := os.WriteFile(path, []byte("env: staging\ndevMode: false\nhttp:\n  addr: \":9999\"\nlog:\n  level: debug\nauth:\n  sealingKey: \"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGENTRY_HTTP_ADDR", ":7777")
	t.Setenv("AGENTRY_AUTH_SESSION_TTL", "8h")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Env != "staging" {
		t.Errorf("file value lost: env=%q", cfg.Env)
	}
	if cfg.HTTP.Addr != ":7777" {
		t.Errorf("env must override file: addr=%q", cfg.HTTP.Addr)
	}
	if cfg.Auth.SessionTTL != 8*time.Hour {
		t.Errorf("duration env: %v", cfg.Auth.SessionTTL)
	}
	if cfg.Log.Level != "debug" {
		t.Errorf("nested file value: %q", cfg.Log.Level)
	}
}

func TestLoadRejectsUnknownKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agentry.yaml")
	if err := os.WriteFile(path, []byte("bogusKey: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("unknown config keys must be rejected")
	}
}

func TestValidateGuards(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{"prod devMode", func(c *Config) { c.Env = "prod"; c.DevMode = true }},
		{"prod unsigned", func(c *Config) { c.Env = "prod"; c.DevMode = false; c.Signing.Kind = "none" }},
		{"bad env", func(c *Config) { c.Env = "yolo" }},
		{"bad storage", func(c *Config) { c.Storage.Kind = "ftp" }},
		{"bad judge", func(c *Config) { c.Judge.Provider = "gpt" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			tc.mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatalf("expected validation error")
			}
		})
	}
}

// §12.3/§12.4 give hard ceilings on credential lifetimes. They are product
// invariants, not tunables: a deployment that raised them would still call
// itself Agentry while issuing credentials the threat model never priced in.
func TestValidateCapsCredentialTTLs(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Config)
		wantErr bool
	}{
		{"session at the cap", func(c *Config) { c.Auth.SessionTTL = MaxSessionTTL }, false},
		{"session over the 24h cap", func(c *Config) { c.Auth.SessionTTL = MaxSessionTTL + time.Minute }, true},
		{"session zero", func(c *Config) { c.Auth.SessionTTL = 0 }, true},
		{"session negative", func(c *Config) { c.Auth.SessionTTL = -time.Hour }, true},

		{"pat at the 1y cap", func(c *Config) { c.Auth.PATMaxTTL = MaxPATTTL }, false},
		{"pat over the 1y cap", func(c *Config) { c.Auth.PATMaxTTL = MaxPATTTL + time.Hour }, true},

		{"org-bound pat at the 90d cap", func(c *Config) { c.Auth.PATOrgBoundMaxTTL = MaxPATOrgBoundTTL }, false},
		{"org-bound pat over the 90d cap", func(c *Config) { c.Auth.PATOrgBoundMaxTTL = MaxPATOrgBoundTTL + time.Hour }, true},
		// An org-bound PAT is a NARROWING of a PAT; letting its ceiling exceed
		// the general one would make "org-bound" mean "longer-lived".
		{"org-bound pat above the general pat cap", func(c *Config) {
			c.Auth.PATMaxTTL = 24 * time.Hour
			c.Auth.PATOrgBoundMaxTTL = 48 * time.Hour
		}, true},

		{"sso max age at the session cap", func(c *Config) { c.Auth.SSOMaxAge = MaxSSOMaxAge }, false},
		{"sso max age past any session's life", func(c *Config) { c.Auth.SSOMaxAge = MaxSSOMaxAge + time.Hour }, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			tc.mutate(&cfg)
			err := cfg.Validate()
			if tc.wantErr && err == nil {
				t.Fatal("expected a validation error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidateGuardsTheNewSurfaces(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{"s3 without a bucket", func(c *Config) { c.Storage.Kind = "s3" }},
		{"kms without a key", func(c *Config) { c.Signing.Kind = "kms" }},
		{"unknown notify kind", func(c *Config) { c.Notify.Kind = "carrier-pigeon" }},
		{"smtp without a host", func(c *Config) { c.Notify.Kind = "smtp"; c.SMTP.From = "a@b.test" }},
		{"smtp without a sender", func(c *Config) { c.Notify.Kind = "smtp"; c.SMTP.Host = "h" }},
		{"smtp with a bad port", func(c *Config) {
			c.Notify.Kind, c.SMTP.Host, c.SMTP.From, c.SMTP.Port = "smtp", "h", "a@b.test", 70000
		}},
		// A password over a cleartext session is a password disclosed.
		{"smtp auth without TLS outside dev", func(c *Config) {
			c.DevMode = false
			c.Auth.SealingKey = "x"
			c.Notify.Kind, c.SMTP.Host, c.SMTP.From = "smtp", "h", "a@b.test"
			c.SMTP.Username, c.SMTP.StartTLS = "u", false
		}},
		{"negative trusted proxies", func(c *Config) { c.HTTP.TrustedProxies = -1 }},
		{"zero quota", func(c *Config) { c.Limits.GitPushesPerHour = 0 }},
		{"unparseable signing window", func(c *Config) { c.Signing.NotAfter = "next tuesday" }},
		{"inverted signing window", func(c *Config) {
			c.Signing.NotBefore = "2026-06-01T00:00:00Z"
			c.Signing.NotAfter = "2026-01-01T00:00:00Z"
		}},
		{"additional key with no id", func(c *Config) {
			c.Signing.AdditionalKeys = []VerificationKey{{PublicKeyPEM: "pem"}}
		}},
		{"additional key with both pem and file", func(c *Config) {
			c.Signing.AdditionalKeys = []VerificationKey{{KeyID: "k", PublicKeyPEM: "pem", PublicKeyFile: "/f"}}
		}},
		{"additional key with neither pem nor file", func(c *Config) {
			c.Signing.AdditionalKeys = []VerificationKey{{KeyID: "k"}}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			tc.mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("expected a validation error")
			}
		})
	}
}

// mailpit speaks plaintext on 1025 and needs no credentials; the dev default
// must not be refused by the guard that protects real relays.
func TestSMTPWithoutAuthNeedsNoTLS(t *testing.T) {
	cfg := Default()
	cfg.Notify.Kind = "smtp"
	cfg.SMTP.Host, cfg.SMTP.Port, cfg.SMTP.From = "mailpit", 1025, "a@b.test"
	cfg.SMTP.StartTLS = false
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the mailpit dev configuration was refused: %v", err)
	}
}

// The §19 defaults are the contract the entitlements resolver hands out.
func TestDefaultLimitsMatchSection19(t *testing.T) {
	l := Default().Limits
	for _, c := range []struct {
		name string
		got  int64
		want int64
	}{
		{"agents per user namespace", int64(l.AgentsPerUserNamespace), 200},
		{"agents per org namespace", int64(l.AgentsPerOrgNamespace), 500},
		{"versions per day", int64(l.VersionsPerDay), 20},
		{"webhook endpoints per org", int64(l.WebhookEndpointsPerOrg), 20},
		{"webhook deliveries per second", int64(l.WebhookDeliveriesPerSecond), 5},
		{"git pushes per hour", int64(l.GitPushesPerHour), 60},
		{"archive max bytes", l.ArchiveMaxBytes, 10 << 20},
		{"archive max files", int64(l.ArchiveMaxFiles), 2000},
		{"archive max file bytes", l.ArchiveMaxFileBytes, 2 << 20},
		{"archive max image bytes", l.ArchiveMaxImageFileBytes, 5 << 20},
	} {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d (§19)", c.name, c.got, c.want)
		}
	}
}

func TestNewEnvOverridesApply(t *testing.T) {
	t.Setenv("AGENTRY_OTEL_ENDPOINT", "http://collector:4318")
	t.Setenv("AGENTRY_TRUSTED_PROXIES", "2")
	t.Setenv("AGENTRY_NOTIFY_KIND", "smtp")
	t.Setenv("AGENTRY_SMTP_HOST", "relay.example")
	t.Setenv("AGENTRY_SMTP_PORT", "2525")
	t.Setenv("AGENTRY_SMTP_FROM", "Agentry <no-reply@example.test>")
	t.Setenv("AGENTRY_SMTP_STARTTLS", "true")
	t.Setenv("AGENTRY_LIMITS_GIT_PUSHES_PER_HOUR", "120")
	t.Setenv("AGENTRY_LIMITS_ARCHIVE_MAX_BYTES", "20971520")
	t.Setenv("AGENTRY_STORAGE_S3_PREFIX", "staging")
	t.Setenv("AGENTRY_STORAGE_S3_USE_PATH_STYLE", "true")
	t.Setenv("AGENTRY_SIGNING_NOT_AFTER", "2027-01-01T00:00:00Z")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Telemetry.OTLPEndpoint != "http://collector:4318" {
		t.Errorf("otlp endpoint = %q", cfg.Telemetry.OTLPEndpoint)
	}
	if cfg.HTTP.TrustedProxies != 2 {
		t.Errorf("trustedProxies = %d", cfg.HTTP.TrustedProxies)
	}
	if cfg.Notify.Kind != "smtp" || cfg.SMTP.Port != 2525 || !cfg.SMTP.StartTLS {
		t.Errorf("smtp config = %+v", cfg.SMTP)
	}
	if cfg.Limits.GitPushesPerHour != 120 {
		t.Errorf("gitPushesPerHour = %d", cfg.Limits.GitPushesPerHour)
	}
	if cfg.Limits.ArchiveMaxBytes != 20<<20 {
		t.Errorf("archiveMaxBytes = %d", cfg.Limits.ArchiveMaxBytes)
	}
	if cfg.Storage.S3Prefix != "staging" || !cfg.Storage.S3UsePathStyle {
		t.Errorf("storage = %+v", cfg.Storage)
	}
	if cfg.Signing.NotAfter != "2027-01-01T00:00:00Z" {
		t.Errorf("signing notAfter = %q", cfg.Signing.NotAfter)
	}
}
