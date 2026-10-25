package config

import (
	"errors"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	// A file named explicitly must exist: its absence is the reading
	// refusal itself, not a later default-validation error (the defaults
	// alone are refused too, below, so any error would not tell them apart).
	missing := filepath.Join(t.TempDir(), "nonexistent-means-defaults-only.yaml")
	cfg, err := Load(missing)
	if !errors.Is(err, fs.ErrNotExist) || !strings.Contains(err.Error(), "reading "+missing) {
		t.Fatalf("Load of an explicit missing file: err = %v, want the reading refusal for it", err)
	}
	// Empty path with no agentry.yaml in cwd yields pure defaults — and the
	// pure defaults refuse to run: dev mode is opt-in, so with no
	// sealing key configured the load fails at the validation, naming it,
	// rather than starting on a public constant.
	if _, err = Load(""); err == nil || !strings.Contains(err.Error(), "sealingKey") {
		t.Fatalf("Load of pure defaults: err = %v, want the sealing-key refusal", err)
	}
	cfg = Default()
	if cfg.Env != "dev" || cfg.DevMode {
		t.Errorf("defaults wrong: %+v", cfg)
	}
	// Opting in is one line, and then the defaults load.
	t.Setenv("AGENTRY_DEV_MODE", "true")
	if cfg, err = Load(""); err != nil || !cfg.DevMode {
		t.Fatalf("Load with AGENTRY_DEV_MODE=true: %v %+v", err, cfg.DevMode)
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
	t.Setenv("AGENTRY_AUTH_TRUSTED_DEVICE_TTL", "72h")

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
	if cfg.Auth.TrustedDeviceTTL != 72*time.Hour {
		t.Errorf("trusted-device duration env: %v, want 72h", cfg.Auth.TrustedDeviceTTL)
	}
	if cfg.Log.Level != "debug" {
		t.Errorf("nested file value: %q", cfg.Log.Level)
	}
}

func TestLoadRejectsUnknownKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agentry.yaml")
	// Everything but the unknown key would load (dev mode opted in), so no
	// other guard can answer for the refusal.
	if err := os.WriteFile(path, []byte("devMode: true\nbogusKey: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "parsing "+path) || !strings.Contains(err.Error(), "bogusKey") {
		t.Fatalf("Load with an unknown key: err = %v, want the parsing refusal naming bogusKey", err)
	}
	// The same file without the key loads.
	if err := os.WriteFile(path, []byte("devMode: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("Load without the unknown key: %v", err)
	}
}

// TestLoadRejectsUnknownNestedKeys: a key the configuration does not have
// is refused inside a known section too, so a setting nothing reads stops
// the server rather than being ignored.
func TestLoadRejectsUnknownNestedKeys(t *testing.T) {
	for _, doc := range []string{
		"auth:\n  idpAdminURL: http://directory:9000\n",
		"social:\n  authentik:\n    clientId: c\n",
		"social:\n  google:\n    clientId: c\n",
		"auth:\n  externalOnly: true\n",
	} {
		path := filepath.Join(t.TempDir(), "agentry.yaml")
		if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Errorf("loaded %q, want a refusal", doc)
		}
	}
}

// devDefault is the baseline with dev mode opted in: what a throwaway
// stack runs, and what tests of the OTHER guards start from.
func devDefault() Config {
	c := Default()
	c.DevMode = true
	return c
}

func TestValidateGuards(t *testing.T) {
	// Configure the other non-dev guards so a missing mode or signing guard
	// cannot hide behind the refusal from an unrelated invalid setting.
	nonDev := func(c *Config) {
		c.DevMode = false
		c.Signing.Kind = "file"
		c.Auth.SealingKey = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
	}
	valid := devDefault()
	nonDev(&valid)
	valid.Env = "prod"
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid production configuration was refused: %v", err)
	}
	cases := []struct {
		name   string
		want   string
		mutate func(*Config)
	}{
		{"prod devMode", "devMode is allowed only with env: dev", func(c *Config) { nonDev(c); c.Env = "prod"; c.DevMode = true }},
		{"staging devMode", "devMode is allowed only with env: dev", func(c *Config) { nonDev(c); c.Env = "staging"; c.DevMode = true }},
		{"no sealing key outside dev mode", "auth.sealingKey", func(c *Config) { c.DevMode = false; c.Auth.SealingKey = "" }},
		{"prod unsigned", "signing.kind none is not allowed in prod", func(c *Config) { nonDev(c); c.Env = "prod"; c.Signing.Kind = "none" }},
		{"bad env", "env must be", func(c *Config) { c.Env = "yolo" }},
		{"bad storage", "storage.kind", func(c *Config) { c.Storage.Kind = "ftp" }},
		{"bad judge", "judge.provider", func(c *Config) { c.Judge.Provider = "gpt" }},
		// Honouring an inbound request id needs a hop that sets it; the flag
		// without a hop count is a contradiction, not a default.
		{"proxyRequestID without a hop", "http.proxyRequestID", func(c *Config) { c.HTTP.ProxyRequestID = true; c.HTTP.TrustedProxies = 0 }},
		{"bad audit stream kind", "audit.streamKind", func(c *Config) { c.Audit.StreamKind = "kafka" }},
		// A staff domain that could never match an address would switch the
		// rule off silently.
		{"staff domain with an at", "auth.staffDomain", func(c *Config) { c.Auth.StaffOrg = "agentry"; c.Auth.StaffDomain = "@secureagentry.net" }},
		{"staff domain with a leading dot", "auth.staffDomain", func(c *Config) { c.Auth.StaffOrg = "agentry"; c.Auth.StaffDomain = ".secureagentry.net" }},
		{"staff domain in capitals", "auth.staffDomain", func(c *Config) { c.Auth.StaffOrg = "agentry"; c.Auth.StaffDomain = "SecureAgentry.net" }},
		{"staff domain of one label", "auth.staffDomain", func(c *Config) { c.Auth.StaffOrg = "agentry"; c.Auth.StaffDomain = "localhost" }},
		// Half a rule is refused: an organization with no domain would admit
		// anyone, a domain with no organization names nobody.
		{"staff org without a domain", "auth.staffOrg and auth.staffDomain", func(c *Config) { c.Auth.StaffOrg = "agentry" }},
		{"staff domain without an org", "auth.staffOrg and auth.staffDomain", func(c *Config) { c.Auth.StaffDomain = "secureagentry.net" }},
		{"staff org that is no handle", "auth.staffOrg must be", func(c *Config) { c.Auth.StaffOrg = "Agentry Staff"; c.Auth.StaffDomain = "secureagentry.net" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := devDefault()
			tc.mutate(&cfg)
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate() = %v, want a refusal naming %q", err, tc.want)
			}
		})
	}
}

// The pg queue driver and its jobs table are gone: a configuration that
// still names it is refused at start with a sentence that says so, not run
// on a driver that no longer exists.
func TestValidateRefusesTheRemovedPGQueueDriver(t *testing.T) {
	cfg := devDefault()
	cfg.Queue.Driver = "pg"
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "removed") || !strings.Contains(err.Error(), "river") {
		t.Fatalf("queue.driver pg: %v, want a refusal that says it was removed and names river", err)
	}
	cfg.Queue.Driver = "river"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("queue.driver river: %v", err)
	}
}

// Credential lifetimes have hard ceilings. They are product
// invariants, not tunables: a deployment that raised them would still call
// itself Agentry while issuing credentials the threat model never priced in.
func TestValidateCapsCredentialTTLs(t *testing.T) {
	// PAT and SSO boundaries come from the contract, not the production
	// constants: raising a ceiling must not move these inputs with it.
	cases := []struct {
		name    string
		mutate  func(*Config)
		wantErr bool
	}{
		{"session at the cap", func(c *Config) { c.Auth.SessionTTL = MaxSessionTTL }, false},
		{"session over the 24h cap", func(c *Config) { c.Auth.SessionTTL = MaxSessionTTL + time.Minute }, true},
		{"session zero", func(c *Config) { c.Auth.SessionTTL = 0 }, true},
		{"session negative", func(c *Config) { c.Auth.SessionTTL = -time.Hour }, true},

		{"pat at the 1y cap", func(c *Config) { c.Auth.PATMaxTTL = 365 * 24 * time.Hour }, false},
		{"pat over the 1y cap", func(c *Config) { c.Auth.PATMaxTTL = 365*24*time.Hour + time.Hour }, true},

		{"org-bound pat at the 90d cap", func(c *Config) { c.Auth.PATOrgBoundMaxTTL = 90 * 24 * time.Hour }, false},
		{"org-bound pat over the 90d cap", func(c *Config) { c.Auth.PATOrgBoundMaxTTL = 90*24*time.Hour + time.Hour }, true},
		// An org-bound PAT is a NARROWING of a PAT; letting its ceiling exceed
		// the general one would make "org-bound" mean "longer-lived".
		{"org-bound pat above the general pat cap", func(c *Config) {
			c.Auth.PATMaxTTL = 24 * time.Hour
			c.Auth.PATOrgBoundMaxTTL = 48 * time.Hour
		}, true},

		{"sso max age at the session cap", func(c *Config) { c.Auth.SSOMaxAge = 24 * time.Hour }, false},
		{"sso max age past any session's life", func(c *Config) { c.Auth.SSOMaxAge = 24*time.Hour + time.Hour }, true},

		// A trusted device is the second browser credential class. It
		// exceeds MaxSessionTTL by design — that is precisely what makes it its
		// own class rather than a longer session — so what these cases prove is
		// that its OWN ceiling binds, and that a deployment cannot price in a
		// credential the threat model never considered by raising the knob.
		{"trusted device at the 30d cap", func(c *Config) { c.Auth.TrustedDeviceTTL = MaxTrustedDeviceTTL }, false},
		{"trusted device over the 30d cap", func(c *Config) { c.Auth.TrustedDeviceTTL = MaxTrustedDeviceTTL + time.Hour }, true},
		{"trusted device zero", func(c *Config) { c.Auth.TrustedDeviceTTL = 0 }, true},
		{"trusted device negative", func(c *Config) { c.Auth.TrustedDeviceTTL = -time.Hour }, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := devDefault()
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

// TestTrustedDeviceIsASecondClassNotALongerSession guards the invariant rather
// than the feature. Introducing a browser credential that outlives the
// session cap is only honest if the session cap itself is untouched, so a
// reader sees one ceiling of two rather than a limit that was quietly
// raised. If someone later "simplifies" the two constants into one, this
// fails and the simplification has to be argued rather than slipped in.
func TestTrustedDeviceIsASecondClassNotALongerSession(t *testing.T) {
	if MaxSessionTTL != 24*time.Hour {
		t.Fatalf("MaxSessionTTL is %s, want 24h: the session cap moved", MaxSessionTTL)
	}
	if MaxTrustedDeviceTTL != 30*24*time.Hour {
		t.Fatalf("MaxTrustedDeviceTTL is %s, want 30d", MaxTrustedDeviceTTL)
	}
	if MaxTrustedDeviceTTL <= MaxSessionTTL {
		t.Fatal("a trusted device must outlive a session, or it is not a second credential class and remembering one grants nothing")
	}
	if got := Default().Auth.TrustedDeviceTTL; got != MaxTrustedDeviceTTL {
		t.Fatalf("the default trusted-device lifetime is %s, want the %s ceiling — the default is what a deployment gets without asking", got, MaxTrustedDeviceTTL)
	}
	// The session default is unchanged: adding the second class must not have
	// moved the first one's default either.
	if got := Default().Auth.SessionTTL; got != 24*time.Hour {
		t.Fatalf("the default session lifetime is %s, want 24h", got)
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
		{"negative knowledge cap", func(c *Config) { c.Limits.KnowledgeBytesPerAccount = -1 }},
		{"a short knowledge sealing key", func(c *Config) { c.Knowledge.SealingKey = "c2hvcnQ=" }},
		// A key of its own: the one that opens webhook secrets
		// must not also open every knowledge pack.
		{"the knowledge key is the auth key", func(c *Config) {
			c.Auth.SealingKey = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
			c.Knowledge.SealingKey = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
		}},
		{"zero git concurrency per IP", func(c *Config) { c.Limits.GitConcurrentPerIP = 0 }},
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
			cfg := devDefault()
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
	cfg := devDefault()
	cfg.Notify.Kind = "smtp"
	cfg.SMTP.Host, cfg.SMTP.Port, cfg.SMTP.From = "mailpit", 1025, "a@b.test"
	cfg.SMTP.StartTLS = false
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the mailpit dev configuration was refused: %v", err)
	}
}

// The quota defaults are the contract the entitlements resolver hands out.
func TestDefaultLimits(t *testing.T) {
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
		{"git concurrent per IP", int64(l.GitConcurrentPerIP), 20},
		{"archive max bytes", l.ArchiveMaxBytes, 10 << 20},
		{"archive max files", int64(l.ArchiveMaxFiles), 2000},
		{"archive max file bytes", l.ArchiveMaxFileBytes, 2 << 20},
		{"archive max image bytes", l.ArchiveMaxImageFileBytes, 5 << 20},
	} {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
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
	t.Setenv("AGENTRY_LIMITS_SSH_KEY_OFFERS_PER_MIN", "30")
	t.Setenv("AGENTRY_LIMITS_GIT_CONCURRENT_PER_IP", "8")
	t.Setenv("AGENTRY_LIMITS_ARCHIVE_MAX_BYTES", "20971520")
	t.Setenv("AGENTRY_LIMITS_REPO_WARN_BYTES", "31457280")
	t.Setenv("AGENTRY_LIMITS_ARCHIVE_MAX_TEXT_BYTES", "2097152")
	t.Setenv("AGENTRY_STORAGE_S3_PREFIX", "staging")
	t.Setenv("AGENTRY_STORAGE_S3_USE_PATH_STYLE", "true")
	t.Setenv("AGENTRY_SIGNING_NOT_AFTER", "2027-01-01T00:00:00Z")
	t.Setenv("AGENTRY_DEV_MODE", "true") // the knobs under test, on the dev baseline

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
	if cfg.Limits.GitPushesPerHour != 120 || cfg.Limits.SSHKeyOffersPerMin != 30 {
		t.Errorf("gitPushesPerHour = %d, sshKeyOffersPerMin = %d", cfg.Limits.GitPushesPerHour, cfg.Limits.SSHKeyOffersPerMin)
	}
	if cfg.Limits.GitConcurrentPerIP != 8 {
		t.Errorf("gitConcurrentPerIP = %d, want 8", cfg.Limits.GitConcurrentPerIP)
	}
	if cfg.Limits.RepoWarnBytes != 31457280 || cfg.Limits.ArchiveMaxTextBytes != 2097152 {
		t.Errorf("repoWarnBytes = %d, archiveMaxTextBytes = %d", cfg.Limits.RepoWarnBytes, cfg.Limits.ArchiveMaxTextBytes)
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

// The judge wires from three env vars (type, base URL, key) plus the model
// override. AGENTRY_JUDGE_TYPE wins over the legacy AGENTRY_JUDGE_PROVIDER,
// and openai/anthropic without endpoint credentials refuse to start.
func TestJudgeEnvConfig(t *testing.T) {
	t.Setenv("AGENTRY_JUDGE_TYPE", "openai")
	t.Setenv("AGENTRY_JUDGE_BASE_URL", "https://llm.example.internal")
	t.Setenv("AGENTRY_JUDGE_API_KEY", "sk-test")
	t.Setenv("AGENTRY_JUDGE_MODEL", "gpt-test")
	t.Setenv("AGENTRY_DEV_MODE", "true") // the knobs under test, on the dev baseline

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Judge.Provider != "openai" || cfg.Judge.BaseURL != "https://llm.example.internal" ||
		cfg.Judge.APIKey != "sk-test" || cfg.Judge.Model != "gpt-test" {
		t.Errorf("judge env not applied: %+v", cfg.Judge)
	}

	// Type wins when both spellings are set.
	t.Setenv("AGENTRY_JUDGE_PROVIDER", "anthropic")
	cfg, err = Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Judge.Provider != "openai" {
		t.Errorf("AGENTRY_JUDGE_TYPE must win over AGENTRY_JUDGE_PROVIDER, got %q", cfg.Judge.Provider)
	}

	// An HTTP protocol without its credentials is a startup error, not a
	// silent fallback: the operator meant to have a judge.
	t.Setenv("AGENTRY_JUDGE_TYPE", "anthropic")
	t.Setenv("AGENTRY_JUDGE_PROVIDER", "")
	t.Setenv("AGENTRY_JUDGE_API_KEY", "")
	if _, err := Load(""); err == nil {
		t.Error("anthropic judge without apiKey must fail validation")
	}

	// The typesafe judge: the key is
	// required and the model id is pinned — an alias is refused at startup.
	t.Setenv("AGENTRY_JUDGE_TYPE", "typesafe")
	t.Setenv("AGENTRY_JUDGE_BASE_URL", "")
	t.Setenv("AGENTRY_JUDGE_MODEL", "")
	if _, err := Load(""); err == nil {
		t.Error("typesafe judge without apiKey must fail validation")
	}
	t.Setenv("AGENTRY_JUDGE_API_KEY", "apikey_test")
	if cfg, err := Load(""); err != nil || cfg.Judge.Provider != "typesafe" {
		t.Errorf("typesafe judge with a key and no model must load (the provider pins the default): %v", err)
	}
	t.Setenv("AGENTRY_JUDGE_MODEL", "jev-1.13.0")
	if cfg, err := Load(""); err != nil || cfg.Judge.Model != "jev-1.13.0" {
		t.Errorf("a pinned typesafe model id must load: %v", err)
	}
	// An alias loads here and is refused by the judge factory at startup
	// (scan.PinnedJudgeModel): one rule, where the provider is.
}

// The brokered web search wires from three env vars; none is
// the default, a provider needs its key, and an unknown name refuses to
// start. The model-input budget has a default and must stay positive.
func TestWebSearchEnvConfig(t *testing.T) {
	t.Setenv("AGENTRY_DEV_MODE", "true")
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.WebSearch.Provider != "" || cfg.Limits.ModelInputPerMin != 120 {
		t.Fatalf("defaults: %+v, %d", cfg.WebSearch, cfg.Limits.ModelInputPerMin)
	}
	t.Setenv("AGENTRY_WEB_SEARCH_PROVIDER", "youcom")
	if _, err := Load(""); err == nil {
		t.Error("a provider without its key must fail validation")
	}
	t.Setenv("AGENTRY_WEB_SEARCH_API_KEY", "ydc-test")
	t.Setenv("AGENTRY_WEB_SEARCH_BASE_URL", "https://search.example.internal")
	t.Setenv("AGENTRY_LIMITS_MODEL_INPUT_PER_MIN", "30")
	cfg, err = Load("")
	if err != nil || cfg.WebSearch.Provider != "youcom" || cfg.WebSearch.APIKey != "ydc-test" ||
		cfg.WebSearch.BaseURL != "https://search.example.internal" || cfg.Limits.ModelInputPerMin != 30 {
		t.Fatalf("env not applied: %v %+v %d", err, cfg.WebSearch, cfg.Limits.ModelInputPerMin)
	}
	t.Setenv("AGENTRY_WEB_SEARCH_PROVIDER", "brave")
	t.Setenv("AGENTRY_WEB_SEARCH_BASE_URL", "")
	if cfg, err = Load(""); err != nil || cfg.WebSearch.Provider != "brave" {
		t.Fatalf("brave: %v %+v", err, cfg.WebSearch)
	}
	for _, p := range []string{"tavily", "exa", "perplexity"} {
		t.Setenv("AGENTRY_WEB_SEARCH_PROVIDER", p)
		if cfg, err = Load(""); err != nil || cfg.WebSearch.Provider != p {
			t.Fatalf("%s: %v %+v", p, err, cfg.WebSearch)
		}
	}
	t.Setenv("AGENTRY_WEB_SEARCH_PROVIDER", "fake")
	if _, err := Load(""); err == nil {
		t.Error("an unknown provider (the tests' fake included) must fail validation")
	}
	t.Setenv("AGENTRY_WEB_SEARCH_PROVIDER", "none")
	t.Setenv("AGENTRY_LIMITS_MODEL_INPUT_PER_MIN", "0")
	if _, err := Load(""); err == nil {
		t.Error("a zero model-input budget must fail validation")
	}
}

func TestStaffOrgAcceptsAHandleAndABareDomain(t *testing.T) {
	cfg := devDefault()
	cfg.Auth.StaffOrg, cfg.Auth.StaffDomain = "agentry", "secureagentry.net"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("a handle and a bare domain were refused: %v", err)
	}
	t.Setenv("AGENTRY_STAFF_ORG", "agentry")
	t.Setenv("AGENTRY_STAFF_DOMAIN", "secureagentry.net")
	got := devDefault()
	if err := applyEnv(&got); err != nil || got.Auth.StaffOrg != "agentry" || got.Auth.StaffDomain != "secureagentry.net" {
		t.Fatalf("the environment did not set them: %q %q %v", got.Auth.StaffOrg, got.Auth.StaffDomain, err)
	}
}

func TestParseCIDRs(t *testing.T) {
	ok := []struct{ in, want string }{
		{"10.0.0.0/8", "10.0.0.0/8"},
		{"172.16.0.0/12", "172.16.0.0/12"},
		{" 127.0.0.1 ", "127.0.0.1/32"},
		{"::1", "::1/128"},
		{"::ffff:10.1.2.3", "10.1.2.3/32"},
		{"fd00::/8", "fd00::/8"},
	}
	for _, c := range ok {
		got, err := ParseCIDRs([]string{c.in})
		if err != nil || len(got) != 1 || got[0].String() != c.want {
			t.Errorf("ParseCIDRs(%q) = %v, %v; want %s", c.in, got, err, c.want)
		}
	}
	for _, bad := range []string{"10.0.0.5/8", "10.0.0.0/33", "::ffff:10.0.0.0/104", "not-an-ip", "", "fe80::1%eth0"} {
		if _, err := ParseCIDRs([]string{bad}); err == nil {
			t.Errorf("ParseCIDRs(%q) accepted", bad)
		}
	}
	p, _ := ParseCIDRs([]string{"172.16.0.0/12"})
	for addr, want := range map[string]bool{"172.18.0.5": true, "::ffff:172.18.0.5": true, "192.168.1.1": false} {
		if got := InCIDRs(p, netip.MustParseAddr(addr)); got != want {
			t.Errorf("InCIDRs(172.16.0.0/12, %s) = %v, want %v", addr, got, want)
		}
	}
}

func TestSSHProxyProtocolCIDRsFromEnv(t *testing.T) {
	t.Setenv("AGENTRY_DEV_MODE", "true")
	t.Setenv("AGENTRY_GIT_SSH_PROXY_PROTOCOL_CIDRS", "10.0.0.0/8, 192.168.4.2")
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(cfg.Git.SSHProxyProtocolCIDRs, "|"); got != "10.0.0.0/8|192.168.4.2" {
		t.Fatalf("sshProxyProtocolCIDRs = %q", got)
	}
	t.Setenv("AGENTRY_GIT_SSH_PROXY_PROTOCOL_CIDRS", "10.0.0.1/8")
	if _, err := Load(""); err == nil || !strings.Contains(err.Error(), "sshProxyProtocolCIDRs") {
		t.Fatalf("a CIDR with host bits set was accepted: %v", err)
	}
}

func TestTrustedProxyCIDRsFromEnv(t *testing.T) {
	t.Setenv("AGENTRY_DEV_MODE", "true")
	t.Setenv("AGENTRY_TRUSTED_PROXIES", "1")
	t.Setenv("AGENTRY_TRUSTED_PROXY_CIDRS", "172.16.0.0/12,192.168.0.0/16")
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(cfg.HTTP.TrustedProxyCIDRs, "|"); got != "172.16.0.0/12|192.168.0.0/16" {
		t.Fatalf("trustedProxyCIDRs = %q", got)
	}
	t.Setenv("AGENTRY_TRUSTED_PROXY_CIDRS", "172.16.0.1/12")
	if _, err := Load(""); err == nil || !strings.Contains(err.Error(), "trustedProxyCIDRs") {
		t.Fatalf("a CIDR with host bits set was accepted: %v", err)
	}
}

func TestKnowledgeSealingKeyFromEnv(t *testing.T) {
	t.Setenv("AGENTRY_KNOWLEDGE_SEALING_KEY", "a25vd2xlZGdlLWtub3dsZWRnZS1rbm93bGVkZ2UtISE=")
	t.Setenv("AGENTRY_KNOWLEDGE_BYTES_PER_ACCOUNT", "104857600")
	t.Setenv("AGENTRY_AUTH_SEALING_KEY", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")
	c, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if c.Knowledge.SealingKey != "a25vd2xlZGdlLWtub3dsZWRnZS1rbm93bGVkZ2UtISE=" || c.Limits.KnowledgeBytesPerAccount != 100<<20 {
		t.Fatalf("knowledge = %+v, cap %d", c.Knowledge, c.Limits.KnowledgeBytesPerAccount)
	}
}

// TestSignInOIDCIsOneProvider: the sign-in OpenID provider is auth.oidc,
// "oidc" unless it says otherwise; "authentik" is the one other id, which
// a deployment whose accounts are linked under it keeps.
func TestSignInOIDCIsOneProvider(t *testing.T) {
	cfg := devDefault()
	if _, ok := cfg.SignInOIDC(); ok {
		t.Fatal("a provider with nothing configured")
	}

	cfg.Auth.OIDC = OIDCProvider{Issuer: "https://idp.example/", ClientID: "c", ClientSecret: "s", Scopes: []string{"openid"}, DisplayName: "Example SSO"}
	p, ok := cfg.SignInOIDC()
	if !ok || p.ID != OIDCProviderID || p.Issuer != "https://idp.example/" || p.DisplayName != "Example SSO" || len(p.Scopes) != 1 {
		t.Fatalf("auth.oidc: %+v %v", p, ok)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("auth.oidc refused: %v", err)
	}

	cfg.Auth.OIDC.ID = AuthentikProviderID
	if p, _ := cfg.SignInOIDC(); p.ID != AuthentikProviderID {
		t.Fatalf("auth.oidc with id authentik: %+v", p)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("auth.oidc with id authentik refused: %v", err)
	}

	for name, tc := range map[string]struct {
		cfg   func(*Config)
		names string
	}{
		"an id no route serves": {func(c *Config) {
			c.Auth.OIDC = OIDCProvider{ID: "google", Issuer: "https://idp.example/", ClientID: "c", ClientSecret: "s"}
		}, "auth.oidc.id"},
		"no issuer": {func(c *Config) { c.Auth.OIDC = OIDCProvider{ClientID: "c", ClientSecret: "s"} }, "issuer"},
	} {
		c := devDefault()
		tc.cfg(&c)
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), tc.names) {
			t.Errorf("%s: %v, want a refusal naming %s", name, err, tc.names)
		}
	}
}

func TestSignInOIDCFromEnv(t *testing.T) {
	t.Setenv("AGENTRY_DEV_MODE", "true")
	t.Setenv("AGENTRY_AUTH_OIDC_ID", "authentik")
	t.Setenv("AGENTRY_AUTH_OIDC_ISSUER", "https://idp.example/")
	t.Setenv("AGENTRY_AUTH_OIDC_CLIENT_ID", "client")
	t.Setenv("AGENTRY_AUTH_OIDC_CLIENT_SECRET", "secret")
	t.Setenv("AGENTRY_AUTH_OIDC_SCOPES", "openid,email,profile,agentry")
	t.Setenv("AGENTRY_AUTH_OIDC_DISPLAY_NAME", "Example SSO")
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	p, ok := cfg.SignInOIDC()
	if !ok || p.ID != "authentik" || p.Issuer != "https://idp.example/" || p.ClientID != "client" || p.ClientSecret != "secret" ||
		strings.Join(p.Scopes, " ") != "openid email profile agentry" || p.DisplayName != "Example SSO" {
		t.Fatalf("from the environment: %+v %v", p, ok)
	}
}

// A judge's key goes to its base URL, so the base is https; plain http is
// accepted only for a loopback address, and a classifier with no key has
// nothing to protect.
func TestJudgeBaseURLIsHTTPSWhereAKeyIsSent(t *testing.T) {
	type j = Judge
	refused := []j{
		{Provider: "typesafe", APIKey: "k", BaseURL: "http://api.typesafe.ai"},
		{Provider: "typesafe", APIKey: "k", BaseURL: "api.typesafe.ai"},
		{Provider: "openai", APIKey: "k", BaseURL: "http://llm.example.internal"},
		{Provider: "anthropic", APIKey: "k", BaseURL: "http://10.0.0.7:8080"},
		{Provider: "classifier", APIKey: "k", BaseURL: "http://prompt-guard:8080/classify"},
		{Provider: "typesafe", APIKey: "k", BaseURL: "https://user:pw@api.typesafe.ai"},
	}
	for _, jc := range refused {
		cfg := devDefault()
		cfg.Judge = jc
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "judge.baseUrl") {
			t.Fatalf("%+v: Validate() = %v, want a refusal naming judge.baseUrl", jc, err)
		}
		if strings.Contains(err.Error(), "pw") {
			t.Fatalf("%+v: the refusal repeats a credential: %v", jc, err)
		}
	}
	accepted := []j{
		{Provider: "typesafe", APIKey: "k"},
		{Provider: "typesafe", APIKey: "k", BaseURL: "https://api.typesafe.ai"},
		{Provider: "typesafe", APIKey: "k", BaseURL: "http://127.0.0.1:8099"},
		{Provider: "openai", APIKey: "k", BaseURL: "https://llm.example.internal"},
		{Provider: "openai", APIKey: "k", BaseURL: "http://localhost:8000"},
		{Provider: "classifier", BaseURL: "http://prompt-guard:8080/classify"},
		{Provider: "classifier", APIKey: "k", BaseURL: "https://guard.example.internal/classify"},
		{Provider: "none"},
		{Provider: "static"},
	}
	for _, jc := range accepted {
		cfg := devDefault()
		cfg.Judge = jc
		if err := cfg.Validate(); err != nil {
			t.Fatalf("%+v: %v", jc, err)
		}
	}
}

// A connector's public client id comes from the file or from its own
// environment variable, which wins and, set empty, removes it.
func TestConnectorPublicClients(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agentry.yaml")
	if err := os.WriteFile(path, []byte("env: dev\ndevMode: true\nconnectors:\n  publicClients:\n    microsoft-365: from-the-file\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.Connectors.PublicClients["microsoft-365"]; got != "from-the-file" {
		t.Fatalf("from the file: %q", got)
	}
	if ConnectorPublicClientEnv("microsoft-365") != "AGENTRY_CONNECTOR_MICROSOFT_365_PUBLIC_CLIENT_ID" {
		t.Fatalf("the variable: %s", ConnectorPublicClientEnv("microsoft-365"))
	}
	t.Setenv("AGENTRY_CONNECTOR_MICROSOFT_365_PUBLIC_CLIENT_ID", "0f6d5e1a-2b3c-4d5e-8f90-123456789abc")
	if cfg, err = Load(path); err != nil || cfg.Connectors.PublicClients["microsoft-365"] != "0f6d5e1a-2b3c-4d5e-8f90-123456789abc" {
		t.Fatalf("the environment did not win: %v %v", cfg.Connectors.PublicClients, err)
	}
	t.Setenv("AGENTRY_CONNECTOR_MICROSOFT_365_PUBLIC_CLIENT_ID", "")
	if cfg, err = Load(path); err != nil || len(cfg.Connectors.PublicClients) != 0 {
		t.Fatalf("an empty variable did not remove it: %v %v", cfg.Connectors.PublicClients, err)
	}
}

// A public client id for a connector this build does not know, for one
// whose app is confidential, or that is not one word is refused at load.
func TestConnectorPublicClientsAreValidated(t *testing.T) {
	for name, entry := range map[string]string{
		"an unknown connector":  "nobody: abc",
		"a confidential app":    "github: Ov23liGitHubApp",
		"more than one word":    "microsoft-365: \"abc def\"",
		"a pasted secret block": "microsoft-365: \"-----BEGIN PRIVATE KEY-----\\nabc\"",
		"too long":              "microsoft-365: " + strings.Repeat("a", 257),
	} {
		dir := t.TempDir()
		path := filepath.Join(dir, "agentry.yaml")
		if err := os.WriteFile(path, []byte("env: dev\ndevMode: true\nconnectors:\n  publicClients:\n    "+entry+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "connectors.publicClients") {
			t.Errorf("%s: %v", name, err)
		}
	}
}
