package config

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "nonexistent-means-defaults-only.yaml"))
	if err == nil {
		t.Fatalf("expected error for explicit missing file")
	}
	// Empty path with no agentry.yaml in cwd yields pure defaults — and the
	// pure defaults refuse to run: dev mode is opt-in (DEV-116), so with no
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
	if err := os.WriteFile(path, []byte("bogusKey: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("unknown config keys must be rejected")
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
	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{"prod devMode", func(c *Config) { c.Env = "prod"; c.DevMode = true }},
		{"staging devMode", func(c *Config) { c.Env = "staging"; c.DevMode = true }},
		{"no sealing key outside dev mode", func(c *Config) { c.DevMode = false; c.Auth.SealingKey = "" }},
		{"prod unsigned", func(c *Config) { c.Env = "prod"; c.DevMode = false; c.Signing.Kind = "none" }},
		{"bad env", func(c *Config) { c.Env = "yolo" }},
		{"bad storage", func(c *Config) { c.Storage.Kind = "ftp" }},
		{"bad judge", func(c *Config) { c.Judge.Provider = "gpt" }},
		// Honouring an inbound request id needs a hop that sets it; the flag
		// without a hop count is a contradiction, not a default.
		{"proxyRequestID without a hop", func(c *Config) { c.HTTP.ProxyRequestID = true; c.HTTP.TrustedProxies = 0 }},
		{"bad audit stream kind", func(c *Config) { c.Audit.StreamKind = "kafka" }},
		// A staff domain that could never match an address would switch the
		// rule off silently (agentry#525, agentry#556).
		{"staff domain with an at", func(c *Config) { c.Auth.StaffOrg = "agentry"; c.Auth.StaffDomain = "@secureagentry.net" }},
		{"staff domain with a leading dot", func(c *Config) { c.Auth.StaffOrg = "agentry"; c.Auth.StaffDomain = ".secureagentry.net" }},
		{"staff domain in capitals", func(c *Config) { c.Auth.StaffOrg = "agentry"; c.Auth.StaffDomain = "SecureAgentry.net" }},
		{"staff domain of one label", func(c *Config) { c.Auth.StaffOrg = "agentry"; c.Auth.StaffDomain = "localhost" }},
		// Half a rule is refused: an organization with no domain would admit
		// anyone, a domain with no organization names nobody (agentry#556).
		{"staff org without a domain", func(c *Config) { c.Auth.StaffOrg = "agentry" }},
		{"staff domain without an org", func(c *Config) { c.Auth.StaffDomain = "secureagentry.net" }},
		{"staff org that is no handle", func(c *Config) { c.Auth.StaffOrg = "Agentry Staff"; c.Auth.StaffDomain = "secureagentry.net" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := devDefault()
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

		// A trusted device is the second browser credential class (agentry#461,
		// plan trusted-devices.md D2). It exceeds MaxSessionTTL by design — that
		// is precisely what makes it its own class rather than a longer session
		// — so what these cases prove is that its OWN ceiling binds, and that a
		// deployment cannot price in a credential the threat model never
		// considered by raising the knob.
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

// TestTrustedDeviceIsASecondClassNotALongerSession guards the amendment rather
// than the feature (agentry#461, plan trusted-devices.md D2). Introducing a
// browser credential that outlives the session cap is only honest if the
// session cap itself is untouched, so a reader of §12.4 sees one ceiling of two
// rather than a limit that was quietly raised. If someone later "simplifies"
// the two constants into one, this fails and the simplification has to be
// argued rather than slipped in.
func TestTrustedDeviceIsASecondClassNotALongerSession(t *testing.T) {
	if MaxSessionTTL != 24*time.Hour {
		t.Fatalf("MaxSessionTTL is %s, want 24h: §12.4's session cap moved", MaxSessionTTL)
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
		{"zero scim budget", func(c *Config) { c.Limits.SCIMPerMin = 0 }},
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
		{"scim per minute per organization", int64(l.SCIMPerMin), 600},
		{"git concurrent per IP", int64(l.GitConcurrentPerIP), 20},
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
	t.Setenv("AGENTRY_LIMITS_SSH_KEY_OFFERS_PER_MIN", "30")
	t.Setenv("AGENTRY_LIMITS_GIT_CONCURRENT_PER_IP", "8")
	t.Setenv("AGENTRY_LIMITS_ARCHIVE_MAX_BYTES", "20971520")
	t.Setenv("AGENTRY_LIMITS_REPO_WARN_BYTES", "31457280")
	t.Setenv("AGENTRY_LIMITS_ARCHIVE_MAX_TEXT_BYTES", "2097152")
	t.Setenv("AGENTRY_STORAGE_S3_PREFIX", "staging")
	t.Setenv("AGENTRY_STORAGE_S3_USE_PATH_STYLE", "true")
	t.Setenv("AGENTRY_SIGNING_NOT_AFTER", "2027-01-01T00:00:00Z")
	t.Setenv("AGENTRY_DEV_MODE", "true") // the knobs under test, on the dev baseline (DEV-116)

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
	t.Setenv("AGENTRY_DEV_MODE", "true") // the knobs under test, on the dev baseline (DEV-116)

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

	// The typesafe judge (plan judge-jev-provider.md, D7): the key is
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

// The five social providers all wire from env: id/secret everywhere, plus
// the endpoint overrides each protocol needs (issuer for the OIDC-proper
// set, explicit URLs for the github shim).
func TestSocialProviderEnv(t *testing.T) {
	t.Setenv("AGENTRY_SOCIAL_GOOGLE_CLIENT_ID", "g-id")
	t.Setenv("AGENTRY_SOCIAL_GITHUB_CLIENT_ID", "gh-id")
	t.Setenv("AGENTRY_SOCIAL_MICROSOFT_CLIENT_ID", "ms-id")
	t.Setenv("AGENTRY_SOCIAL_MICROSOFT_ISSUER", "https://issuer.example/ms")
	t.Setenv("AGENTRY_SOCIAL_OPENAI_CLIENT_ID", "oai-id")
	t.Setenv("AGENTRY_SOCIAL_OPENAI_ISSUER", "https://issuer.example/oai")
	t.Setenv("AGENTRY_SOCIAL_CLAUDE_CLIENT_ID", "claude-id")
	t.Setenv("AGENTRY_SOCIAL_CLAUDE_ISSUER", "https://issuer.example/claude")
	t.Setenv("AGENTRY_DEV_MODE", "true") // the knobs under test, on the dev baseline (DEV-116)

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Social.Google.ClientID != "g-id" || cfg.Social.GitHub.ClientID != "gh-id" {
		t.Errorf("google/github env not applied: %+v", cfg.Social)
	}
	if cfg.Social.Microsoft.ClientID != "ms-id" || cfg.Social.Microsoft.Issuer != "https://issuer.example/ms" {
		t.Errorf("microsoft env not applied: %+v", cfg.Social.Microsoft)
	}
	if cfg.Social.OpenAI.ClientID != "oai-id" || cfg.Social.OpenAI.Issuer != "https://issuer.example/oai" {
		t.Errorf("openai env not applied: %+v", cfg.Social.OpenAI)
	}
	if cfg.Social.Claude.ClientID != "claude-id" || cfg.Social.Claude.Issuer != "https://issuer.example/claude" {
		t.Errorf("claude env not applied: %+v", cfg.Social.Claude)
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

// TestRetiredStaffKeysAreNamed (agentry#556): the group and the domain-alone
// keys still load, grant nothing, and are named for the start-up warning.
func TestRetiredStaffKeysAreNamed(t *testing.T) {
	cfg := devDefault()
	if keys := cfg.RetiredStaffKeys(); len(keys) != 0 {
		t.Fatalf("nothing set, yet %v", keys)
	}
	cfg.Auth.IdPStaffGroup, cfg.Auth.IdPStaffDomain = "agentry-platform-staff", "secureagentry.net"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("a configuration still setting the retired keys must load: %v", err)
	}
	if keys := cfg.RetiredStaffKeys(); len(keys) != 2 {
		t.Fatalf("retired keys = %v", keys)
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
