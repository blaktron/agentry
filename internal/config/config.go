// Package config loads agentryd configuration from agentry.yaml plus
// AGENTRY_* environment overrides (PLAN §0.8, M0). Environment always wins
// over file values; defaults are safe for local development.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the full agentryd configuration tree.
type Config struct {
	// Env names the deployment environment: dev | staging | prod.
	Env string `yaml:"env"`
	// DevMode enables development conveniences (auto-approve pipeline stub in
	// M3 per §18.2, verbose errors). MUST be false in prod; Validate enforces it.
	DevMode bool `yaml:"devMode"`

	HTTP     HTTP     `yaml:"http"`
	Database Database `yaml:"database"`
	Redis    Redis    `yaml:"redis"`
	Storage  Storage  `yaml:"storage"`
	Git      Git      `yaml:"git"`
	Log      Log      `yaml:"log"`
	Auth     Auth     `yaml:"auth"`
	Limits   Limits   `yaml:"limits"`
	Signing  Signing  `yaml:"signing"`
	Judge    Judge    `yaml:"judge"`
	BaseURL  string   `yaml:"baseURL"` // public origin, e.g. https://agentry.example
}

// HTTP configures listeners. Git traffic may share Addr (self-host) or use
// GitAddr (SaaS separate hostname, §6.1).
type HTTP struct {
	Addr    string `yaml:"addr"`
	GitAddr string `yaml:"gitAddr"`
}

// Database configures the PostgreSQL system of record (D-03).
type Database struct {
	URL string `yaml:"url"`
	// MigrateOnStart runs goose migrations at boot (self-host convenience).
	MigrateOnStart bool `yaml:"migrateOnStart"`
}

// Redis is an optional dependency (D-06); empty URL = in-memory fallbacks.
type Redis struct {
	URL string `yaml:"url"`
}

// Storage selects the archive/evidence object store: local FS (self-host,
// dev) or S3 (SaaS).
type Storage struct {
	Kind     string `yaml:"kind"` // local | s3
	LocalDir string `yaml:"localDir"`
	S3Bucket string `yaml:"s3Bucket"`
	S3Region string `yaml:"s3Region"`
}

// Git configures bare-repo hosting (§6.2).
type Git struct {
	DataDir string `yaml:"dataDir"` // bare repos under {dataDir}/{uuid[0:2]}/{uuid}.git
	BinPath string `yaml:"binPath"` // git binary; defaults to $PATH lookup
}

// Log configures structured logging.
type Log struct {
	Level string `yaml:"level"` // debug | info | warn | error
}

// Auth holds authentication tunables (§12).
type Auth struct {
	// SessionTTL is the absolute session lifetime (§12.4 caps at 24h).
	SessionTTL time.Duration `yaml:"sessionTTL"`
	// PATMaxTTL is the maximum PAT lifetime (§12.3: 1y, 90d org-bound).
	PATMaxTTL time.Duration `yaml:"patMaxTTL"`
	// CookieSecure marks session cookies Secure (default true outside dev).
	CookieSecure bool `yaml:"cookieSecure"`
	// SealingKey is a base64 32-byte key encrypting small secrets at rest
	// (TOTP seeds). Empty is allowed only in dev (a fixed insecure key).
	SealingKey string `yaml:"sealingKey"`
}

// Limits tunes the §19 API rate quotas (self-host operators may adjust;
// SaaS values come from the entitlements layer later).
type Limits struct {
	AuthedPerHour     int `yaml:"authedPerHour"`     // sustained authed budget
	AuthedBurstPerMin int `yaml:"authedBurstPerMin"` // authed burst
	AnonymousPerMin   int `yaml:"anonymousPerMin"`   // anonymous per-IP
	LoginPerMin       int `yaml:"loginPerMin"`       // login/register per-IP

	// Git/repo quotas (§19): 100 MB hard, 25 MB single-object cap.
	RepoQuotaBytes   int `yaml:"repoQuotaBytes"`
	RepoMaxBlobBytes int `yaml:"repoMaxBlobBytes"`
}

// Signing configures attestation signing (D-16): kms | file | none(dev).
type Signing struct {
	Kind      string `yaml:"kind"` // kms | file | none
	KMSKeyARN string `yaml:"kmsKeyARN"`
	KeyFile   string `yaml:"keyFile"`
}

// Judge selects the S5 LLM adjudication provider (D-13).
type Judge struct {
	Provider string `yaml:"provider"` // bedrock | anthropic | classifier | none
	Model    string `yaml:"model"`
	Region   string `yaml:"region"`
}

// Default returns the development-safe baseline configuration.
func Default() Config {
	return Config{
		Env:     "dev",
		DevMode: true,
		HTTP:    HTTP{Addr: ":8080"},
		Database: Database{
			URL:            "postgres://agentry:agentry@localhost:5477/agentry_dev?sslmode=disable",
			MigrateOnStart: true,
		},
		Storage: Storage{Kind: "local", LocalDir: ".devdata/storage"},
		Git:     Git{DataDir: ".devdata/git"},
		Log:     Log{Level: "info"},
		Auth: Auth{
			SessionTTL:   24 * time.Hour,
			PATMaxTTL:    365 * 24 * time.Hour,
			CookieSecure: false,
		},
		Limits: Limits{
			AuthedPerHour:     5000,
			AuthedBurstPerMin: 100,
			AnonymousPerMin:   60,
			LoginPerMin:       10,
			RepoQuotaBytes:    100 << 20,
			RepoMaxBlobBytes:  25 << 20,
		},
		Signing: Signing{Kind: "none"},
		Judge:   Judge{Provider: "none"},
	}
}

// Load builds configuration: defaults ← optional YAML file ← AGENTRY_* env.
// path may be empty; then AGENTRY_CONFIG or ./agentry.yaml is used if present.
func Load(path string) (Config, error) {
	cfg := Default()

	if path == "" {
		path = os.Getenv("AGENTRY_CONFIG")
	}
	if path == "" {
		if _, err := os.Stat("agentry.yaml"); err == nil {
			path = "agentry.yaml"
		}
	}
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return cfg, fmt.Errorf("config: reading %s: %w", path, err)
		}
		dec := yaml.NewDecoder(strings.NewReader(string(b)))
		dec.KnownFields(true)
		if err := dec.Decode(&cfg); err != nil {
			return cfg, fmt.Errorf("config: parsing %s: %w", path, err)
		}
	}

	if err := applyEnv(&cfg); err != nil {
		return cfg, err
	}
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// applyEnv maps AGENTRY_* variables onto the tree. The mapping is explicit —
// boring and greppable beats reflective magic for a security product.
func applyEnv(c *Config) error {
	str := func(key string, dst *string) {
		if v, ok := os.LookupEnv(key); ok {
			*dst = v
		}
	}
	boolean := func(key string, dst *bool) error {
		v, ok := os.LookupEnv(key)
		if !ok {
			return nil
		}
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("config: %s: %w", key, err)
		}
		*dst = b
		return nil
	}
	dur := func(key string, dst *time.Duration) error {
		v, ok := os.LookupEnv(key)
		if !ok {
			return nil
		}
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("config: %s: %w", key, err)
		}
		*dst = d
		return nil
	}

	str("AGENTRY_ENV", &c.Env)
	str("AGENTRY_HTTP_ADDR", &c.HTTP.Addr)
	str("AGENTRY_HTTP_GIT_ADDR", &c.HTTP.GitAddr)
	str("AGENTRY_DATABASE_URL", &c.Database.URL)
	str("AGENTRY_REDIS_URL", &c.Redis.URL)
	str("AGENTRY_STORAGE_KIND", &c.Storage.Kind)
	str("AGENTRY_STORAGE_LOCAL_DIR", &c.Storage.LocalDir)
	str("AGENTRY_STORAGE_S3_BUCKET", &c.Storage.S3Bucket)
	str("AGENTRY_STORAGE_S3_REGION", &c.Storage.S3Region)
	str("AGENTRY_GIT_DATA_DIR", &c.Git.DataDir)
	str("AGENTRY_GIT_BIN", &c.Git.BinPath)
	str("AGENTRY_LOG_LEVEL", &c.Log.Level)
	str("AGENTRY_BASE_URL", &c.BaseURL)
	str("AGENTRY_SIGNING_KIND", &c.Signing.Kind)
	str("AGENTRY_SIGNING_KMS_KEY_ARN", &c.Signing.KMSKeyARN)
	str("AGENTRY_SIGNING_KEY_FILE", &c.Signing.KeyFile)
	str("AGENTRY_AUTH_SEALING_KEY", &c.Auth.SealingKey)
	str("AGENTRY_JUDGE_PROVIDER", &c.Judge.Provider)
	str("AGENTRY_JUDGE_MODEL", &c.Judge.Model)
	str("AGENTRY_JUDGE_REGION", &c.Judge.Region)

	if err := boolean("AGENTRY_DEV_MODE", &c.DevMode); err != nil {
		return err
	}
	if err := boolean("AGENTRY_DATABASE_MIGRATE_ON_START", &c.Database.MigrateOnStart); err != nil {
		return err
	}
	if err := boolean("AGENTRY_AUTH_COOKIE_SECURE", &c.Auth.CookieSecure); err != nil {
		return err
	}
	if err := dur("AGENTRY_AUTH_SESSION_TTL", &c.Auth.SessionTTL); err != nil {
		return err
	}
	if err := dur("AGENTRY_AUTH_PAT_MAX_TTL", &c.Auth.PATMaxTTL); err != nil {
		return err
	}
	return nil
}

// Validate rejects configurations that must never run.
func (c Config) Validate() error {
	switch c.Env {
	case "dev", "staging", "prod":
	default:
		return fmt.Errorf("config: env must be dev|staging|prod, got %q", c.Env)
	}
	if c.Env == "prod" && c.DevMode {
		return fmt.Errorf("config: devMode must be false in prod")
	}
	switch c.Storage.Kind {
	case "local", "s3":
	default:
		return fmt.Errorf("config: storage.kind must be local|s3, got %q", c.Storage.Kind)
	}
	switch c.Signing.Kind {
	case "none", "file", "kms":
	default:
		return fmt.Errorf("config: signing.kind must be none|file|kms, got %q", c.Signing.Kind)
	}
	if c.Env == "prod" && c.Signing.Kind == "none" {
		return fmt.Errorf("config: signing.kind none is not allowed in prod")
	}
	if !c.DevMode && c.Auth.SealingKey == "" {
		return fmt.Errorf("config: auth.sealingKey is required outside dev mode")
	}
	switch c.Judge.Provider {
	case "none", "bedrock", "anthropic", "classifier":
	default:
		return fmt.Errorf("config: judge.provider must be none|bedrock|anthropic|classifier, got %q", c.Judge.Provider)
	}
	return nil
}
