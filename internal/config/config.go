// Package config loads agentryd configuration from agentry.yaml plus
// AGENTRY_* environment overrides (PLAN §0.8, M0). Environment always wins
// over file values; defaults are safe for local development.
package config

import (
	"fmt"
	"net/url"
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

	HTTP      HTTP      `yaml:"http"`
	Database  Database  `yaml:"database"`
	Redis     Redis     `yaml:"redis"`
	Storage   Storage   `yaml:"storage"`
	Git       Git       `yaml:"git"`
	Log       Log       `yaml:"log"`
	Auth      Auth      `yaml:"auth"`
	Limits    Limits    `yaml:"limits"`
	Signing   Signing   `yaml:"signing"`
	Judge     Judge     `yaml:"judge"`
	Scan      Scan      `yaml:"scan"`
	Social    Social    `yaml:"social"`
	Audit     Audit     `yaml:"audit"`
	RedTeam   RedTeam   `yaml:"redTeam"`
	Telemetry Telemetry `yaml:"telemetry"`
	Notify    Notify    `yaml:"notify"`
	SMTP      SMTP      `yaml:"smtp"`
	BaseURL   string    `yaml:"baseURL"` // public origin, e.g. https://agentry.example
	Web       Web       `yaml:"web"`
	UI        UI        `yaml:"ui"`
	Brand     Brand     `yaml:"brand"`
	// MinCLIVersion, when set, is advertised via GET /api/v1/meta so the CLI
	// can warn (or refuse, on a major gap) before talking to an API it
	// predates (§11 distribution note). Empty = no minimum advertised.
	MinCLIVersion string `yaml:"minCLIVersion"`
}

// HTTP configures listeners. Git traffic may share Addr (self-host) or use
// GitAddr (SaaS separate hostname, §6.1).
type HTTP struct {
	Addr    string `yaml:"addr"`
	GitAddr string `yaml:"gitAddr"`
	// TrustedProxies is how many reverse-proxy hops sit in front of agentryd.
	// 0 (the default) means agentryd is addressed directly and
	// X-Forwarded-For is ignored entirely — a header any client can forge is
	// not evidence of anything.
	//
	// Behind CloudFront → ALB → agentryd, set 2: the per-IP rate limits then
	// key on the 2nd-from-last XFF entry, which is the last address a
	// *trusted* hop wrote. Setting this higher than the real hop count hands
	// callers the ability to choose their own rate-limit bucket, so it must
	// match the deployment exactly (§19, §13.5).
	TrustedProxies int `yaml:"trustedProxies"`
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
	// S3Prefix is an optional key prefix inside the bucket, letting one
	// bucket host several environments.
	S3Prefix string `yaml:"s3Prefix"`
	// S3Endpoint overrides the AWS endpoint (MinIO in the compose dev stack,
	// or an S3-compatible store self-hosted). Empty uses AWS.
	S3Endpoint string `yaml:"s3Endpoint"`
	// S3UsePathStyle addresses buckets as {endpoint}/{bucket}/{key} rather
	// than by virtual host. Required by MinIO; AWS does not need it.
	S3UsePathStyle bool `yaml:"s3UsePathStyle"`
}

// Git configures bare-repo hosting (§6.2).
type Git struct {
	DataDir string `yaml:"dataDir"` // bare repos under {dataDir}/{uuid[0:2]}/{uuid}.git
	BinPath string `yaml:"binPath"` // git binary; defaults to $PATH lookup
	// SSHAddr, when set, is where the git and all roles listen for the SSH
	// transport (§6.1 Q7, agentry#70), e.g. ":2222". Empty disables it.
	SSHAddr string `yaml:"sshAddr"`
	// SSHHostKeyFile is the PEM host key; empty means {dataDir}/ssh_host_ed25519_key,
	// generated on first start.
	SSHHostKeyFile string `yaml:"sshHostKeyFile"`
	// SSHPublicURL is the base clients use, e.g. "ssh://git@git.example.com:2222";
	// when set, agent documents carry gitSshUrl.
	SSHPublicURL string `yaml:"sshPublicUrl"`
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
	// PATOrgBoundMaxTTL caps org-bound PAT lifetime under enforced SSO
	// (§12.3: 90 days).
	PATOrgBoundMaxTTL time.Duration `yaml:"patOrgBoundMaxTTL"`
	// SSOMaxAge is how fresh a session's SSO assertion must be to act on an
	// enforced-SSO org's resources (§12.4, default 8h).
	SSOMaxAge time.Duration `yaml:"ssoMaxAge"`
	// CookieSecure marks session cookies Secure (default true outside dev).
	CookieSecure bool `yaml:"cookieSecure"`
	// SealingKey is a base64 32-byte key encrypting small secrets at rest
	// (TOTP seeds). Empty is allowed only in dev (a fixed insecure key).
	SealingKey string `yaml:"sealingKey"`
	// ExternalOnly hands credentials and the account directory to an
	// external IdP (DEV-057: the stack's Authentik instance). When true the
	// native register / password-login / email-verify / TOTP endpoints
	// answer 410 Gone and sign-in happens only through a configured social
	// or SSO provider. Sessions, PATs, and RBAC stay native: the IdP owns
	// who you are, this server owns what you may do. The §12.1 "2FA before
	// public publish" gate is delegated to the IdP as well, since no account
	// can enrol a native TOTP factor while this is set (see
	// internal/api/publish_gate.go).
	ExternalOnly bool `yaml:"externalOnly"`
	// IdPLogoutURL is the directory's end-session flow: where sign-out sends
	// the browser once the session is revoked, so the next sign-in asks
	// again (DEV-057). Empty means sign-out ends on the home page.
	IdPLogoutURL string `yaml:"idpLogoutURL"`
	// IdPAdminURL / IdPAdminToken let account erasure (§12.7) reach into the
	// directory service and delete the sign-in account there too — authentik's
	// API, as a bearer token with rights over users (agentry#20). Empty means
	// erasure stops at the registry, which docs/self-hosting.md and the
	// privacy policy then have to say. The URL is the API origin as the
	// server reaches it (compose: http://authentik-server:9000).
	IdPAdminURL   string `yaml:"idpAdminURL"`
	IdPAdminToken string `yaml:"idpAdminToken"`
	// IdPStaffGroup names the directory group whose members are platform
	// staff (agentry#51). At every `authentik` sign-in the account's
	// platform_staff flag is set to "is a member of this group" — so staff
	// is granted AND revoked in the directory, never by hand in SQL. Empty
	// disables the sync and leaves the flag as it is.
	IdPStaffGroup string `yaml:"idpStaffGroup"`
	// RequireIdPMFA re-enables the §12.1 "2FA before public publish" gate
	// under externalOnly, satisfied by evidence rather than trust: the
	// account must have signed in at least once with an ID token whose
	// `amr` names a second factor (users.idp_mfa_at). Off by default because
	// it is only honest once the directory actually enforces MFA
	// (agentry#23, DEV-076).
	RequireIdPMFA bool `yaml:"requireIdpMFA"`
}

// Limits tunes the §19 quotas. These are the values internal/entitlements'
// config-backed default Resolver hands out; the SaaS overlay swaps in a
// Resolver that reads them per-org instead (§14.2). Nothing in the OSS tree
// reads a limit except through that Resolver.
type Limits struct {
	AuthedPerHour     int `yaml:"authedPerHour"`     // sustained authed budget
	AuthedBurstPerMin int `yaml:"authedBurstPerMin"` // authed burst
	AnonymousPerMin   int `yaml:"anonymousPerMin"`   // anonymous per-IP
	LoginPerMin       int `yaml:"loginPerMin"`       // login/register per-IP

	// Git/repo quotas (§19): 100 MB hard, 25 MB single-object cap.
	RepoQuotaBytes   int `yaml:"repoQuotaBytes"`
	RepoMaxBlobBytes int `yaml:"repoMaxBlobBytes"`
	// GitPushesPerHour is the §19 per-repo push budget (60/h).
	GitPushesPerHour int `yaml:"gitPushesPerHour"`

	// Namespace + publish-velocity quotas (§19).
	AgentsPerUserNamespace int `yaml:"agentsPerUserNamespace"` // 200
	AgentsPerOrgNamespace  int `yaml:"agentsPerOrgNamespace"`  // 500
	VersionsPerDay         int `yaml:"versionsPerDay"`         // 20 per agent

	// Webhook quotas (§19): 20 endpoints per org, 5 deliveries/s per org.
	WebhookEndpointsPerOrg     int `yaml:"webhookEndpointsPerOrg"`
	WebhookDeliveriesPerSecond int `yaml:"webhookDeliveriesPerSecond"`

	// Release-archive quotas (§19), enforced by manifest validation (V8).
	ArchiveMaxBytes          int64 `yaml:"archiveMaxBytes"`          // 10 MiB
	ArchiveMaxFiles          int   `yaml:"archiveMaxFiles"`          // 2000
	ArchiveMaxFileBytes      int64 `yaml:"archiveMaxFileBytes"`      // 2 MiB
	ArchiveMaxImageFileBytes int64 `yaml:"archiveMaxImageFileBytes"` // 5 MiB
}

// Signing configures attestation signing (D-16): kms | file | none(dev).
type Signing struct {
	Kind      string `yaml:"kind"` // kms | file | none
	KMSKeyARN string `yaml:"kmsKeyARN"`
	// KMSRegion overrides the ambient AWS region for the KMS client. Empty
	// uses the credential chain's region.
	KMSRegion string `yaml:"kmsRegion"`
	KeyFile   string `yaml:"keyFile"`
	// NotBefore/NotAfter bound the ACTIVE key's validity window, RFC3339
	// (§8.8: the discovery document carries a validity window per key). Both
	// optional; an empty side is unbounded.
	NotBefore string `yaml:"notBefore"`
	NotAfter  string `yaml:"notAfter"`
	// AdditionalKeys are verification-only public keys published alongside
	// the active one. §8.8 rotates by OVERLAPPING validity windows, which is
	// only representable if the endpoint can serve more than one key: during
	// a rotation the outgoing key stays listed, with a notAfter, until every
	// attestation it signed has been re-verified or aged out.
	//
	// YAML/file only — a list does not map onto a single env var, and the
	// values are public keys, not secrets.
	AdditionalKeys []VerificationKey `yaml:"additionalKeys"`
}

// VerificationKey is one published entry in signing-keys.json.
type VerificationKey struct {
	KeyID     string `yaml:"keyId"`
	Algorithm string `yaml:"algorithm"` // default ecdsa-p256-sha256
	// Exactly one of PublicKeyPEM (inline) or PublicKeyFile (path) is used.
	PublicKeyPEM  string `yaml:"publicKeyPem"`
	PublicKeyFile string `yaml:"publicKeyFile"`
	NotBefore     string `yaml:"notBefore"` // RFC3339, optional
	NotAfter      string `yaml:"notAfter"`  // RFC3339, optional
}

// Telemetry configures the §16.2 metric exporters (D-25).
type Telemetry struct {
	// OTLPEndpoint is the collector base URL, e.g. http://localhost:4318 for
	// the ADOT sidecar. Empty disables OTLP export; /metrics stays on either
	// way, so a self-hosted instance is never dark.
	OTLPEndpoint string `yaml:"otlpEndpoint"`
	// ExportInterval is the OTLP flush period (default 30s, matching the
	// collector's batch timeout).
	ExportInterval time.Duration `yaml:"exportInterval"`
	// QueueSampleInterval is how often the worker publishes queue depth and
	// oldest-job age. It bounds how stale the §16.3 queue-age page alarm can
	// be, so it must stay well under the 15-minute alarm threshold.
	QueueSampleInterval time.Duration `yaml:"queueSampleInterval"`
}

// Notify selects the notification transport (§13.4: SES on SaaS, mailpit in
// the compose dev stack).
type Notify struct {
	// Kind is log | smtp. log stays the default so a fresh install never
	// silently fails to deliver: it says so, in the log.
	Kind string `yaml:"kind"`
}

// Web names a front end that fronts this server — the SecureAgentry site,
// or any other (DEV-091). When URL is set, every browser destination the
// API writes (where a failed sign-in lands, where a signed-in browser goes,
// where an email link points, where sign-out ends) is a page of that site.
// When it is unset the server points at its own pages under /ui/.
type Web struct {
	// URL is the site's origin, e.g. https://agentry.example (no path).
	URL string `yaml:"url"`
}

// UI selects how much of the server's own browser surface (/ui/…,
// DEV-091) is served: full (device authorize, sign-in, account, review,
// staff, org admin), authorize (only the device-authorize page — what a
// deployment with a site in front uses), or off.
type UI struct {
	Mode string `yaml:"mode"`
}

// Brand is what this deployment calls itself and where it sends people
// for help. Nothing is required: a deployment without a name is called by
// its public host, then "Agentry" (see Config.DisplayName).
type Brand struct {
	Name          string `yaml:"name"`
	LogoURL       string `yaml:"logoURL"`
	CSSURL        string `yaml:"cssURL"`
	SupportEmail  string `yaml:"supportEmail"`
	SecurityEmail string `yaml:"securityEmail"`
	PrivacyURL    string `yaml:"privacyURL"`
	TermsURL      string `yaml:"termsURL"`
}

// DisplayName is what notification bodies, authenticator apps and the
// server's own pages call this deployment: brand.name, else the public
// origin's host, else "Agentry".
func (c Config) DisplayName() string {
	if c.Brand.Name != "" {
		return c.Brand.Name
	}
	if c.BaseURL != "" {
		if u, err := url.Parse(c.BaseURL); err == nil && u.Host != "" {
			return u.Host
		}
		return c.BaseURL
	}
	return "Agentry"
}

// SMTP configures the smtp notifier. Point it at SES's SMTP endpoint on AWS
// (see docs/ops/deployment.md) or at mailpit on :1025 in dev.
type SMTP struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	// From is the envelope + header sender, e.g. "Agentry <no-reply@example>".
	From string `yaml:"from"`
	// StartTLS upgrades the connection before authenticating. Required
	// against SES; mailpit speaks plaintext on 1025, so dev sets it false.
	StartTLS bool `yaml:"startTLS"`
	// Timeout bounds a single send (dial + handshake + data).
	Timeout time.Duration `yaml:"timeout"`
}

// Judge selects the S5 LLM adjudication provider (D-13).
//
// openai and anthropic talk to any endpoint speaking the matching wire
// protocol (hosted APIs or self-hosted gateways alike): set BaseURL to the
// API root and APIKey to the credential. The AGENTRY_JUDGE_TYPE,
// AGENTRY_JUDGE_BASE_URL and AGENTRY_JUDGE_API_KEY environment variables
// configure the same three values.
type Judge struct {
	Provider string `yaml:"provider"` // openai | anthropic | bedrock | classifier | static | none
	Model    string `yaml:"model"`
	Region   string `yaml:"region"`
	BaseURL  string `yaml:"baseUrl"`
	APIKey   string `yaml:"apiKey"`
}

// Scan configures the external scanner tools behind the §8.3 seams
// (DEV-006, agentry#40). Every field is optional: unset, the native Go
// scanners run alone. The OSV and opengrep seams went with the code kinds
// (DEV-088): nothing code-bearing is published any more.
type Scan struct {
	// GitleaksBin is the path of a gitleaks binary S2 execs in addition to
	// its native ruleset. "auto" resolves it from PATH; empty disables.
	GitleaksBin string `yaml:"gitleaksBin"`
	// ToolTimeout bounds one external tool invocation; 0 means two minutes.
	ToolTimeout time.Duration `yaml:"toolTimeout"`
	// OSVURL is the vulnerability database S7 asks about declared MCP
	// servers (agentry#177). Empty means https://api.osv.dev; "none"
	// switches the lookup off (S7 then reports "not checked").
	OSVURL string `yaml:"osvUrl"`
}

// Social configures social login for individual accounts (§12.1). A provider
// with no client id is simply not offered: the start endpoint 404s, so an
// unconfigured deployment advertises nothing it cannot complete. Google and
// Microsoft have built-in OIDC endpoints; OpenAI and Claude publish no fixed
// consumer sign-in endpoints, so they additionally need an issuer override.
type Social struct {
	Google    SocialProvider `yaml:"google"`
	GitHub    SocialProvider `yaml:"github"`
	Microsoft SocialProvider `yaml:"microsoft"`
	OpenAI    SocialProvider `yaml:"openai"`
	Claude    SocialProvider `yaml:"claude"`
	// Authentik is the deployment's own directory service (DEV-057). Like
	// openai/claude it has no default issuer; the operator points it at the
	// instance's application (…/application/o/<slug>/).
	Authentik SocialProvider `yaml:"authentik"`
}

// SocialProvider is one provider's OAuth client registration.
type SocialProvider struct {
	ClientID     string `yaml:"clientId"`
	ClientSecret string `yaml:"clientSecret"`
	// Issuer/AuthURL/TokenURL/APIBaseURL override the provider's endpoints.
	// Empty in production; tests point them at an in-process provider.
	Issuer     string `yaml:"issuer"`
	AuthURL    string `yaml:"authURL"`
	TokenURL   string `yaml:"tokenURL"`
	APIBaseURL string `yaml:"apiBaseURL"`
}

// Configured reports whether the provider can be offered.
func (p SocialProvider) Configured() bool { return p.ClientID != "" && p.ClientSecret != "" }

// RedTeam configures the §17.5 scheduled red-team job (agentry#67): corpus
// rewrites scanned against the S3/S4 bundle, report-only.
type RedTeam struct {
	// Interval is how often a worker runs the job; 0 disables it.
	Interval time.Duration `yaml:"interval"`
	// CorpusDir overrides where the attack corpus is read from (default:
	// the image's /srv/agentry/attack-corpus, else testdata/attack-corpus).
	CorpusDir string `yaml:"corpusDir"`
}

// Audit configures the §12.6 continuous audit stream and §4.3 retention.
type Audit struct {
	// StreamKind selects the NDJSON sink: none | file | s3.
	StreamKind string `yaml:"streamKind"`
	// StreamDir is the directory file-kind streams write daily files into.
	StreamDir string `yaml:"streamDir"`
	// StreamFlush bounds how long an event may sit in the buffer. §12.6 says
	// "within ~1 min"; the default leaves headroom under that.
	StreamFlush time.Duration `yaml:"streamFlush"`
	// StreamS3Bucket is the destination for s3-kind streams.
	StreamS3Bucket string `yaml:"streamS3Bucket"`
	// RetentionDays is how long audit rows stay in the hot table (§4.3:
	// 400 days on SaaS, configurable self-host). 0 disables pruning.
	RetentionDays int `yaml:"retentionDays"`
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
			SessionTTL:        24 * time.Hour,
			PATMaxTTL:         365 * 24 * time.Hour,
			PATOrgBoundMaxTTL: 90 * 24 * time.Hour,
			SSOMaxAge:         8 * time.Hour,
			CookieSecure:      false,
		},
		Limits: Limits{
			AuthedPerHour:              5000,
			AuthedBurstPerMin:          100,
			AnonymousPerMin:            60,
			LoginPerMin:                10,
			RepoQuotaBytes:             100 << 20,
			RepoMaxBlobBytes:           25 << 20,
			GitPushesPerHour:           60,
			AgentsPerUserNamespace:     200,
			AgentsPerOrgNamespace:      500,
			VersionsPerDay:             20,
			WebhookEndpointsPerOrg:     20,
			WebhookDeliveriesPerSecond: 5,
			ArchiveMaxBytes:            10 << 20,
			ArchiveMaxFiles:            2000,
			ArchiveMaxFileBytes:        2 << 20,
			ArchiveMaxImageFileBytes:   5 << 20,
		},
		Signing: Signing{Kind: "none"},
		Judge:   Judge{Provider: "none"},
		UI:      UI{Mode: "full"},
		Audit: Audit{
			StreamKind:    "none",
			StreamDir:     ".devdata/audit-stream",
			StreamFlush:   30 * time.Second,
			RetentionDays: 400,
		},
		RedTeam: RedTeam{Interval: 24 * time.Hour},
		Telemetry: Telemetry{
			ExportInterval: 30 * time.Second,
			// Well under the §16.3 15-minute queue-age threshold, so the
			// alarm never fires on a stale sample.
			QueueSampleInterval: 15 * time.Second,
		},
		Notify: Notify{Kind: "log"},
		SMTP:   SMTP{Port: 587, StartTLS: true, Timeout: 15 * time.Second},
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
	integer := func(key string, dst *int) error {
		v, ok := os.LookupEnv(key)
		if !ok {
			return nil
		}
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("config: %s: %w", key, err)
		}
		*dst = n
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
	str("AGENTRY_STORAGE_S3_PREFIX", &c.Storage.S3Prefix)
	str("AGENTRY_STORAGE_S3_ENDPOINT", &c.Storage.S3Endpoint)
	str("AGENTRY_GIT_DATA_DIR", &c.Git.DataDir)
	str("AGENTRY_GIT_BIN", &c.Git.BinPath)
	str("AGENTRY_GIT_SSH_ADDR", &c.Git.SSHAddr)
	str("AGENTRY_GIT_SSH_HOST_KEY", &c.Git.SSHHostKeyFile)
	str("AGENTRY_GIT_SSH_PUBLIC_URL", &c.Git.SSHPublicURL)
	str("AGENTRY_LOG_LEVEL", &c.Log.Level)
	str("AGENTRY_BASE_URL", &c.BaseURL)
	str("AGENTRY_WEB_URL", &c.Web.URL)
	str("AGENTRY_IDP_LOGOUT_URL", &c.Auth.IdPLogoutURL)
	str("AGENTRY_UI_MODE", &c.UI.Mode)
	str("AGENTRY_BRAND_NAME", &c.Brand.Name)
	str("AGENTRY_BRAND_LOGO_URL", &c.Brand.LogoURL)
	str("AGENTRY_BRAND_CSS_URL", &c.Brand.CSSURL)
	str("AGENTRY_SUPPORT_EMAIL", &c.Brand.SupportEmail)
	str("AGENTRY_SECURITY_EMAIL", &c.Brand.SecurityEmail)
	str("AGENTRY_PRIVACY_URL", &c.Brand.PrivacyURL)
	str("AGENTRY_TERMS_URL", &c.Brand.TermsURL)
	str("AGENTRY_SIGNING_KIND", &c.Signing.Kind)
	str("AGENTRY_SIGNING_KMS_KEY_ARN", &c.Signing.KMSKeyARN)
	str("AGENTRY_SIGNING_KMS_REGION", &c.Signing.KMSRegion)
	str("AGENTRY_SIGNING_KEY_FILE", &c.Signing.KeyFile)
	str("AGENTRY_SIGNING_NOT_BEFORE", &c.Signing.NotBefore)
	str("AGENTRY_SIGNING_NOT_AFTER", &c.Signing.NotAfter)
	str("AGENTRY_AUTH_SEALING_KEY", &c.Auth.SealingKey)
	str("AGENTRY_JUDGE_PROVIDER", &c.Judge.Provider)
	str("AGENTRY_JUDGE_MODEL", &c.Judge.Model)
	str("AGENTRY_JUDGE_REGION", &c.Judge.Region)
	str("AGENTRY_JUDGE_BASE_URL", &c.Judge.BaseURL)
	str("AGENTRY_JUDGE_API_KEY", &c.Judge.APIKey)
	// AGENTRY_JUDGE_TYPE is the plain spelling for "which wire protocol";
	// when set it wins over AGENTRY_JUDGE_PROVIDER.
	str("AGENTRY_JUDGE_TYPE", &c.Judge.Provider)
	// External scanner tools (§8.3 seams, agentry#40).
	str("AGENTRY_SCAN_GITLEAKS_BIN", &c.Scan.GitleaksBin)
	str("AGENTRY_SCAN_OSV_URL", &c.Scan.OSVURL)
	if v := os.Getenv("AGENTRY_SCAN_TOOL_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			c.Scan.ToolTimeout = d
		}
	}

	// Social login (§12.1). Listed one variable per field on purpose: the
	// same "boring and greppable" rule the rest of this function follows.
	str("AGENTRY_SOCIAL_GOOGLE_CLIENT_ID", &c.Social.Google.ClientID)
	str("AGENTRY_SOCIAL_GOOGLE_CLIENT_SECRET", &c.Social.Google.ClientSecret)
	str("AGENTRY_SOCIAL_GOOGLE_ISSUER", &c.Social.Google.Issuer)
	str("AGENTRY_SOCIAL_GITHUB_CLIENT_ID", &c.Social.GitHub.ClientID)
	str("AGENTRY_SOCIAL_GITHUB_CLIENT_SECRET", &c.Social.GitHub.ClientSecret)
	str("AGENTRY_SOCIAL_GITHUB_AUTH_URL", &c.Social.GitHub.AuthURL)
	str("AGENTRY_SOCIAL_GITHUB_TOKEN_URL", &c.Social.GitHub.TokenURL)
	str("AGENTRY_SOCIAL_GITHUB_API_BASE_URL", &c.Social.GitHub.APIBaseURL)
	str("AGENTRY_SOCIAL_MICROSOFT_CLIENT_ID", &c.Social.Microsoft.ClientID)
	str("AGENTRY_SOCIAL_MICROSOFT_CLIENT_SECRET", &c.Social.Microsoft.ClientSecret)
	str("AGENTRY_SOCIAL_MICROSOFT_ISSUER", &c.Social.Microsoft.Issuer)
	str("AGENTRY_SOCIAL_OPENAI_CLIENT_ID", &c.Social.OpenAI.ClientID)
	str("AGENTRY_SOCIAL_OPENAI_CLIENT_SECRET", &c.Social.OpenAI.ClientSecret)
	str("AGENTRY_SOCIAL_OPENAI_ISSUER", &c.Social.OpenAI.Issuer)
	str("AGENTRY_SOCIAL_CLAUDE_CLIENT_ID", &c.Social.Claude.ClientID)
	str("AGENTRY_SOCIAL_CLAUDE_CLIENT_SECRET", &c.Social.Claude.ClientSecret)
	str("AGENTRY_SOCIAL_CLAUDE_ISSUER", &c.Social.Claude.Issuer)
	str("AGENTRY_SOCIAL_AUTHENTIK_CLIENT_ID", &c.Social.Authentik.ClientID)
	str("AGENTRY_SOCIAL_AUTHENTIK_CLIENT_SECRET", &c.Social.Authentik.ClientSecret)
	str("AGENTRY_SOCIAL_AUTHENTIK_ISSUER", &c.Social.Authentik.Issuer)
	str("AGENTRY_IDP_ADMIN_URL", &c.Auth.IdPAdminURL)
	str("AGENTRY_IDP_ADMIN_TOKEN", &c.Auth.IdPAdminToken)
	str("AGENTRY_IDP_STAFF_GROUP", &c.Auth.IdPStaffGroup)
	if err := boolean("AGENTRY_AUTH_REQUIRE_IDP_MFA", &c.Auth.RequireIdPMFA); err != nil {
		return err
	}

	// Audit stream + retention (§12.6, §4.3).
	str("AGENTRY_AUDIT_STREAM_KIND", &c.Audit.StreamKind)
	str("AGENTRY_AUDIT_STREAM_DIR", &c.Audit.StreamDir)
	str("AGENTRY_AUDIT_STREAM_S3_BUCKET", &c.Audit.StreamS3Bucket)
	if err := dur("AGENTRY_AUDIT_STREAM_FLUSH", &c.Audit.StreamFlush); err != nil {
		return err
	}
	if err := integer("AGENTRY_AUDIT_RETENTION_DAYS", &c.Audit.RetentionDays); err != nil {
		return err
	}
	// §17.5 red-team job (agentry#67).
	if err := dur("AGENTRY_REDTEAM_INTERVAL", &c.RedTeam.Interval); err != nil {
		return err
	}
	str("AGENTRY_REDTEAM_CORPUS_DIR", &c.RedTeam.CorpusDir)

	if err := boolean("AGENTRY_DEV_MODE", &c.DevMode); err != nil {
		return err
	}
	if err := boolean("AGENTRY_DATABASE_MIGRATE_ON_START", &c.Database.MigrateOnStart); err != nil {
		return err
	}
	if err := boolean("AGENTRY_AUTH_EXTERNAL_ONLY", &c.Auth.ExternalOnly); err != nil {
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
	if err := dur("AGENTRY_AUTH_PAT_ORG_BOUND_MAX_TTL", &c.Auth.PATOrgBoundMaxTTL); err != nil {
		return err
	}
	if err := dur("AGENTRY_AUTH_SSO_MAX_AGE", &c.Auth.SSOMaxAge); err != nil {
		return err
	}

	// Telemetry (§16.2, D-25).
	str("AGENTRY_MIN_CLI_VERSION", &c.MinCLIVersion)
	str("AGENTRY_OTEL_ENDPOINT", &c.Telemetry.OTLPEndpoint)
	if err := dur("AGENTRY_OTEL_EXPORT_INTERVAL", &c.Telemetry.ExportInterval); err != nil {
		return err
	}
	if err := dur("AGENTRY_METRICS_QUEUE_SAMPLE_INTERVAL", &c.Telemetry.QueueSampleInterval); err != nil {
		return err
	}
	if err := integer("AGENTRY_TRUSTED_PROXIES", &c.HTTP.TrustedProxies); err != nil {
		return err
	}

	// Notifications (§13.4).
	str("AGENTRY_NOTIFY_KIND", &c.Notify.Kind)
	str("AGENTRY_SMTP_HOST", &c.SMTP.Host)
	str("AGENTRY_SMTP_USER", &c.SMTP.Username)
	str("AGENTRY_SMTP_PASS", &c.SMTP.Password)
	str("AGENTRY_SMTP_FROM", &c.SMTP.From)
	if err := integer("AGENTRY_SMTP_PORT", &c.SMTP.Port); err != nil {
		return err
	}
	if err := boolean("AGENTRY_SMTP_STARTTLS", &c.SMTP.StartTLS); err != nil {
		return err
	}
	if err := dur("AGENTRY_SMTP_TIMEOUT", &c.SMTP.Timeout); err != nil {
		return err
	}

	// §19 quotas. Exposed as env so a self-host operator can raise them
	// without a config file; the entitlements Resolver is what reads them.
	for _, m := range []struct {
		key string
		dst *int
	}{
		{"AGENTRY_LIMITS_AUTHED_PER_HOUR", &c.Limits.AuthedPerHour},
		{"AGENTRY_LIMITS_AUTHED_BURST_PER_MIN", &c.Limits.AuthedBurstPerMin},
		{"AGENTRY_LIMITS_ANONYMOUS_PER_MIN", &c.Limits.AnonymousPerMin},
		{"AGENTRY_LIMITS_LOGIN_PER_MIN", &c.Limits.LoginPerMin},
		{"AGENTRY_LIMITS_GIT_PUSHES_PER_HOUR", &c.Limits.GitPushesPerHour},
		{"AGENTRY_LIMITS_AGENTS_PER_USER_NAMESPACE", &c.Limits.AgentsPerUserNamespace},
		{"AGENTRY_LIMITS_AGENTS_PER_ORG_NAMESPACE", &c.Limits.AgentsPerOrgNamespace},
		{"AGENTRY_LIMITS_VERSIONS_PER_DAY", &c.Limits.VersionsPerDay},
		{"AGENTRY_LIMITS_WEBHOOK_ENDPOINTS_PER_ORG", &c.Limits.WebhookEndpointsPerOrg},
		{"AGENTRY_LIMITS_WEBHOOK_DELIVERIES_PER_SECOND", &c.Limits.WebhookDeliveriesPerSecond},
		{"AGENTRY_LIMITS_ARCHIVE_MAX_FILES", &c.Limits.ArchiveMaxFiles},
	} {
		if err := integer(m.key, m.dst); err != nil {
			return err
		}
	}
	for _, m := range []struct {
		key string
		dst *int64
	}{
		{"AGENTRY_LIMITS_ARCHIVE_MAX_BYTES", &c.Limits.ArchiveMaxBytes},
		{"AGENTRY_LIMITS_ARCHIVE_MAX_FILE_BYTES", &c.Limits.ArchiveMaxFileBytes},
		{"AGENTRY_LIMITS_ARCHIVE_MAX_IMAGE_FILE_BYTES", &c.Limits.ArchiveMaxImageFileBytes},
	} {
		if err := integer64(m.key, m.dst); err != nil {
			return err
		}
	}

	if err := boolean("AGENTRY_STORAGE_S3_USE_PATH_STYLE", &c.Storage.S3UsePathStyle); err != nil {
		return err
	}
	return nil
}

func integer64(key string, dst *int64) error {
	v, ok := os.LookupEnv(key)
	if !ok {
		return nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return fmt.Errorf("config: %s: %w", key, err)
	}
	*dst = n
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
	switch c.UI.Mode {
	case "full", "authorize", "off":
	default:
		return fmt.Errorf("config: ui.mode must be full|authorize|off, got %q", c.UI.Mode)
	}
	if c.Web.URL != "" {
		u, err := url.Parse(c.Web.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
			return fmt.Errorf("config: web.url must be an absolute http(s) origin, got %q", c.Web.URL)
		}
	}
	if c.Env == "prod" && c.Signing.Kind == "none" {
		return fmt.Errorf("config: signing.kind none is not allowed in prod")
	}
	if !c.DevMode && c.Auth.SealingKey == "" {
		return fmt.Errorf("config: auth.sealingKey is required outside dev mode")
	}
	switch c.Judge.Provider {
	case "", "none", "static", "openai", "anthropic", "bedrock", "classifier":
	default:
		return fmt.Errorf("config: judge.provider must be none|static|openai|anthropic|bedrock|classifier, got %q", c.Judge.Provider)
	}
	switch c.Judge.Provider {
	case "openai", "anthropic":
		if c.Judge.BaseURL == "" || c.Judge.APIKey == "" {
			return fmt.Errorf("config: judge.baseUrl and judge.apiKey are required when judge.provider is %q", c.Judge.Provider)
		}
	case "classifier":
		if c.Judge.BaseURL == "" {
			return fmt.Errorf("config: judge.baseUrl (the classify endpoint) is required when judge.provider is %q", c.Judge.Provider)
		}
	}
	switch c.Audit.StreamKind {
	case "", "none", "file", "s3":
	default:
		return fmt.Errorf("config: audit.streamKind must be none|file|s3, got %q", c.Audit.StreamKind)
	}
	if c.Audit.StreamKind == "file" && c.Audit.StreamDir == "" {
		return fmt.Errorf("config: audit.streamDir is required when audit.streamKind is file")
	}
	if c.Audit.RetentionDays < 0 {
		return fmt.Errorf("config: audit.retentionDays must be >= 0")
	}
	if err := c.validateAuthTTLs(); err != nil {
		return err
	}
	if err := c.validateNotify(); err != nil {
		return err
	}
	if c.Storage.Kind == "s3" && c.Storage.S3Bucket == "" {
		return fmt.Errorf("config: storage.s3Bucket is required when storage.kind is s3")
	}
	if c.Signing.Kind == "kms" && c.Signing.KMSKeyARN == "" {
		return fmt.Errorf("config: signing.kmsKeyARN is required when signing.kind is kms")
	}
	if err := validateWindow("signing", c.Signing.NotBefore, c.Signing.NotAfter); err != nil {
		return err
	}
	for i, k := range c.Signing.AdditionalKeys {
		where := fmt.Sprintf("signing.additionalKeys[%d]", i)
		if k.KeyID == "" {
			return fmt.Errorf("config: %s.keyId is required", where)
		}
		if (k.PublicKeyPEM == "") == (k.PublicKeyFile == "") {
			return fmt.Errorf("config: %s must set exactly one of publicKeyPem or publicKeyFile", where)
		}
		if err := validateWindow(where, k.NotBefore, k.NotAfter); err != nil {
			return err
		}
	}
	if c.HTTP.TrustedProxies < 0 {
		return fmt.Errorf("config: http.trustedProxies must be >= 0")
	}
	return c.validateLimits()
}

// TTL ceilings from §12.3/§12.4. These are hard product limits, not tunables:
// a deployment that raised them would still be an Agentry deployment by name
// while quietly issuing credentials the threat model never priced in.
const (
	// MaxSessionTTL — §12.4: "sessions capped at 24 h absolute".
	MaxSessionTTL = 24 * time.Hour
	// MaxPATTTL — §12.3: max token lifetime 1 year.
	MaxPATTTL = 365 * 24 * time.Hour
	// MaxPATOrgBoundTTL — §12.3: 90 days if org-bound under enforced SSO.
	MaxPATOrgBoundTTL = 90 * 24 * time.Hour
	// MaxSSOMaxAge bounds the enforced-SSO freshness window. §12.4 gives 8 h
	// as the DEFAULT and leaves the value org-configurable, so the ceiling is
	// derived rather than quoted: a freshness requirement longer than the
	// absolute session cap can never bind, because no session survives long
	// enough to violate it. Capping at the session cap keeps the knob honest.
	MaxSSOMaxAge = MaxSessionTTL
)

func (c Config) validateAuthTTLs() error {
	for _, b := range []struct {
		name  string
		value time.Duration
		max   time.Duration
	}{
		{"auth.sessionTTL", c.Auth.SessionTTL, MaxSessionTTL},
		{"auth.patMaxTTL", c.Auth.PATMaxTTL, MaxPATTTL},
		{"auth.patOrgBoundMaxTTL", c.Auth.PATOrgBoundMaxTTL, MaxPATOrgBoundTTL},
		{"auth.ssoMaxAge", c.Auth.SSOMaxAge, MaxSSOMaxAge},
	} {
		if b.value <= 0 {
			return fmt.Errorf("config: %s must be > 0", b.name)
		}
		if b.value > b.max {
			return fmt.Errorf("config: %s is %s; the maximum is %s (§12.3/§12.4)", b.name, b.value, b.max)
		}
	}
	// An org-bound PAT is a narrowing of a PAT, so its ceiling cannot exceed
	// the general one — otherwise "org-bound" would mean "longer-lived".
	if c.Auth.PATOrgBoundMaxTTL > c.Auth.PATMaxTTL {
		return fmt.Errorf("config: auth.patOrgBoundMaxTTL (%s) exceeds auth.patMaxTTL (%s)",
			c.Auth.PATOrgBoundMaxTTL, c.Auth.PATMaxTTL)
	}
	return nil
}

func (c Config) validateNotify() error {
	switch c.Notify.Kind {
	case "", "log":
		return nil
	case "smtp":
	default:
		return fmt.Errorf("config: notify.kind must be log|smtp, got %q", c.Notify.Kind)
	}
	if c.SMTP.Host == "" {
		return fmt.Errorf("config: smtp.host is required when notify.kind is smtp")
	}
	if c.SMTP.Port <= 0 || c.SMTP.Port > 65535 {
		return fmt.Errorf("config: smtp.port must be 1-65535, got %d", c.SMTP.Port)
	}
	if c.SMTP.From == "" {
		return fmt.Errorf("config: smtp.from is required when notify.kind is smtp")
	}
	// A password sent over a cleartext session is a password disclosed. In dev
	// (mailpit) there is no password, so the pairing only bites in real use.
	if c.SMTP.Username != "" && !c.SMTP.StartTLS && !c.DevMode {
		return fmt.Errorf("config: smtp.startTLS must be true when smtp.username is set outside dev mode")
	}
	return nil
}

func (c Config) validateLimits() error {
	for _, l := range []struct {
		name  string
		value int64
	}{
		{"limits.authedPerHour", int64(c.Limits.AuthedPerHour)},
		{"limits.authedBurstPerMin", int64(c.Limits.AuthedBurstPerMin)},
		{"limits.anonymousPerMin", int64(c.Limits.AnonymousPerMin)},
		{"limits.loginPerMin", int64(c.Limits.LoginPerMin)},
		{"limits.repoQuotaBytes", int64(c.Limits.RepoQuotaBytes)},
		{"limits.repoMaxBlobBytes", int64(c.Limits.RepoMaxBlobBytes)},
		{"limits.gitPushesPerHour", int64(c.Limits.GitPushesPerHour)},
		{"limits.agentsPerUserNamespace", int64(c.Limits.AgentsPerUserNamespace)},
		{"limits.agentsPerOrgNamespace", int64(c.Limits.AgentsPerOrgNamespace)},
		{"limits.versionsPerDay", int64(c.Limits.VersionsPerDay)},
		{"limits.webhookEndpointsPerOrg", int64(c.Limits.WebhookEndpointsPerOrg)},
		{"limits.webhookDeliveriesPerSecond", int64(c.Limits.WebhookDeliveriesPerSecond)},
		{"limits.archiveMaxBytes", c.Limits.ArchiveMaxBytes},
		{"limits.archiveMaxFiles", int64(c.Limits.ArchiveMaxFiles)},
		{"limits.archiveMaxFileBytes", c.Limits.ArchiveMaxFileBytes},
		{"limits.archiveMaxImageFileBytes", c.Limits.ArchiveMaxImageFileBytes},
	} {
		if l.value <= 0 {
			return fmt.Errorf("config: %s must be > 0", l.name)
		}
	}
	return nil
}

// validateWindow rejects unparseable or inverted validity windows at startup,
// so a rotation typo cannot publish a key set nothing accepts.
func validateWindow(where, notBefore, notAfter string) error {
	var nb, na time.Time
	var err error
	if notBefore != "" {
		if nb, err = time.Parse(time.RFC3339, notBefore); err != nil {
			return fmt.Errorf("config: %s.notBefore: %w", where, err)
		}
	}
	if notAfter != "" {
		if na, err = time.Parse(time.RFC3339, notAfter); err != nil {
			return fmt.Errorf("config: %s.notAfter: %w", where, err)
		}
	}
	if !nb.IsZero() && !na.IsZero() && !na.After(nb) {
		return fmt.Errorf("config: %s.notAfter (%s) must be after notBefore (%s)", where, notAfter, notBefore)
	}
	return nil
}
