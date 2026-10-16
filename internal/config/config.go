// Package config loads agentryd configuration from agentry.yaml plus
// AGENTRY_* environment overrides. Environment always wins over file values;
// defaults are safe for local development.
package config

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/blaktron/agentry/pkg/websearch"
)

// Config is the full agentryd configuration tree.
type Config struct {
	// Env names the deployment environment: dev | staging | prod.
	Env string `yaml:"env"`
	// DevMode enables development conveniences, and is opt-in: false unless
	// the configuration says otherwise, and refused unless env is dev
	// (Validate enforces both). One boolean switches five
	// controls off at once — the at-rest sealing key (a public constant
	// stands in), 2FA before a public publish, release signing (an
	// ephemeral key at every start), the scan judge (none becomes static)
	// and the S8 IP-cluster signal (a fixed literal) — so a deployment that
	// did not ask for it must never get it.
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
	WebSearch WebSearch `yaml:"webSearch"`
	Scan      Scan      `yaml:"scan"`
	Social    Social    `yaml:"social"`
	Audit     Audit     `yaml:"audit"`
	Orgs      Orgs      `yaml:"orgs"`
	RedTeam   RedTeam   `yaml:"redTeam"`
	Telemetry Telemetry `yaml:"telemetry"`
	Queue     Queue     `yaml:"queue"`
	Notify    Notify    `yaml:"notify"`
	SMTP      SMTP      `yaml:"smtp"`
	BaseURL   string    `yaml:"baseURL"` // public origin, e.g. https://agentry.example
	Web       Web       `yaml:"web"`
	UI        UI        `yaml:"ui"`
	Brand     Brand     `yaml:"brand"`
	Knowledge Knowledge `yaml:"knowledge"`
	// MinCLIVersion, when set, is advertised via GET /api/v1/meta so the CLI
	// can warn (or refuse, on a major gap) before talking to an API it
	// predates. Empty = no minimum advertised.
	MinCLIVersion string `yaml:"minCLIVersion"`
}

// HTTP configures listeners. Git traffic may share Addr (self-host) or use
// GitAddr (a separate hostname in a hosted deployment).
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
	// match the deployment exactly.
	TrustedProxies int `yaml:"trustedProxies"`
	// TrustedProxyCIDRs, when set, names the addresses the trusted hop
	// connects from. X-Forwarded-For is then read only on a
	// request whose TCP peer is inside one of these ranges; every other
	// request resolves to its peer, whatever the header says. Without it
	// the hop count trusts the header's tail from whoever connects, so a
	// client that reaches agentryd directly names its own address; with
	// it that is a property of the code, not of which ports a deployment
	// happens to expose. CIDRs or bare addresses. Used only when
	// trustedProxies >= 1; the hop count keeps its meaning for the entries
	// the trusted hops wrote.
	TrustedProxyCIDRs []string `yaml:"trustedProxyCIDRs"`
	// ProxyRequestID says the hop in front SETS X-Request-Id on every request
	// it forwards (the compose edge does; an ALB does not), so an inbound id
	// is honoured (docs/logging.md). Off (the default) means the server mints
	// its own and ignores the header. A trusted hop count is not enough on
	// its own: a hop that forwards the header without overwriting it lets
	// any client choose the id stamped on its lines and audit rows.
	ProxyRequestID bool `yaml:"proxyRequestID"`
}

// Database configures the PostgreSQL system of record.
type Database struct {
	URL string `yaml:"url"`
	// MigrateOnStart runs goose migrations at boot (self-host convenience).
	MigrateOnStart bool `yaml:"migrateOnStart"`
}

// Redis is an optional dependency, and nothing in the core reads the
// URL today: it is reported as features.redis on GET /api/v1/meta and that is
// all. The state a replica set must share lives in Postgres — sessions, the
// queue, and the SAML replay and request sets — so there is no
// in-memory fallback this would replace. The rate-limit buckets stay per
// process either way (docs/self-hosting.md).
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

// Git configures bare-repo hosting.
type Git struct {
	DataDir string `yaml:"dataDir"` // bare repos under {dataDir}/{uuid[0:2]}/{uuid}.git
	BinPath string `yaml:"binPath"` // git binary; defaults to $PATH lookup
	// HooksDir is where the git role makes the private directory git runs
	// the pre-receive hook from; it must allow exec and be owned by the
	// server (or sticky, like /tmp). Empty means the system temp directory.
	// The repositories' own volume is not used, since it may not allow exec.
	HooksDir string `yaml:"hooksDir"`
	// SSHAddr, when set, is where the git and all roles listen for the SSH
	// transport, e.g. ":2222". Empty disables it.
	SSHAddr string `yaml:"sshAddr"`
	// SSHHostKeyFile is the PEM host key; empty means {dataDir}/ssh_host_ed25519_key,
	// generated on first start.
	SSHHostKeyFile string `yaml:"sshHostKeyFile"`
	// SSHPublicURL is the base clients use, e.g. "ssh://git@git.example.com:2222";
	// when set, agent documents carry gitSshUrl.
	SSHPublicURL string `yaml:"sshPublicUrl"`
	// SSHProxyProtocolCIDRs, when set, says a TCP proxy fronts the SSH
	// listener and names the addresses it connects from.
	// Every connection must then come from one of these ranges and open
	// with a PROXY protocol header (v1 or v2), whose source address becomes
	// the client's: the key-offer budget and the log lines key on
	// it. A connection from any other address is refused, header or
	// not, so a client cannot name its own address. Empty (the default)
	// reads no header and keys on the TCP peer. CIDRs or bare addresses.
	SSHProxyProtocolCIDRs []string `yaml:"sshProxyProtocolCIDRs"`
}

// Log configures structured logging.
type Log struct {
	Level string `yaml:"level"` // debug | info | warn | error
}

// Auth holds authentication tunables.
type Auth struct {
	// SessionTTL is the absolute session lifetime (capped at 24h).
	SessionTTL time.Duration `yaml:"sessionTTL"`
	// PATMaxTTL is the maximum PAT lifetime (1y, 90d org-bound).
	PATMaxTTL time.Duration `yaml:"patMaxTTL"`
	// PATOrgBoundMaxTTL caps org-bound PAT lifetime under enforced SSO
	// (90 days).
	PATOrgBoundMaxTTL time.Duration `yaml:"patOrgBoundMaxTTL"`
	// SSOMaxAge is how fresh a session's SSO assertion must be to act on an
	// enforced-SSO org's resources (default 8h).
	SSOMaxAge time.Duration `yaml:"ssoMaxAge"`
	// TrustedDeviceTTL is how long a browser remembered at sign-in skips the
	// second factor. This is a second
	// browser credential class and it deliberately outlives the session cap:
	// a session still has to be earned by password on every sign-in and is
	// still capped at MaxSessionTTL, so raising this does not lengthen any
	// session. The lifetime is absolute — using it does not extend it — and
	// the ceiling below is a hard product limit like the others.
	TrustedDeviceTTL time.Duration `yaml:"trustedDeviceTTL"`
	// IdPTrustCheckToken turns on remembered browsers on the directory's
	// sign-in: the directory's sign-in flow presents
	// it as a bearer secret when it asks the registry whether a browser's
	// cookie is a live record, and the registry mints records from a
	// directory sign-in only while it is set. Empty means the directory path
	// is off: nothing is minted there and the check route answers 404. At
	// least 32 characters; the directory's side holds the same value.
	// Where an extension supplies the directory, it remembers browsers and
	// answers the check itself, and the core's route answers 404; the core
	// still expires the cookie when an account clears its remembered
	// browsers.
	IdPTrustCheckToken string `yaml:"idpTrustCheckToken"`
	// DirectoryCookieDomain is the parent domain the remembered-browser
	// cookie of the directory path is set on (the native path's cookie is
	// always host-only), when the directory and the registry are sibling
	// hosts (app.example.com and auth.example.com under example.com). Empty
	// derives it: a directory on the registry's own host gets a host-only
	// cookie, and one on a subdomain of it gets the registry's host. See
	// DirectoryTrustCookieDomain.
	DirectoryCookieDomain string `yaml:"directoryCookieDomain"`
	// CookieSecure marks session cookies Secure (default true outside dev).
	CookieSecure bool `yaml:"cookieSecure"`
	// SealingKey is a base64 32-byte key encrypting small secrets at rest
	// (TOTP seeds). Empty is allowed only in dev (a fixed insecure key).
	SealingKey string `yaml:"sealingKey"`
	// ExternalOnly hands credentials and the account directory to an
	// external IdP (the stack's Authentik instance). When true the
	// native register / password-login / email-verify / TOTP endpoints
	// answer 410 Gone and sign-in happens only through a configured social
	// or SSO provider. Sessions, PATs, and RBAC stay native: the IdP owns
	// who you are, this server owns what you may do. The "2FA before
	// public publish" gate is delegated to the IdP as well, since no account
	// can enrol a native TOTP factor while this is set (see
	// internal/api/publish_gate.go).
	ExternalOnly bool `yaml:"externalOnly"`
	// IdPLogoutURL is the directory's sign-out URL: where sign-out sends the
	// browser once the session is revoked, so the next sign-in asks again.
	// For authentik that is the provider's end-session endpoint behind the
	// cancel view (docs/self-hosting.md). Empty means sign-out ends on the
	// home page.
	IdPLogoutURL string `yaml:"idpLogoutURL"`
	// IdPAdminURL / IdPAdminToken let account erasure reach into the
	// directory service and delete the sign-in account there too — authentik's
	// API, as a bearer token with rights over users. Empty means
	// erasure stops at the registry, which docs/self-hosting.md and the
	// privacy policy then have to say. The URL is the API origin as the
	// server reaches it (compose: http://authentik-server:9000).
	IdPAdminURL   string `yaml:"idpAdminURL"`
	IdPAdminToken string `yaml:"idpAdminToken"`
	// StaffOrg is the handle of the staff organization:
	// platform staff is exactly an active account with a verified address
	// at StaffDomain that is an active member of this organization, and
	// the organization admits nobody else. Membership is granted by the
	// organization's admins; the address is verified by the directory. The
	// flag is recomputed at every membership change, at sign-in and once
	// when the server starts. Set both or neither; with neither the flag
	// is left as it is.
	StaffOrg string `yaml:"staffOrg"`
	// StaffDomain is the staff organization's domain: a bare lower-case
	// DNS name, matched exactly (no subdomain) against the account's
	// verified address.
	StaffDomain string `yaml:"staffDomain"`
	// IdPStaffMirrorGroup names the directory group the registry keeps equal
	// to its platform staff: every active account with the platform_staff
	// flag, and nobody else, matched by verified address. It is a mirror,
	// written by the registry through IdPAdminURL/IdPAdminToken, never read
	// back as a source: the flag stays the staff organization's. A directory
	// application that should admit staff alone, such as an OpenSearch
	// Dashboards, reads membership of this group from its tokens. Empty means no mirror. It needs the admin URL and token and
	// the staff organization. Where an extension supplies the directory,
	// the core keeps no mirror and the extension keeps its own.
	IdPStaffMirrorGroup string `yaml:"idpStaffMirrorGroup"`
	// IdPStaffGroup is retired: the directory group no longer grants
	// platform staff. It is still read, so a
	// configuration that sets it loads, and the server warns at start-up.
	IdPStaffGroup string `yaml:"idpStaffGroup"`
	// IdPStaffDomain is retired: being at a domain makes an account
	// eligible to join the staff organization (StaffDomain), not staff by
	// itself. Read and warned about like
	// IdPStaffGroup.
	IdPStaffDomain string `yaml:"idpStaffDomain"`
	// OIDC is the deployment's one "sign in with your OpenID provider": any
	// OpenID Connect issuer the operator registers the registry with. See
	// OIDCProvider, and SignInOIDC for how the social.authentik keys
	// name the same provider.
	OIDC OIDCProvider `yaml:"oidc"`
	// RequireIdPMFA re-enables the "2FA before public publish" gate
	// under externalOnly, satisfied by evidence rather than trust: the
	// account must have signed in at least once with an ID token whose
	// `amr` names a second factor (users.idp_mfa_at). Off by default because
	// it is only honest once the directory actually enforces MFA.
	RequireIdPMFA bool `yaml:"requireIdpMFA"`
}

// Queue selects the async job driver.
type Queue struct {
	// Driver is "river" (the default and the only driver: River,
	// Postgres-backed, its tables created by the migrator). "pg", a driver
	// built on SELECT … FOR UPDATE SKIP LOCKED, is refused: its jobs table
	// no longer exists.
	Driver string `yaml:"driver"`
	// Workers is how many jobs one worker process runs at once per queue.
	// 1 keeps the serial behaviour.
	Workers int `yaml:"workers"`
}

// Limits tunes the quotas. These are the values internal/entitlements'
// config-backed default Resolver hands out; a hosted overlay swaps in a
// Resolver that reads them per-org instead. Nothing in the open-source tree
// reads a limit except through that Resolver.
type Limits struct {
	AuthedPerHour     int `yaml:"authedPerHour"`     // sustained authed budget
	AuthedBurstPerMin int `yaml:"authedBurstPerMin"` // authed burst
	AnonymousPerMin   int `yaml:"anonymousPerMin"`   // anonymous per-IP
	LoginPerMin       int `yaml:"loginPerMin"`       // login/register per-IP
	// SCIMPerMin is the SCIM data plane's budget per organization, per
	// minute and as its burst (600): a directory syncs from one place, so the
	// organization, not the address, is what it spends.
	SCIMPerMin int `yaml:"scimPerMin"`
	// ModelInputPerMin is the model-input routes' budget per caller, per
	// minute and as its burst (120): a platform staff member,
	// or one hosted job. An address presenting job credentials may spend
	// ten times that, which bounds guessing at credentials without
	// starving the sandbox hosts behind one NAT.
	ModelInputPerMin int `yaml:"modelInputPerMin"`

	// Git/repo quotas: 100 MB hard, 25 MB warn (the pre-receive hook
	// tells the pusher), 25 MB single-object cap.
	RepoQuotaBytes   int `yaml:"repoQuotaBytes"`
	RepoWarnBytes    int `yaml:"repoWarnBytes"`
	RepoMaxBlobBytes int `yaml:"repoMaxBlobBytes"`
	// GitPushesPerHour is the per-repo push budget (60/h), one number
	// on both transports.
	GitPushesPerHour int `yaml:"gitPushesPerHour"`
	// SSHKeyOffersPerMin bounds the public keys one source address may
	// offer the git SSH listener per minute, spent before the key is looked
	// up (60/min).
	SSHKeyOffersPerMin int `yaml:"sshKeyOffersPerMin"`
	// GitConcurrentPerIP is the budget of concurrent git operations per
	// client address (20), on both transports, keyed on the trusted client
	// address (http.trustedProxyCIDRs, git.sshProxyProtocolCIDRs). An
	// address at it is refused at once rather than queued.
	GitConcurrentPerIP int `yaml:"gitConcurrentPerIP"`

	// Namespace + publish-velocity quotas.
	AgentsPerUserNamespace int `yaml:"agentsPerUserNamespace"` // 200
	AgentsPerOrgNamespace  int `yaml:"agentsPerOrgNamespace"`  // 500
	VersionsPerDay         int `yaml:"versionsPerDay"`         // 20 per agent

	// Webhook quotas: 20 endpoints per org, 5 deliveries/s per org.
	WebhookEndpointsPerOrg     int `yaml:"webhookEndpointsPerOrg"`
	WebhookDeliveriesPerSecond int `yaml:"webhookDeliveriesPerSecond"`

	// Release-archive quotas, enforced by manifest validation (V8).
	ArchiveMaxBytes          int64 `yaml:"archiveMaxBytes"`          // 10 MiB
	ArchiveMaxFiles          int   `yaml:"archiveMaxFiles"`          // 2000
	ArchiveMaxFileBytes      int64 `yaml:"archiveMaxFileBytes"`      // 2 MiB
	ArchiveMaxImageFileBytes int64 `yaml:"archiveMaxImageFileBytes"` // 5 MiB
	ArchiveMaxTextBytes      int64 `yaml:"archiveMaxTextBytes"`      // 1 MiB: the text files in total

	// KnowledgeBytesPerAccount caps the knowledge an account keeps in the
	// registry, in bytes of its packs' trees. 0, the default, is no cap: a
	// self-hoster sets one. A cap never deletes: over it, no pack is added or
	// grown.
	KnowledgeBytesPerAccount int64 `yaml:"knowledgeBytesPerAccount"`
}

// Knowledge configures the store of knowledge packs.
type Knowledge struct {
	// SealingKey is a base64 32-byte key the core wraps packs' data keys
	// under (AGENTRY_KNOWLEDGE_SEALING_KEY): a key of its own, refused when
	// it is the auth sealing key. Empty outside dev mode leaves the store
	// off (its routes answer 503) unless an extension wraps the keys; in
	// dev mode a fixed insecure key stands in, as for the auth sealer.
	SealingKey string `yaml:"sealingKey"`
}

// Signing configures attestation signing: kms | file | none(dev).
type Signing struct {
	Kind      string `yaml:"kind"` // kms | file | none
	KMSKeyARN string `yaml:"kmsKeyARN"`
	// KMSRegion overrides the ambient AWS region for the KMS client. Empty
	// uses the credential chain's region.
	KMSRegion string `yaml:"kmsRegion"`
	KeyFile   string `yaml:"keyFile"`
	// NotBefore/NotAfter bound the ACTIVE key's validity window, RFC3339
	// (the discovery document carries a validity window per key). Both
	// optional; an empty side is unbounded.
	NotBefore string `yaml:"notBefore"`
	NotAfter  string `yaml:"notAfter"`
	// AdditionalKeys are verification-only public keys published alongside
	// the active one. Rotation works by OVERLAPPING validity windows, which
	// is only representable if the endpoint can serve more than one key:
	// during a rotation the outgoing key stays listed, with a notAfter, until
	// every attestation it signed has been re-verified or aged out.
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

// Telemetry configures the metric exporters.
type Telemetry struct {
	// OTLPEndpoint is the collector base URL, e.g. http://localhost:4318 for
	// the ADOT sidecar. Empty disables OTLP export; /metrics stays on either
	// way, so a self-hosted instance is never dark.
	OTLPEndpoint string `yaml:"otlpEndpoint"`
	// ExportInterval is the OTLP flush period (default 30s, matching the
	// collector's batch timeout).
	ExportInterval time.Duration `yaml:"exportInterval"`
	// QueueSampleInterval is how often the worker publishes queue depth and
	// oldest-job age. It bounds how stale the queue-age page alarm can
	// be, so it must stay well under the 15-minute alarm threshold.
	QueueSampleInterval time.Duration `yaml:"queueSampleInterval"`
}

// Notify selects the notification transport (SES in a hosted deployment, mailpit in
// the compose dev stack).
type Notify struct {
	// Kind is log | smtp. log stays the default so a fresh install never
	// silently fails to deliver: it says so, in the log.
	Kind string `yaml:"kind"`
}

// Web names a front end that fronts this server: the hosted site, or any
// other. When URL is set, every browser destination the API writes (where a
// failed sign-in lands, where a signed-in browser goes, where an email link
// points, where sign-out ends) is a page of that site. When it is unset the server points at its own pages under /ui/.
type Web struct {
	// URL is the site's origin, e.g. https://agentry.example (no path).
	URL string `yaml:"url"`
}

// UI selects how much of the server's own browser surface (/ui/…) is
// served: full (device authorize, sign-in, account, review, staff, org
// admin), authorize (only the device-authorize page — what a deployment with
// a site in front uses), or off.
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

// DirectoryTrustCookieDomain says where the remembered-browser cookie of the
// directory path is set. The registry sets it on the OIDC
// callback, on its own host, and the browser has to send it to the
// directory's flow executor, which is where the directory asks the registry
// about it. Cookies ignore ports, so:
//
//   - a directory on the registry's own host gets a host-only cookie ("");
//   - a directory on a subdomain of the registry's host gets a cookie for
//     the registry's host, which covers its subdomains;
//   - sibling hosts need auth.directoryCookieDomain, a parent domain of
//     both, and a browser refuses one that does not cover the host setting
//     it, so this refuses it first.
//
// An explicit domain must be a DNS name with at least two labels: a browser
// ignores a Domain attribute that is an address or a public suffix, and the
// cookie would then silently be host-only.
func (c Config) DirectoryTrustCookieDomain() (string, error) {
	issuer := c.DirectoryIssuer()
	if issuer == "" {
		return "", fmt.Errorf("config: auth.idpTrustCheckToken needs the directory configured (social.authentik, or auth.oidc with id authentik, with its issuer): it is the directory that asks")
	}
	registry := hostOf(c.BaseURL)
	if registry == "" {
		return "", fmt.Errorf("config: auth.idpTrustCheckToken needs baseURL: the registry sets the cookie on the callback at its public origin, and the directory has to be able to receive it")
	}
	directory := hostOf(issuer)
	if directory == "" {
		return "", fmt.Errorf("config: the directory's issuer %q has no host", issuer)
	}
	covers := func(parent, host string) bool { return host == parent || strings.HasSuffix(host, "."+parent) }
	d := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(c.Auth.DirectoryCookieDomain), "."))
	if d == "" {
		switch {
		case directory == registry:
			return "", nil
		case covers(registry, directory):
			return registry, nil
		default:
			return "", fmt.Errorf("config: the directory (%s) is not on the registry's host (%s) or under it: set auth.directoryCookieDomain to a parent domain of both", directory, registry)
		}
	}
	if _, err := netip.ParseAddr(d); err == nil || !strings.Contains(d, ".") {
		return "", fmt.Errorf("config: auth.directoryCookieDomain %q must be a domain name of at least two labels; a browser ignores an address or a bare label there", d)
	}
	if !covers(d, registry) || !covers(d, directory) {
		return "", fmt.Errorf("config: auth.directoryCookieDomain %q must cover both the registry (%s) and the directory (%s)", d, registry, directory)
	}
	return d, nil
}

// hostOf is the lower-cased host name of a URL, without its port; "" when
// the URL has none.
func hostOf(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
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

// Judge selects the S5 LLM adjudication provider.
//
// openai and anthropic talk to any endpoint speaking the matching wire
// protocol (hosted APIs or self-hosted gateways alike): set BaseURL to the
// API root and APIKey to the credential. The AGENTRY_JUDGE_TYPE,
// AGENTRY_JUDGE_BASE_URL and AGENTRY_JUDGE_API_KEY environment variables
// configure the same three values.
type Judge struct {
	Provider string `yaml:"provider"` // openai | anthropic | bedrock | typesafe | classifier | static | none
	Model    string `yaml:"model"`
	Region   string `yaml:"region"`
	BaseURL  string `yaml:"baseUrl"`
	APIKey   string `yaml:"apiKey"`
}

// WebSearch is the web search provider the registry brokers for the
// model-input search route: the Drafter's `web_search`, with the key held
// here beside the judge's so no sandbox host gains one. Provider is none
// (the default: the route answers 503), youcom (You.com's Web Search API),
// brave (Brave's LLM Context API), or tavily, exa or perplexity, which are
// there for a person's own key. AGENTRY_WEB_SEARCH_PROVIDER,
// AGENTRY_WEB_SEARCH_BASE_URL and AGENTRY_WEB_SEARCH_API_KEY set them; the
// key is never logged.
type WebSearch struct {
	Provider string `yaml:"provider"`
	BaseURL  string `yaml:"baseUrl"`
	APIKey   string `yaml:"apiKey"`
}

// Scan configures the external scanner tools behind the scanner seams.
// Every field is optional: unset, the native Go scanners run alone.
type Scan struct {
	// GitleaksBin is the path of a gitleaks binary S2 execs in addition to
	// its native ruleset. "auto" resolves it from PATH; empty disables.
	GitleaksBin string `yaml:"gitleaksBin"`
	// ToolTimeout bounds one external tool invocation; 0 means two minutes.
	ToolTimeout time.Duration `yaml:"toolTimeout"`
	// OSVURL is the vulnerability database S7 asks about declared MCP
	// servers. Empty means https://api.osv.dev; "none"
	// switches the lookup off (S7 then reports "not checked").
	OSVURL string `yaml:"osvUrl"`
	// NPMRegistryURL and PyPIURL are where S7 asks whether a declared
	// server's pinned version is published. Empty means
	// https://registry.npmjs.org and https://pypi.org; "none" in
	// NPMRegistryURL stops S7 asking either, and the report says it did not
	// check.
	NPMRegistryURL string `yaml:"npmRegistryUrl"`
	PyPIURL        string `yaml:"pypiUrl"`
}

// Social configures social login for individual accounts. A provider
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
	// Authentik is the deployment's own directory service. Like
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

// The ids the sign-in OIDC provider may have.
const (
	// OIDCProviderID is the generic provider's id.
	OIDCProviderID = "oidc"
	// DirectoryProviderID is the id of a provider that is the deployment's
	// own directory: its accounts are linked as "authentik:<sub>".
	DirectoryProviderID = "authentik"
)

// OIDCProvider is the sign-in OpenID provider: an issuer with a discovery
// document, and the client the registry is registered there as. Its
// redirect URI is <baseURL>/api/v1/auth/oidc/<id>/callback.
type OIDCProvider struct {
	// ID names the provider: the segment of its sign-in routes and the
	// prefix of every identity it links ("<id>:<sub>"). "oidc" by default;
	// "authentik" for a deployment whose provider is its own directory,
	// whose accounts are linked under that prefix already. Changing it
	// on a deployment with accounts unlinks every one of them.
	ID           string `yaml:"id"`
	Issuer       string `yaml:"issuer"`
	ClientID     string `yaml:"clientId"`
	ClientSecret string `yaml:"clientSecret"`
	// Scopes are asked for at sign-in; empty asks for openid, email and
	// profile (and, for the directory, the agentry scope its own claims
	// come with).
	Scopes []string `yaml:"scopes"`
	// DisplayName is what the sign-in page calls it ("Continue with …");
	// empty names it after the deployment for the directory and "your
	// OpenID provider" otherwise.
	DisplayName string `yaml:"displayName"`
}

// Configured reports whether the provider can be offered.
func (p OIDCProvider) Configured() bool { return p.ClientID != "" && p.ClientSecret != "" }

// SignInOIDC is the deployment's sign-in OpenID provider, when it has one:
// auth.oidc as configured, with its id defaulted, or else the
// social.authentik keys read as that provider under the id "authentik",
// which every identity they linked carries. The two are never both set
// (validate refuses it).
func (c Config) SignInOIDC() (OIDCProvider, bool) {
	if p := c.Auth.OIDC; p.Configured() {
		if p.ID == "" {
			p.ID = OIDCProviderID
		}
		return p, true
	}
	if a := c.Social.Authentik; a.Configured() {
		return OIDCProvider{ID: DirectoryProviderID, Issuer: a.Issuer, ClientID: a.ClientID, ClientSecret: a.ClientSecret}, true
	}
	return OIDCProvider{}, false
}

// DirectoryIssuer is the issuer of the sign-in provider when that provider
// is the deployment's own directory, "" otherwise: where the directory's
// settings links and the remembered browser's cookie domain come from.
func (c Config) DirectoryIssuer() string {
	if p, ok := c.SignInOIDC(); ok && p.ID == DirectoryProviderID {
		return strings.TrimSpace(p.Issuer)
	}
	return ""
}

// RedTeam configures the scheduled red-team job: corpus
// rewrites scanned against the S3/S4 bundle, report-only.
type RedTeam struct {
	// Interval is how often a worker runs the job; 0 disables it.
	Interval time.Duration `yaml:"interval"`
	// CorpusDir overrides where the attack corpus is read from (default:
	// the image's /srv/agentry/attack-corpus, else testdata/attack-corpus).
	CorpusDir string `yaml:"corpusDir"`
}

// Audit configures the continuous audit stream and its retention.
type Audit struct {
	// StreamKind selects the archive sink: none | file | log | s3.
	StreamKind string `yaml:"streamKind"`
	// StreamDir is the directory file-kind streams write daily files into.
	StreamDir string `yaml:"streamDir"`
	// StreamFlush bounds how long an event may sit in the buffer. The stream
	// promises delivery within about a minute; the default leaves headroom
	// under that.
	StreamFlush time.Duration `yaml:"streamFlush"`
	// StreamS3Bucket is the destination for s3-kind streams.
	StreamS3Bucket string `yaml:"streamS3Bucket"`
	// RetentionDays is how long audit rows stay in the hot table (400
	// days in a hosted deployment, configurable when self-hosted). 0
	// disables pruning.
	RetentionDays int `yaml:"retentionDays"`
}

// Orgs configures the organization lifecycle.
type Orgs struct {
	// DecommissionHold is how long a decommissioned organization stays
	// readable — members keep read and export — before the erasure job
	// deletes its agents, repositories, blobs and invitations and releases
	// its handle and domain. Zero erases at the next hourly sweep.
	DecommissionHold time.Duration `yaml:"decommissionHold"`
	// PendingDigestEvery is how often the worker mails each organization's
	// admins the pending members they have not been told about:
	// the domain fold-in and the IdP's provisioning are batched into one mail
	// per admin, and a person is named once. Zero keeps the default of a day;
	// the sweep that runs when an organization gains a domain sends one
	// digest at once regardless.
	PendingDigestEvery time.Duration `yaml:"pendingDigestEvery"`
}

// Default returns the baseline configuration: a development environment
// with dev mode OFF. A config that names no sealing key and no signing key
// therefore fails at boot rather than running on public constants; a
// throwaway stack opts in with devMode: true.
func Default() Config {
	return Config{
		Env:     "dev",
		DevMode: false,
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
			TrustedDeviceTTL:  30 * 24 * time.Hour,
			CookieSecure:      false,
		},
		Limits: Limits{
			AuthedPerHour:              5000,
			AuthedBurstPerMin:          100,
			AnonymousPerMin:            60,
			LoginPerMin:                10,
			SCIMPerMin:                 600,
			ModelInputPerMin:           120,
			RepoQuotaBytes:             100 << 20,
			RepoWarnBytes:              25 << 20,
			RepoMaxBlobBytes:           25 << 20,
			GitPushesPerHour:           60,
			SSHKeyOffersPerMin:         60,
			GitConcurrentPerIP:         20,
			AgentsPerUserNamespace:     200,
			AgentsPerOrgNamespace:      500,
			VersionsPerDay:             20,
			WebhookEndpointsPerOrg:     20,
			WebhookDeliveriesPerSecond: 5,
			ArchiveMaxBytes:            10 << 20,
			ArchiveMaxFiles:            2000,
			ArchiveMaxFileBytes:        2 << 20,
			ArchiveMaxImageFileBytes:   5 << 20,
			ArchiveMaxTextBytes:        1 << 20,
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
		Orgs:    Orgs{DecommissionHold: 30 * 24 * time.Hour, PendingDigestEvery: 24 * time.Hour},
		RedTeam: RedTeam{Interval: 24 * time.Hour},
		Queue:   Queue{Driver: "river", Workers: 1},
		Telemetry: Telemetry{
			ExportInterval: 30 * time.Second,
			// Well under the 15-minute queue-age threshold, so the
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
	// list reads a comma-separated value; set but empty clears the list.
	list := func(key string, dst *[]string) {
		v, ok := os.LookupEnv(key)
		if !ok {
			return
		}
		var out []string
		for _, part := range strings.Split(v, ",") {
			if part = strings.TrimSpace(part); part != "" {
				out = append(out, part)
			}
		}
		*dst = out
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
	str("AGENTRY_GIT_HOOKS_DIR", &c.Git.HooksDir)
	str("AGENTRY_GIT_SSH_ADDR", &c.Git.SSHAddr)
	str("AGENTRY_GIT_SSH_HOST_KEY", &c.Git.SSHHostKeyFile)
	str("AGENTRY_GIT_SSH_PUBLIC_URL", &c.Git.SSHPublicURL)
	list("AGENTRY_GIT_SSH_PROXY_PROTOCOL_CIDRS", &c.Git.SSHProxyProtocolCIDRs)
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
	str("AGENTRY_KNOWLEDGE_SEALING_KEY", &c.Knowledge.SealingKey)
	str("AGENTRY_JUDGE_PROVIDER", &c.Judge.Provider)
	str("AGENTRY_JUDGE_MODEL", &c.Judge.Model)
	str("AGENTRY_JUDGE_REGION", &c.Judge.Region)
	str("AGENTRY_JUDGE_BASE_URL", &c.Judge.BaseURL)
	str("AGENTRY_JUDGE_API_KEY", &c.Judge.APIKey)
	// AGENTRY_JUDGE_TYPE is the plain spelling for "which wire protocol";
	// when set it wins over AGENTRY_JUDGE_PROVIDER.
	str("AGENTRY_JUDGE_TYPE", &c.Judge.Provider)
	str("AGENTRY_WEB_SEARCH_PROVIDER", &c.WebSearch.Provider)
	str("AGENTRY_WEB_SEARCH_BASE_URL", &c.WebSearch.BaseURL)
	str("AGENTRY_WEB_SEARCH_API_KEY", &c.WebSearch.APIKey)
	// External scanner tools.
	str("AGENTRY_SCAN_GITLEAKS_BIN", &c.Scan.GitleaksBin)
	str("AGENTRY_SCAN_OSV_URL", &c.Scan.OSVURL)
	str("AGENTRY_SCAN_NPM_REGISTRY", &c.Scan.NPMRegistryURL)
	str("AGENTRY_SCAN_PYPI_URL", &c.Scan.PyPIURL)
	if v := os.Getenv("AGENTRY_SCAN_TOOL_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			c.Scan.ToolTimeout = d
		}
	}

	// Social login. Listed one variable per field on purpose: the
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
	str("AGENTRY_AUTH_OIDC_ID", &c.Auth.OIDC.ID)
	str("AGENTRY_AUTH_OIDC_ISSUER", &c.Auth.OIDC.Issuer)
	str("AGENTRY_AUTH_OIDC_CLIENT_ID", &c.Auth.OIDC.ClientID)
	str("AGENTRY_AUTH_OIDC_CLIENT_SECRET", &c.Auth.OIDC.ClientSecret)
	list("AGENTRY_AUTH_OIDC_SCOPES", &c.Auth.OIDC.Scopes)
	str("AGENTRY_AUTH_OIDC_DISPLAY_NAME", &c.Auth.OIDC.DisplayName)
	str("AGENTRY_IDP_ADMIN_URL", &c.Auth.IdPAdminURL)
	str("AGENTRY_IDP_ADMIN_TOKEN", &c.Auth.IdPAdminToken)
	str("AGENTRY_IDP_TRUST_CHECK_TOKEN", &c.Auth.IdPTrustCheckToken)
	str("AGENTRY_AUTH_DIRECTORY_COOKIE_DOMAIN", &c.Auth.DirectoryCookieDomain)
	str("AGENTRY_STAFF_ORG", &c.Auth.StaffOrg)
	str("AGENTRY_STAFF_DOMAIN", &c.Auth.StaffDomain)
	str("AGENTRY_IDP_STAFF_GROUP", &c.Auth.IdPStaffGroup)
	str("AGENTRY_IDP_STAFF_MIRROR_GROUP", &c.Auth.IdPStaffMirrorGroup)
	str("AGENTRY_IDP_STAFF_DOMAIN", &c.Auth.IdPStaffDomain)
	if err := boolean("AGENTRY_AUTH_REQUIRE_IDP_MFA", &c.Auth.RequireIdPMFA); err != nil {
		return err
	}

	// Audit stream + retention.
	str("AGENTRY_AUDIT_STREAM_KIND", &c.Audit.StreamKind)
	str("AGENTRY_AUDIT_STREAM_DIR", &c.Audit.StreamDir)
	str("AGENTRY_AUDIT_STREAM_S3_BUCKET", &c.Audit.StreamS3Bucket)
	if err := dur("AGENTRY_AUDIT_STREAM_FLUSH", &c.Audit.StreamFlush); err != nil {
		return err
	}
	if err := integer("AGENTRY_AUDIT_RETENTION_DAYS", &c.Audit.RetentionDays); err != nil {
		return err
	}
	// The organization lifecycle.
	if err := dur("AGENTRY_ORGS_DECOMMISSION_HOLD", &c.Orgs.DecommissionHold); err != nil {
		return err
	}
	if err := dur("AGENTRY_ORGS_PENDING_DIGEST_EVERY", &c.Orgs.PendingDigestEvery); err != nil {
		return err
	}
	// Red-team job.
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
	if err := dur("AGENTRY_AUTH_TRUSTED_DEVICE_TTL", &c.Auth.TrustedDeviceTTL); err != nil {
		return err
	}

	// Telemetry.
	str("AGENTRY_MIN_CLI_VERSION", &c.MinCLIVersion)
	str("AGENTRY_OTEL_ENDPOINT", &c.Telemetry.OTLPEndpoint)
	if err := dur("AGENTRY_OTEL_EXPORT_INTERVAL", &c.Telemetry.ExportInterval); err != nil {
		return err
	}
	if err := dur("AGENTRY_METRICS_QUEUE_SAMPLE_INTERVAL", &c.Telemetry.QueueSampleInterval); err != nil {
		return err
	}
	if err := boolean("AGENTRY_PROXY_REQUEST_ID", &c.HTTP.ProxyRequestID); err != nil {
		return err
	}
	if err := integer("AGENTRY_TRUSTED_PROXIES", &c.HTTP.TrustedProxies); err != nil {
		return err
	}
	list("AGENTRY_TRUSTED_PROXY_CIDRS", &c.HTTP.TrustedProxyCIDRs)

	// Notifications.
	str("AGENTRY_NOTIFY_KIND", &c.Notify.Kind)
	str("AGENTRY_SMTP_HOST", &c.SMTP.Host)
	str("AGENTRY_QUEUE_DRIVER", &c.Queue.Driver)
	if err := integer("AGENTRY_QUEUE_WORKERS", &c.Queue.Workers); err != nil {
		return err
	}
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

	// Quotas. Exposed as env so a self-host operator can raise them
	// without a config file; the entitlements Resolver is what reads them.
	for _, m := range []struct {
		key string
		dst *int
	}{
		{"AGENTRY_LIMITS_AUTHED_PER_HOUR", &c.Limits.AuthedPerHour},
		{"AGENTRY_LIMITS_AUTHED_BURST_PER_MIN", &c.Limits.AuthedBurstPerMin},
		{"AGENTRY_LIMITS_ANONYMOUS_PER_MIN", &c.Limits.AnonymousPerMin},
		{"AGENTRY_LIMITS_LOGIN_PER_MIN", &c.Limits.LoginPerMin},
		{"AGENTRY_LIMITS_SCIM_PER_MIN", &c.Limits.SCIMPerMin},
		{"AGENTRY_LIMITS_MODEL_INPUT_PER_MIN", &c.Limits.ModelInputPerMin},
		{"AGENTRY_LIMITS_GIT_PUSHES_PER_HOUR", &c.Limits.GitPushesPerHour},
		{"AGENTRY_LIMITS_SSH_KEY_OFFERS_PER_MIN", &c.Limits.SSHKeyOffersPerMin},
		{"AGENTRY_LIMITS_GIT_CONCURRENT_PER_IP", &c.Limits.GitConcurrentPerIP},
		{"AGENTRY_LIMITS_REPO_WARN_BYTES", &c.Limits.RepoWarnBytes},
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
		{"AGENTRY_LIMITS_ARCHIVE_MAX_TEXT_BYTES", &c.Limits.ArchiveMaxTextBytes},
		{"AGENTRY_KNOWLEDGE_BYTES_PER_ACCOUNT", &c.Limits.KnowledgeBytesPerAccount},
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

// staffOrgRE is a lower-case handle as an organization's is written.
var staffOrgRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,37}[a-z0-9])?$`)

// RetiredStaffKeys names the retired staff keys this configuration still
// sets, for the start-up warning: they grant nothing now.
func (c *Config) RetiredStaffKeys() []string {
	var out []string
	if c.Auth.IdPStaffGroup != "" {
		out = append(out, "auth.idpStaffGroup (AGENTRY_IDP_STAFF_GROUP)")
	}
	if c.Auth.IdPStaffDomain != "" {
		out = append(out, "auth.idpStaffDomain (AGENTRY_IDP_STAFF_DOMAIN)")
	}
	return out
}

// staffDomainRE is a bare lower-case DNS name of at least two labels.
var staffDomainRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

// Validate rejects configurations that must never run.
func (c Config) Validate() error {
	switch c.Env {
	case "dev", "staging", "prod":
	default:
		return fmt.Errorf("config: env must be dev|staging|prod, got %q", c.Env)
	}
	switch c.Queue.Driver {
	case "", "river":
	case "pg":
		return fmt.Errorf("config: queue.driver pg was removed with its jobs table; use river, the default")
	default:
		return fmt.Errorf("config: queue.driver must be river, got %q", c.Queue.Driver)
	}
	if c.Queue.Workers < 1 {
		return fmt.Errorf("config: queue.workers must be at least 1, got %d", c.Queue.Workers)
	}
	if c.DevMode && c.Env != "dev" {
		return fmt.Errorf("config: devMode is allowed only with env: dev (got env %q)", c.Env)
	}
	if (c.Auth.StaffOrg == "") != (c.Auth.StaffDomain == "") {
		// Half a rule is no rule: an organization with no domain would admit
		// anyone, and a domain with no organization names nobody.
		return fmt.Errorf("config: auth.staffOrg and auth.staffDomain are set together or not at all (got %q and %q)", c.Auth.StaffOrg, c.Auth.StaffDomain)
	}
	if g := c.Auth.IdPStaffMirrorGroup; g != "" {
		// The mirror is written through the directory's admin API and filled
		// from the staff organization: without either it would be a group
		// nobody keeps, which an application would still read as staff.
		if c.Auth.IdPAdminURL == "" || c.Auth.IdPAdminToken == "" {
			return fmt.Errorf("config: auth.idpStaffMirrorGroup needs auth.idpAdminURL and auth.idpAdminToken, which the registry writes the group through")
		}
		if c.Auth.StaffOrg == "" {
			return fmt.Errorf("config: auth.idpStaffMirrorGroup needs auth.staffOrg and auth.staffDomain: the group mirrors the staff organization's platform staff")
		}
		if g == c.Auth.IdPStaffGroup {
			return fmt.Errorf("config: auth.idpStaffMirrorGroup must not be the retired auth.idpStaffGroup (%q): that group was a source of staff, the mirror is written by the registry", g)
		}
	}
	if err := c.validateSignInOIDC(); err != nil {
		return err
	}
	if c.Auth.IdPTrustCheckToken != "" {
		// Remembered browsers on the directory path: refused
		// here rather than discovered at the first sign-in, where a cookie
		// the directory never receives would look like a feature that
		// silently does nothing.
		if len(c.Auth.IdPTrustCheckToken) < 32 {
			return fmt.Errorf("config: auth.idpTrustCheckToken must be at least 32 characters (got %d)", len(c.Auth.IdPTrustCheckToken))
		}
		if _, err := c.DirectoryTrustCookieDomain(); err != nil {
			return err
		}
	}
	if o := c.Auth.StaffOrg; o != "" && !staffOrgRE.MatchString(o) {
		return fmt.Errorf("config: auth.staffOrg must be an organization handle like agentry, got %q", o)
	}
	if d := c.Auth.StaffDomain; d != "" && !staffDomainRE.MatchString(d) {
		// A domain that could never match an address (an @, a leading dot, a
		// capital) would switch the rule off silently; refuse it at start-up.
		return fmt.Errorf("config: auth.staffDomain must be a bare lower-case domain like example.com, got %q", d)
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
	if err := c.validateKnowledge(); err != nil {
		return err
	}
	switch c.Judge.Provider {
	case "", "none", "static", "openai", "anthropic", "bedrock", "typesafe", "classifier":
	default:
		return fmt.Errorf("config: judge.provider must be none|static|openai|anthropic|bedrock|typesafe|classifier, got %q", c.Judge.Provider)
	}
	switch c.Judge.Provider {
	case "openai", "anthropic":
		if c.Judge.BaseURL == "" || c.Judge.APIKey == "" {
			return fmt.Errorf("config: judge.baseUrl and judge.apiKey are required when judge.provider is %q", c.Judge.Provider)
		}
	case "typesafe":
		// The key is the deployment fact this package can check. The model
		// id must be a pinned version; that rule
		// lives with the provider (scan.PinnedJudgeModel), and the factory
		// refuses an alias at startup.
		if c.Judge.APIKey == "" {
			return fmt.Errorf("config: judge.apiKey is required when judge.provider is %q", c.Judge.Provider)
		}
	case "classifier":
		if c.Judge.BaseURL == "" {
			return fmt.Errorf("config: judge.baseUrl (the classify endpoint) is required when judge.provider is %q", c.Judge.Provider)
		}
	}
	// The names are pkg/websearch's own list, so a provider added there is
	// accepted here without a second switch.
	if !websearch.Known(c.WebSearch.Provider) {
		return fmt.Errorf("config: webSearch.provider must be %s, got %q", strings.Join(websearch.Providers(), "|"), c.WebSearch.Provider)
	}
	if p := c.WebSearch.Provider; p != "" && p != "none" && c.WebSearch.APIKey == "" {
		return fmt.Errorf("config: webSearch.apiKey is required when webSearch.provider is %q", p)
	}
	switch c.Audit.StreamKind {
	case "", "none", "file", "log", "s3":
	default:
		return fmt.Errorf("config: audit.streamKind must be none|file|log|s3, got %q", c.Audit.StreamKind)
	}
	if c.Audit.StreamKind == "file" && c.Audit.StreamDir == "" {
		return fmt.Errorf("config: audit.streamDir is required when audit.streamKind is file")
	}
	if c.Audit.RetentionDays < 0 {
		return fmt.Errorf("config: audit.retentionDays must be >= 0")
	}
	if c.Orgs.DecommissionHold < 0 {
		return fmt.Errorf("config: orgs.decommissionHold must be >= 0")
	}
	if c.Orgs.PendingDigestEvery < 0 {
		return fmt.Errorf("config: orgs.pendingDigestEvery must be >= 0")
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
	if c.HTTP.ProxyRequestID && c.HTTP.TrustedProxies < 1 {
		return fmt.Errorf("config: http.proxyRequestID needs http.trustedProxies >= 1 (a hop that sets the header must exist)")
	}
	if c.HTTP.TrustedProxies < 0 {
		return fmt.Errorf("config: http.trustedProxies must be >= 0")
	}
	if _, err := ParseCIDRs(c.HTTP.TrustedProxyCIDRs); err != nil {
		return fmt.Errorf("config: http.trustedProxyCIDRs: %w", err)
	}
	if _, err := ParseCIDRs(c.Git.SSHProxyProtocolCIDRs); err != nil {
		return fmt.Errorf("config: git.sshProxyProtocolCIDRs: %w", err)
	}
	return c.validateLimits()
}

// TTL ceilings. These are hard product limits, not tunables: a deployment
// that raised them would still be an Agentry deployment by name while quietly
// issuing credentials the threat model never priced in.
const (
	// MaxSessionTTL — sessions are capped at 24 h absolute.
	MaxSessionTTL = 24 * time.Hour
	// MaxPATTTL — max token lifetime 1 year.
	MaxPATTTL = 365 * 24 * time.Hour
	// MaxPATOrgBoundTTL — 90 days if org-bound under enforced SSO.
	MaxPATOrgBoundTTL = 90 * 24 * time.Hour
	// MaxTrustedDeviceTTL bounds how long a remembered browser skips the
	// second factor. It exceeds MaxSessionTTL by design and is the second
	// browser credential class: PATs (1y) and org-bound PATs (90d) already
	// exceed the session cap the same way. What keeps this honest is that the
	// credential is narrow — it skips one factor on one sign-in path, mints
	// only after that factor was actually answered, expires absolutely
	// rather than sliding, and grants no session and no scope of its own.
	MaxTrustedDeviceTTL = 30 * 24 * time.Hour
	// MaxSSOMaxAge bounds the enforced-SSO freshness window. 8 h is
	// the DEFAULT and the value is org-configurable, so the ceiling is
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
		{"auth.trustedDeviceTTL", c.Auth.TrustedDeviceTTL, MaxTrustedDeviceTTL},
	} {
		if b.value <= 0 {
			return fmt.Errorf("config: %s must be > 0", b.name)
		}
		if b.value > b.max {
			return fmt.Errorf("config: %s is %s; the maximum is %s", b.name, b.value, b.max)
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

// validateKnowledge refuses a knowledge sealing key that is not 32 bytes of
// base64, or that is the auth sealing key: a key of its own, so that what
// opens the TOTP seeds does not also open every pack, and a negative cap.
func (c Config) validateKnowledge() error {
	if c.Limits.KnowledgeBytesPerAccount < 0 {
		return fmt.Errorf("config: limits.knowledgeBytesPerAccount must be >= 0 (0 is no cap)")
	}
	if c.Knowledge.SealingKey == "" {
		return nil
	}
	k, err := base64.StdEncoding.DecodeString(c.Knowledge.SealingKey)
	if err != nil || len(k) != 32 {
		return fmt.Errorf("config: knowledge.sealingKey must be 32 bytes, base64")
	}
	if a, err := base64.StdEncoding.DecodeString(c.Auth.SealingKey); err == nil && bytes.Equal(a, k) {
		return fmt.Errorf("config: knowledge.sealingKey must not be the auth sealing key")
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
		{"limits.scimPerMin", int64(c.Limits.SCIMPerMin)},
		{"limits.modelInputPerMin", int64(c.Limits.ModelInputPerMin)},
		{"limits.repoQuotaBytes", int64(c.Limits.RepoQuotaBytes)},
		{"limits.repoWarnBytes", int64(c.Limits.RepoWarnBytes)},
		{"limits.repoMaxBlobBytes", int64(c.Limits.RepoMaxBlobBytes)},
		{"limits.gitPushesPerHour", int64(c.Limits.GitPushesPerHour)},
		{"limits.sshKeyOffersPerMin", int64(c.Limits.SSHKeyOffersPerMin)},
		{"limits.gitConcurrentPerIP", int64(c.Limits.GitConcurrentPerIP)},
		{"limits.agentsPerUserNamespace", int64(c.Limits.AgentsPerUserNamespace)},
		{"limits.agentsPerOrgNamespace", int64(c.Limits.AgentsPerOrgNamespace)},
		{"limits.versionsPerDay", int64(c.Limits.VersionsPerDay)},
		{"limits.webhookEndpointsPerOrg", int64(c.Limits.WebhookEndpointsPerOrg)},
		{"limits.webhookDeliveriesPerSecond", int64(c.Limits.WebhookDeliveriesPerSecond)},
		{"limits.archiveMaxBytes", c.Limits.ArchiveMaxBytes},
		{"limits.archiveMaxFiles", int64(c.Limits.ArchiveMaxFiles)},
		{"limits.archiveMaxFileBytes", c.Limits.ArchiveMaxFileBytes},
		{"limits.archiveMaxImageFileBytes", c.Limits.ArchiveMaxImageFileBytes},
		{"limits.archiveMaxTextBytes", c.Limits.ArchiveMaxTextBytes},
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

// ParseCIDRs parses a list of address ranges naming trusted proxies. Each
// entry is a CIDR ("10.0.0.0/8") or a bare address, which means that one
// address. A prefix with host bits set ("10.0.0.5/8") is refused rather than
// silently widened or narrowed: a typo in a trust list should fail loudly.
func ParseCIDRs(list []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(list))
	for _, s := range list {
		s = strings.TrimSpace(s)
		if !strings.Contains(s, "/") {
			a, err := netip.ParseAddr(s)
			if err != nil || a.Zone() != "" {
				return nil, fmt.Errorf("%q is neither a CIDR nor an address", s)
			}
			a = a.Unmap()
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
			continue
		}
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("%q is not a CIDR", s)
		}
		if p.Addr().Is4In6() {
			return nil, fmt.Errorf("%q is an IPv4-mapped range; write the IPv4 CIDR", s)
		}
		if p.Masked() != p {
			return nil, fmt.Errorf("%q has host bits set (did you mean %s?)", s, p.Masked())
		}
		out = append(out, p)
	}
	return out, nil
}

// InCIDRs reports whether addr falls in one of the ranges. An IPv4 address
// seen in its IPv6-mapped form (a dual-stack listener) matches its IPv4
// range.
func InCIDRs(prefixes []netip.Prefix, addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// validateSignInOIDC refuses a sign-in provider that would be ambiguous or
// unreachable: named twice (auth.oidc beside social.authentik),
// under an id its routes do not serve, or configured without an issuer.
func (c Config) validateSignInOIDC() error {
	p := c.Auth.OIDC
	if p.ID != "" && p.ID != OIDCProviderID && p.ID != DirectoryProviderID {
		return fmt.Errorf("config: auth.oidc.id must be %q or %q, got %q", OIDCProviderID, DirectoryProviderID, p.ID)
	}
	if !p.Configured() {
		return nil
	}
	if c.Social.Authentik.Configured() {
		return fmt.Errorf("config: auth.oidc and social.authentik both name the sign-in provider; keep one (auth.oidc with id %q keeps social.authentik's accounts linked)", DirectoryProviderID)
	}
	if strings.TrimSpace(p.Issuer) == "" {
		return fmt.Errorf("config: auth.oidc needs an issuer: the registry discovers the provider's endpoints from it")
	}
	return nil
}
