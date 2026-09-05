// Package api is the HTTP layer (§2.1 L2/L3 seam): generated OpenAPI server
// stubs, middleware, health endpoints, and well-known documents. Route
// authorization declarations live in authz_routes.go per §12.2.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/auth"
	samlsp "github.com/blaktron/agentry/internal/auth/saml"
	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/dnsx"
	"github.com/blaktron/agentry/internal/entitlements"
	"github.com/blaktron/agentry/internal/metrics"
	"github.com/blaktron/agentry/internal/notify"
	"github.com/blaktron/agentry/internal/queue"
	"github.com/blaktron/agentry/internal/ratelimit"
	"github.com/blaktron/agentry/internal/registry"
	"github.com/blaktron/agentry/internal/render"
	"github.com/blaktron/agentry/internal/scan"
	"github.com/blaktron/agentry/internal/store"
	storegen "github.com/blaktron/agentry/internal/store/gen"
	"github.com/blaktron/agentry/internal/version"
	"github.com/blaktron/agentry/internal/webhook"
	"github.com/blaktron/agentry/pkg/ruleset"
)

// Server implements the generated ServerInterface plus non-spec endpoints
// (health, well-known). It is assembled once per process by NewHandler.
type Server struct {
	cfg      config.Config
	st       *store.Store // nil when running without a database (limited dev mode)
	log      *slog.Logger
	auditW   *audit.Writer
	notifier notify.Notifier
	// dirEraser deletes the sign-in account in the directory service on
	// erasure (agentry#20); nil when auth.idpAdminURL is unset.
	dirEraser directoryEraser
	sealer    *auth.Sealer
	signer    scan.Signer
	limits    *ratelimit.Buckets
	classes   limitClasses
	reg       *registry.Service
	blobs     registry.BlobStore
	pipeline  *scan.Pipeline
	renderer  *render.Renderer
	// Enterprise (M6/WG-J): webhook fan-out, DNS resolver for domain
	// verification, and the shared SAML assertion replay cache.
	webhooks   *webhook.Dispatcher
	resolver   dnsx.Resolver
	samlReplay samlsp.ReplayCache
	// jobs is the enqueue-side queue client (webhook deliveries, audit
	// exports). The worker role drains it; nil without a database.
	jobs queue.Client
	// ents resolves the §19 quotas (§14.2 seam).
	ents entitlements.Resolver
	// mx is the §16.2 instrument set; nil is a working no-op.
	mx *metrics.Metrics
	// oidcHTTPClient, when set, is the HTTP client OIDC discovery/JWKS/token
	// calls use (tests point it at an httptest IdP). nil = default client.
	oidcHTTPClient *http.Client
	// imgHTTPClient overrides the image proxy's guarded client (tests).
	imgHTTPClient *http.Client
}

// New creates the API server. st may be nil in database-less dev mode; any
// handler that needs the store fails closed with 503 in that case.
func New(cfg config.Config, st *store.Store, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	sealer, serr := auth.NewSealer(cfg.Auth.SealingKey, cfg.DevMode)
	if serr != nil {
		// Config validation already enforces key presence outside dev; an
		// invalid key value is a hard startup error surfaced by panicking
		// here during construction (never mid-request).
		panic(serr)
	}
	aud := audit.NewWriter(log)
	// §12.6 continuous NDJSON archive (see internal/audit/stream.go).
	auditStream := audit.NewStream(cfg.Audit.StreamKind, cfg.Audit.StreamDir,
		cfg.Audit.StreamS3Bucket, cfg.Audit.StreamFlush, log)
	aud.SetStream(auditStream)
	notifier, nerr := notify.New(notify.Options{
		Kind:     cfg.Notify.Kind,
		BaseURL:  cfg.BaseURL,
		SMTP:     smtpOptions(cfg),
		Log:      log,
		Registry: registryDisplayName(cfg),
	})
	if nerr != nil {
		panic(nerr) // startup-time config failure, never mid-request
	}
	srv := &Server{
		cfg:      cfg,
		st:       st,
		log:      log,
		auditW:   aud,
		notifier: notifier,
		sealer:   sealer,
		renderer: render.New(),
		limits:   ratelimit.New(ratelimit.DefaultIdleTTL),
		classes:  classesFromConfig(cfg.Limits),
		ents:     entitlements.NewConfigResolver(cfg.Limits),
	}
	if fs, ok := auditStream.(*audit.FileStream); ok {
		// A dropped archive record is a deliberate fail-open (DEV-020);
		// count it so the choice stays visible (agentry#33). Metrics are
		// attached later via SetMetrics; RecordFailOpen is nil-safe.
		fs.OnDrop = func() { srv.mx.RecordFailOpen(context.Background(), metrics.FailOpenAuditStreamDrop) }
	}
	// Enterprise defaults, set regardless of database presence (§12.4, §9.3).
	srv.resolver = dnsx.NewSystemResolver()
	srv.samlReplay = samlsp.NewMemoryReplayCache()
	if st != nil {
		srv.reg = registry.NewService(st, aud)
		// Webhook fan-out (§9.3): enqueue deliveries onto the Postgres queue;
		// the worker role runs the delivery handler. Wired before the blobs
		// early-return so the event sink is always active.
		srv.jobs = queue.NewPGClient(st, log)
		srv.webhooks = webhook.NewDispatcher(webhook.Deps{
			Store: st, Sealer: sealer, Queue: srv.jobs, Log: log,
			DeliveriesPerSecond: float64(cfg.Limits.WebhookDeliveriesPerSecond),
		})
		srv.reg.SetEventSink(srv.emitAgentEvent)
		srv.reg.SetEntitlements(srv.ents)
		// Archive storage. Both kinds are wired here, so the pipeline below is
		// assembled identically either way — the s3 kind used to fall through
		// with a nil store and take the whole scan pipeline down with it,
		// which meant the shipped SaaS default could not scan anything.
		blobs, berr := newBlobStore(cfg)
		if berr != nil {
			panic(berr) // startup-time config failure, never mid-request
		}
		srv.blobs = blobs
		srv.reg.SetBlobStore(blobs)
		// M4 security pipeline (§8): the orchestrator + gate replace the M3
		// dev stub. Ruleset embedded (§8.3); judge + signer per config.
		bundle, err := ruleset.Load()
		if err != nil {
			panic(err)
		}
		// Startup-fatal on purpose: the previous code kept a locally generated
		// uuid when registration failed, and that uuid names no
		// ruleset_releases row — so every CreateScanRun afterwards failed its
		// foreign key, silently, until someone restarted the process.
		rulesetReg, rerr := scan.RegisterRuleset(context.Background(), st, bundle)
		if rerr != nil {
			panic(rerr)
		}
		judge, jerr := scan.BuildJudgeProvider(context.Background(), scan.JudgeConfig{
			Provider: judgeProviderName(cfg),
			Model:    cfg.Judge.Model,
			BaseURL:  cfg.Judge.BaseURL,
			APIKey:   cfg.Judge.APIKey,
			Region:   cfg.Judge.Region,
		})
		if jerr != nil {
			panic(jerr)
		}
		signer, serr := scan.NewSigner(context.Background(), scan.SignerOptions{
			Kind:      cfg.Signing.Kind,
			KeyFile:   cfg.Signing.KeyFile,
			KMSKeyARN: cfg.Signing.KMSKeyARN,
			KMSRegion: cfg.Signing.KMSRegion,
			DevMode:   cfg.DevMode,
		})
		if serr != nil {
			panic(serr)
		}
		srv.signer = signer
		orch := scan.NewOrchestrator(bundle, judge, log)
		tools, terr := externalScanTools(cfg.Scan, log)
		if terr != nil {
			panic(terr)
		}
		orch.SetExternalTools(tools)
		srv.pipeline = scan.NewPipeline(scan.PipelineDeps{
			Store: st, Registry: srv.reg, Blobs: srv.blobs, Orchestrator: orch,
			Signer: signer, Audit: aud, Notifier: srv.notifier, Log: log,
			RegistryURL: cfg.BaseURL,
			RulesetID:   rulesetReg.ID, RulesetVer: rulesetReg.Semver,
		})
		srv.reg.SetPipeline(srv.pipeline)
		// §8.6 knobs that reject at submission time, and the §12.1/§19
		// 2FA-before-public-publish gate. Both sit on the registry so the
		// git-tag auto-publish path is covered as well as the API.
		srv.reg.SetPolicyGate(srv.pipeline)
		srv.reg.SetPublicPublish2FA(publicPublish2FAEnabled(cfg))
		srv.reg.SetIPClusterSecret(ipClusterSecret(cfg))
		// README images route through the same-origin proxy (agentry#64);
		// the renderer needs the server's signing key, so it is built here.
		srv.renderer = render.NewWithOptions(render.Options{ImageProxy: srv.imageProxyURL})
		if cfg.Auth.IdPAdminURL != "" && cfg.Auth.IdPAdminToken != "" {
			srv.dirEraser = newAuthentikEraser(cfg.Auth.IdPAdminURL, cfg.Auth.IdPAdminToken)
		}
		srv.reg.SetLogger(log)
		// A ruleset semver we have never seen means the catalogue was judged
		// by older rules (§8.7).
		scan.EnqueueRescanSweepOnNewRuleset(context.Background(), srv.jobs, log, rulesetReg)
	}
	return srv
}

// Close releases the resources the server owns outside the request path: the
// rate-limit bucket store's collector goroutine, and the metric exporters.
// Without it every server built in a process (tests especially) leaks a
// goroutine holding every bucket it ever created.
func (s *Server) Close() error {
	var errs []error
	errs = append(errs, s.limits.Close())
	if s.mx != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		errs = append(errs, s.mx.Shutdown(ctx))
	}
	return errors.Join(errs...)
}

// newBlobStore builds the configured archive store (§13.4: local FS for
// self-host and dev, S3 on SaaS).
func newBlobStore(cfg config.Config) (registry.BlobStore, error) {
	switch cfg.Storage.Kind {
	case "s3":
		return registry.NewS3(context.Background(), registry.S3Options{
			Bucket:       cfg.Storage.S3Bucket,
			Region:       cfg.Storage.S3Region,
			Prefix:       cfg.Storage.S3Prefix,
			Endpoint:     cfg.Storage.S3Endpoint,
			UsePathStyle: cfg.Storage.S3UsePathStyle,
		})
	default:
		return registry.NewLocalFS(cfg.Storage.LocalDir)
	}
}

// smtpOptions maps the config block onto the notifier's options.
func smtpOptions(cfg config.Config) notify.SMTPOptions {
	return notify.SMTPOptions{
		Host:     cfg.SMTP.Host,
		Port:     cfg.SMTP.Port,
		Username: cfg.SMTP.Username,
		Password: cfg.SMTP.Password,
		From:     cfg.SMTP.From,
		StartTLS: cfg.SMTP.StartTLS,
		Timeout:  cfg.SMTP.Timeout,
	}
}

// registryDisplayName is what notification bodies call this deployment. The
// public origin's host is the name users already know it by; "Agentry" is the
// fallback for a deployment that has not set one.
func registryDisplayName(cfg config.Config) string {
	if cfg.BaseURL == "" {
		return "Agentry"
	}
	if u, err := url.Parse(cfg.BaseURL); err == nil && u.Host != "" {
		return u.Host
	}
	return cfg.BaseURL
}

// entitlements returns the §14.2 resolver, defaulting to the shipped §19
// limits so a partially wired server still enforces quotas.
func (s *Server) entitlements() entitlements.Resolver {
	if s.ents == nil {
		return entitlements.Default()
	}
	return s.ents
}

// SetEntitlements swaps the quota resolver (the SaaS overlay, and tests).
func (s *Server) SetEntitlements(r entitlements.Resolver) {
	s.ents = r
	if s.reg != nil {
		s.reg.SetEntitlements(r)
	}
}

// SetMetrics wires the §16.2 instrument set. nil leaves every record a no-op.
func (s *Server) SetMetrics(m *metrics.Metrics) {
	s.mx = m
	if s.pipeline != nil {
		s.pipeline.SetMetrics(m)
	}
	if s.webhooks != nil {
		s.webhooks.SetMetrics(m)
	}
}

// Metrics returns the wired instrument set (nil-safe for callers).
func (s *Server) Metrics() *metrics.Metrics { return s.mx }

// Notifier exposes the configured notifier so other roles share one instance.
func (s *Server) Notifier() notify.Notifier { return s.notifier }

// SetNotifier overrides the notifier (tests).
func (s *Server) SetNotifier(n notify.Notifier) {
	s.notifier = n
	if s.pipeline != nil {
		s.pipeline.SetNotifier(n)
	}
}

// Pipeline exposes the assembled security pipeline so the worker role runs
// exactly the object the api role wires — including its registry event sink,
// without which rescan-driven agent.quarantined webhooks went nowhere.
// nil when this server has no archive store (see New).
func (s *Server) Pipeline() *scan.Pipeline { return s.pipeline }

// Reg exposes the registry service so role wiring can share one instance
// (git role injects its archiver; auto-publish uses the same pipeline).
func (s *Server) Reg() *registry.Service { return s.reg }

// SetResolver overrides the DNS resolver (domain verification; tests inject a
// fake resolver, §12.4).
func (s *Server) SetResolver(r dnsx.Resolver) { s.resolver = r }

// SetWebhookDispatcher overrides the webhook dispatcher (tests inject a
// loopback-allowing delivery client). The registry event sink already points
// at s.emitAgentEvent, which reads s.webhooks at call time.
func (s *Server) SetWebhookDispatcher(d *webhook.Dispatcher) { s.webhooks = d }

// SetOIDCHTTPClient overrides the HTTP client used for OIDC discovery/JWKS/
// token calls (tests point it at an in-process IdP).
func (s *Server) SetOIDCHTTPClient(c *http.Client) { s.oidcHTTPClient = c }

// SetImageProxyClient overrides the guarded client the README image proxy
// fetches with (tests point it at an in-process server).
func (s *Server) SetImageProxyClient(c *http.Client) { s.imgHTTPClient = c }

// RegisterQueueHandlers wires this server's async job handlers onto a queue
// worker (the worker role, and tests): webhook delivery (§9.3) and audit
// export (§12.6).
func (s *Server) RegisterQueueHandlers(q queue.Client) {
	if s.webhooks != nil {
		s.webhooks.RegisterHandlers(q)
	}
	q.Register(jobAuditExport, s.runAuditExport)
	s.registerAuditRetention(q) // §4.3 hot-table retention (audit_retention.go)
	s.registerRedTeam(q)        // §17.5 report-only red-team job (handlers_redteam.go)
}

// emitAgentEvent is the registry event sink (§9.3): it resolves the agent's
// owning org and fans the transition out to that org's webhooks. Personal
// namespaces (no org) and fan-out errors are swallowed — webhooks never affect
// the state change that triggered them.
func (s *Server) emitAgentEvent(ctx context.Context, agentID uuid.UUID, event string, payload map[string]any) {
	if s.webhooks == nil || s.st == nil {
		return
	}
	orgID, err := s.q().GetAgentOwnerOrg(ctx, agentID)
	if err != nil {
		return // personal namespace or agent gone
	}
	if err := s.webhooks.Emit(ctx, orgID, event, payload); err != nil {
		s.log.Error("webhook emit", "event", event, "err", err)
	}
}

// q returns the base query layer, or nil without a database.
func (s *Server) q() *storegen.Queries {
	if s.st == nil {
		return nil
	}
	return s.st.Queries()
}

// requireDB writes 503 and returns false when no database is configured.
func (s *Server) requireDB(w http.ResponseWriter, r *http.Request) bool {
	if s.st == nil {
		problemUnavailable(w, r, "database not configured")
		return false
	}
	return true
}

// GetMeta implements GET /api/v1/meta (§9.2): server version + feature flags.
func (s *Server) GetMeta(w http.ResponseWriter, r *http.Request) {
	features := map[string]bool{
		"redis":   s.cfg.Redis.URL != "",
		"signing": s.cfg.Signing.Kind != "none",
		"judge":   s.cfg.Judge.Provider != "none",
		"s3":      s.cfg.Storage.Kind == "s3",
		// externalOnly tells the web tier and clients that accounts live in
		// a directory service (DEV-057): the native credential surface is
		// gone, so do not offer password or TOTP forms (agentry#21).
		"externalOnly": s.cfg.Auth.ExternalOnly,
	}
	meta := Meta{
		Version:    version.Version,
		ApiVersion: "v1",
		Features:   features,
	}
	if s.cfg.MinCLIVersion != "" {
		meta.MinCLIVersion = &s.cfg.MinCLIVersion
	}
	writeJSON(w, http.StatusOK, meta)
}

// healthz is liveness (process up); readyz is readiness (dependencies).
func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	type dep struct {
		Name string `json:"name"`
		OK   bool   `json:"ok"`
	}
	deps := []dep{}
	ready := true
	if s.st != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		err := s.st.Ping(ctx)
		deps = append(deps, dep{Name: "postgres", OK: err == nil})
		if err != nil {
			ready = false
		}
	} else {
		deps = append(deps, dep{Name: "postgres", OK: false})
		ready = false
	}
	w.Header().Set("Content-Type", "application/json")
	if !ready {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"ready": ready, "deps": deps})
}

// wellKnownRegistry serves /.well-known/agentry/registry.json (§9.2):
// API root, version, feature discovery for CLIs pointed at this host.
func (s *Server) wellKnownRegistry(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"api":     "/api/v1",
		"version": version.Version,
		"git":     true,
	})
}

// wellKnownSigningKeys serves /.well-known/agentry/signing-keys.json (§8.8):
// the verification key set clients pin on first use (TOFU) and use to verify
// DSSE attestations offline. Rotation = overlapping validity windows.
func (s *Server) wellKnownSigningKeys(w http.ResponseWriter, r *http.Request) {
	out := struct {
		Keys []signingKey `json:"keys"`
	}{Keys: s.signingKeySet()}
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, out)
}

// signingKey is one entry in signing-keys.json. notBefore/notAfter are what
// make §8.8's "rotation = overlapping validity windows" representable: without
// them the document can only ever describe one key as current, and an operator
// rotating a key has no way to say "both of these are legitimate, here is
// when each applies". Omitted when unset, so an unbounded key is silent rather
// than claiming a window it does not have.
type signingKey struct {
	KeyID     string `json:"keyId"`
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"publicKeyPem"`
	NotBefore string `json:"notBefore,omitempty"`
	NotAfter  string `json:"notAfter,omitempty"`
}

const defaultSigningAlgorithm = "ecdsa-p256-sha256"

// signingKeySet assembles the published key set: the active signer first, then
// any verification-only keys the operator configured for an in-flight
// rotation. A key whose PEM cannot be read is dropped with a log line rather
// than failing the endpoint — serving the keys that ARE valid keeps existing
// clients verifying, where a 500 would break all of them at once.
func (s *Server) signingKeySet() []signingKey {
	keys := []signingKey{}
	if s.signer != nil {
		keys = append(keys, signingKey{
			KeyID:     s.signer.KeyID(),
			Algorithm: defaultSigningAlgorithm,
			PublicKey: s.signer.PublicKeyPEM(),
			NotBefore: s.cfg.Signing.NotBefore,
			NotAfter:  s.cfg.Signing.NotAfter,
		})
	}
	for _, k := range s.cfg.Signing.AdditionalKeys {
		pemText := k.PublicKeyPEM
		if pemText == "" && k.PublicKeyFile != "" {
			b, err := os.ReadFile(k.PublicKeyFile) //nolint:gosec // operator-configured path
			if err != nil {
				s.log.Error("signing keys: reading additional key", "keyId", k.KeyID, "err", err)
				continue
			}
			pemText = string(b)
		}
		if pemText == "" {
			continue
		}
		alg := k.Algorithm
		if alg == "" {
			alg = defaultSigningAlgorithm
		}
		keys = append(keys, signingKey{
			KeyID:     k.KeyID,
			Algorithm: alg,
			PublicKey: pemText,
			NotBefore: k.NotBefore,
			NotAfter:  k.NotAfter,
		})
	}
	return keys
}

// NewHandler assembles the full HTTP handler for the api role.
func NewHandler(s *Server) http.Handler {
	return NewHandlerWithGit(s, nil)
}

// NewHandlerWithGit additionally mounts git smart-HTTP routes on the same
// mux (the `all` role / self-host single binary). mountGit may be nil.
func NewHandlerWithGit(s *Server, mountGit func(*http.ServeMux)) http.Handler {
	mux := http.NewServeMux()
	if mountGit != nil {
		mountGit(mux)
	}

	mux.HandleFunc("GET /api/v1/img/{sig}/{ref}", s.serveImageProxy) // agentry#64
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("GET /readyz", s.readyz)
	mux.HandleFunc("GET /.well-known/agentry/registry.json", s.wellKnownRegistry)
	mux.HandleFunc("GET /.well-known/agentry/signing-keys.json", s.wellKnownSigningKeys)

	// Prometheus exposition (D-25). Mounted outside /api/v1 alongside the
	// health endpoints and, like them, unauthenticated: a scraper is
	// infrastructure, not a principal, and the RBAC chokepoint has no way to
	// express it. The numbers are operational (request rates, queue depth,
	// stage timings) and carry no user content, but they do describe traffic
	// shape — bind agentryd to a private interface, or keep /metrics off the
	// public listener at the proxy. docs/ops/deployment.md says so too.
	mux.Handle("GET /metrics", s.metricsHandler())

	// SCIM 2.0 data plane (§12.5). Mounted outside the generated /api/v1
	// handler: it uses its own base path, application/scim+json media type, and
	// authenticates by SCIM bearer token (not the RBAC chokepoint), so it is
	// deliberately not part of the OpenAPI surface (see handlers_scim.go).
	s.mountSCIM(mux)

	// Org SSO landing (§12.4 endpoint list): `https://…/sso/{org}` starts the
	// org's configured SAML/OIDC login. Root-mounted for the same reason as
	// SCIM — it is a browser destination, not part of the JSON API surface.
	s.mountSSOLanding(mux)

	// Generated OpenAPI routes under /api/v1 (spec-first, D-09).
	apiHandler := HandlerWithOptions(s, StdHTTPServerOptions{
		BaseURL:    "/api/v1",
		BaseRouter: mux,
		ErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			problemBadRequest(w, r, err.Error())
		},
		Middlewares: []MiddlewareFunc{s.principalMiddleware},
	})

	return withMiddleware(apiHandler, s.log, s.Metrics, s.cfg.HTTP.TrustedProxies)
}

// metricsHandler serves /metrics, reading s.mx at request time so
// SetMetrics can be called after the handler is built.
func (s *Server) metricsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mx.Handler().ServeHTTP(w, r)
	})
}

// judgeProviderName picks the judge provider: config value, or "static" in
// dev so the pipeline is exercisable without a live model (DEV-007).
func judgeProviderName(cfg config.Config) string {
	p := cfg.Judge.Provider
	if p == "" {
		p = "none"
	}
	if p == "none" && cfg.DevMode {
		return "static"
	}
	return p
}

// writeJSON writes a JSON 2xx response with no-store cache semantics (§9.1).
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// readJSON decodes a request body strictly (unknown fields rejected).
func readJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		problemBadRequest(w, r, "invalid JSON body: "+err.Error())
		return false
	}
	return true
}

// readJSONOptional decodes an optional request body; an empty body is not an
// error (used by endpoints whose requestBody is not required).
func readJSONOptional(r *http.Request, dst any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	if err := dec.Decode(dst); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	return nil
}

// ipClusterSecret derives the S8 IP-cluster hash key (agentry#27) from the
// sealing key — the one secret every deployment already has. Dev mode with
// no key uses a fixed value, like the sealer: the signal still works on a
// dev stack and the docs say it is not a secret there.
func ipClusterSecret(cfg config.Config) []byte {
	if cfg.Auth.SealingKey != "" {
		return []byte("ip-cluster:" + cfg.Auth.SealingKey)
	}
	if cfg.DevMode {
		return []byte("ip-cluster:dev-insecure")
	}
	return nil
}

// externalScanTools builds the §8.3 external-scanner set from config
// (agentry#40). A configured tool that cannot be resolved is a startup
// error: an operator who asked for gitleaks must not get silent native-only.
func externalScanTools(c config.Scan, log *slog.Logger) (scan.ExternalTools, error) {
	var t scan.ExternalTools
	gl, err := scan.ResolveExecTool("gitleaks", c.GitleaksBin, "", c.ToolTimeout)
	if err != nil {
		return t, err
	}
	if gl != nil {
		t.Gitleaks = gl
		log.Info("scan: gitleaks enabled", "bin", gl.Bin)
	}
	return t, nil
}
