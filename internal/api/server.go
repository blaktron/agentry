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
	"os"
	"strings"
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
	"github.com/blaktron/agentry/internal/ui"
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
	// paths is where this server sends browsers (a site in front of it, or
	// its own /ui/ pages — DEV-091).
	paths webPaths
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
	// ents resolves the §19 quotas (§14.2 seam); coreEnts is the
	// config-driven one, kept for an extension's resolver to wrap.
	ents     entitlements.Resolver
	coreEnts entitlements.Resolver
	// mx is the §16.2 instrument set; nil is a working no-op.
	mx *metrics.Metrics
	// oidcHTTPClient, when set, is the HTTP client OIDC discovery/JWKS/token
	// calls use (tests point it at an httptest IdP). nil = default client.
	oidcHTTPClient *http.Client
	// oidcGuard is the egress policy OIDC discovery, JWKS and token
	// requests obey when no oidcHTTPClient is injected: the production
	// guard, loopback allowed in dev mode so a local IdP works. An
	// organization's issuer is an address any org admin can name, so it is
	// fetched like a webhook, never with http.DefaultClient (security
	// review 2026-09-20 §5.8.1).
	oidcGuard  webhook.Guard
	oidcEgress *http.Client
	// imgHTTPClient overrides the image proxy's guarded client (tests).
	imgHTTPClient *http.Client
	// imgKey signs image-proxy URLs (newImgProxyKey).
	imgKey []byte
	// extensions and eventHooks are the closed build's additions (extensions.go).
	extensions []extensionMount
	eventHooks []func(ctx context.Context, ev Event)
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
	paths := newWebPaths(cfg)
	notifier, nerr := notify.New(notify.Options{
		Kind:     cfg.Notify.Kind,
		BaseURL:  cfg.BaseURL,
		SMTP:     smtpOptions(cfg),
		Log:      log,
		Registry: cfg.DisplayName(),
		Links:    notify.Links{Dashboard: paths.dashboardURL(), VerifyEmail: paths.verifyEmailURL, ReportCard: paths.reportCardURL, Settings: paths.settingsURL()},
	})
	if nerr != nil {
		panic(nerr) // startup-time config failure, never mid-request
	}
	srv := &Server{
		cfg:      cfg,
		paths:    paths,
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
	srv.coreEnts = srv.ents
	if fs, ok := auditStream.(*audit.FileStream); ok {
		// A dropped archive record is a deliberate fail-open (DEV-020);
		// count it so the choice stays visible (agentry#33). Metrics are
		// attached later via SetMetrics; RecordFailOpen is nil-safe.
		fs.OnDrop = func() { srv.mx.RecordFailOpen(context.Background(), metrics.FailOpenAuditStreamDrop) }
	}
	// Enterprise defaults, set regardless of database presence (§12.4, §9.3).
	srv.resolver = dnsx.NewSystemResolver()
	srv.samlReplay = samlsp.NewMemoryReplayCache()
	srv.SetOIDCEgressGuard(webhook.Guard{AllowLoopback: cfg.DevMode})
	srv.imgKey = newImgProxyKey(cfg.Auth.SealingKey)
	if st != nil {
		srv.reg = registry.NewService(st, aud)
		// Webhook fan-out (§9.3): enqueue deliveries onto the Postgres queue;
		// the worker role runs the delivery handler. Wired before the blobs
		// early-return so the event sink is always active.
		jobs, jerr := queue.Open(cfg.Queue.Driver, cfg.Queue.Workers, st, log)
		if jerr != nil {
			// Config.Validate rejects an unknown driver before New runs; a
			// hand-built config that skipped it gets the default and a log line.
			log.Error("queue: open", "driver", cfg.Queue.Driver, "err", jerr)
			jobs = queue.NewRiverClient(st, log)
		}
		srv.jobs = jobs
		srv.webhooks = webhook.NewDispatcher(webhook.Deps{
			Store: st, Sealer: sealer, Queue: srv.jobs, Log: log,
			DeliveriesPerSecond: float64(cfg.Limits.WebhookDeliveriesPerSecond),
		})
		srv.reg.SetEventSink(srv.emitAgentEvent)
		srv.reg.SetOrgEventSink(srv.emitOrgEvent)
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
		log.Info("scan: judge configured", "provider", judge.Name(), "model", judge.ModelID())
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
		// The signer's public key is recorded so a rotation orphans nothing
		// (§8.8, agentry#350): retired keys stay advertised, and a key some
		// attestation lacks triggers the re-attestation sweep once the
		// pipeline below exists to run it.
		keyReg, kerr := scan.RegisterSigningKey(context.Background(), st, signer)
		if kerr != nil {
			panic(kerr)
		}
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
		// S7's vulnerability database and the scanned-server registry go on
		// the pipeline, which hands them to the orchestrator (S7) and keeps
		// them for the daily sweep (agentry#177); setting them on the
		// orchestrator alone left the sweep with no database.
		srv.pipeline.SetMCPScanning(osvClient(cfg.Scan, log), scan.NewStoreMCPScanCache(st))
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
		scan.EnqueueReattestSweepIfBehind(context.Background(), st, srv.jobs, log, signer, keyReg)
		scan.EnqueueAttestSweepIfBehind(context.Background(), st, srv.jobs, log, signer)
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

// entitlements returns the §14.2 resolver, defaulting to the shipped §19
// limits so a partially wired server still enforces quotas.
func (s *Server) entitlements() entitlements.Resolver {
	if s.ents == nil {
		return entitlements.Default()
	}
	return s.ents
}

// CoreEntitlements is the resolver built from configuration, whatever an
// extension later replaced it with: what an extension's resolver wraps
// (agentry#326).
func (s *Server) CoreEntitlements() entitlements.Resolver {
	if s.coreEnts == nil {
		return entitlements.Default()
	}
	return s.coreEnts
}

// SetEntitlements swaps the quota resolver (the SaaS overlay, and tests).
func (s *Server) SetEntitlements(r entitlements.Resolver) {
	s.ents = r
	if s.reg != nil {
		s.reg.SetEntitlements(r)
	}
}

// SetMCPScanning swaps S7's vulnerability database client (tests use a
// fake); the scanned-server registry stays the store's.
func (s *Server) SetMCPScanning(client scan.OSVClient) {
	if s.pipeline != nil && s.st != nil {
		s.pipeline.SetMCPScanning(client, scan.NewStoreMCPScanCache(s.st))
	}
}

// MCPSweepReady reports whether the daily MCP sweep would consult a
// vulnerability database (the wiring check for agentry#177's sweep).
func (s *Server) MCPSweepReady() bool { return s.pipeline != nil && s.pipeline.MCPScanningEnabled() }

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

// SetOIDCEgressGuard replaces the egress policy OIDC requests go through
// (tests answer a name with an address of their choosing through the
// guard's resolver seam; production keeps the default).
func (s *Server) SetOIDCEgressGuard(g webhook.Guard) {
	s.oidcGuard = g
	s.oidcEgress = webhook.NewHTTPClient(g, nil)
}

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
	s.registerOrgLifecycle(q)   // the decommission sweep (handlers_org_lifecycle.go, agentry#363)
	s.registerFoldIn(q)         // the fold-in sweep and the pending members digest (handlers_fold_in.go, agentry#364)
}

// emitAgentEvent is the registry event sink (§9.3): it resolves the agent's
// owning org and fans the transition out to that org's webhooks. Personal
// namespaces (no org) and fan-out errors are swallowed — webhooks never affect
// the state change that triggered them.
func (s *Server) emitAgentEvent(ctx context.Context, agentID uuid.UUID, event string, payload map[string]any) {
	if s.st == nil {
		return
	}
	if s.webhooks == nil {
		s.fireEvent(ctx, Event{Kind: event, AgentID: agentID, Payload: payload})
		return
	}
	orgID, err := s.q().GetAgentOwnerOrg(ctx, agentID)
	if err != nil {
		// Personal namespace or agent gone: no webhooks, but the extension
		// hooks still hear the transition.
		s.fireEvent(ctx, Event{Kind: event, AgentID: agentID, Payload: payload})
		return
	}
	if err := s.webhooks.Emit(ctx, orgID, event, payload); err != nil {
		s.log.ErrorContext(ctx, "webhook emit", "event", event, "err", err)
	}
	s.fireEvent(ctx, Event{Kind: event, OrgID: orgID, AgentID: agentID, Payload: payload})
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
		problemUnavailable(w, r, "The server has no database configured; this endpoint needs one.")
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
		// externalOnly tells front ends and clients that accounts live in
		// a directory service (DEV-057): the native credential surface is
		// gone, so do not offer password or TOTP forms (agentry#21).
		"externalOnly": s.cfg.Auth.ExternalOnly,
		// publicPublish2FA says whether the §19 second-factor gate on public
		// publishing is enforced here (publish_gate.go: off in dev mode, and
		// off under externalOnly unless requireIdpMFA), so a front end states
		// the requirement only where the server holds it (agentry#269).
		"publicPublish2FA": publicPublish2FAEnabled(s.cfg),
	}
	meta := Meta{
		Version:    version.Version,
		ApiVersion: "v1",
		Features:   features,
	}
	// brand and ui (DEV-091): what this deployment calls itself and whether
	// it serves its own browser pages, so a client can name it and open
	// the device-authorize page wherever it lives.
	brand := BrandInfo{Name: s.cfg.DisplayName()}
	if v := s.cfg.Brand.LogoURL; v != "" {
		brand.LogoUrl = &v
	}
	if v := s.cfg.Brand.SupportEmail; v != "" {
		brand.SupportEmail = &v
	}
	meta.Brand = &brand
	ui := UIInfo{Mode: UIInfoMode(s.cfg.UI.Mode)}
	if s.cfg.UI.Mode != "off" {
		if u := s.paths.authorizeURL(); u != "" {
			ui.AuthorizeUrl = &u
		}
	}
	meta.Ui = &ui
	if names := s.ExtensionNames(); len(names) > 0 {
		meta.Extensions = &names
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
// DSSE attestations offline. Rotation = overlapping validity windows, plus
// the registry's own record of every key it has signed with (agentry#350).
func (s *Server) wellKnownSigningKeys(w http.ResponseWriter, r *http.Request) {
	out := struct {
		Keys []signingKey `json:"keys"`
	}{Keys: s.signingKeySet(r.Context())}
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, out)
}

// signingKey is one entry in signing-keys.json. notBefore/notAfter are what
// make §8.8's "rotation = overlapping validity windows" representable: without
// them the document can only ever describe one key as current, and an operator
// rotating a key has no way to say "both of these are legitimate, here is
// when each applies". Omitted when unset, so an unbounded key is silent rather
// than claiming a window it does not have.
//
// status is the registry's own record (agentry#350): `active` for the key
// that signs today, `retired` for a key the registry signed with before and
// no longer does — still listed, with the date, so an attestation it signed
// verifies and a client can say "signed by a retired key". A verification-only
// key from the operator's config carries no status: the registry never
// signed with it and cannot say what it was.
type signingKey struct {
	KeyID     string `json:"keyId"`
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"publicKeyPem"`
	NotBefore string `json:"notBefore,omitempty"`
	NotAfter  string `json:"notAfter,omitempty"`
	Status    string `json:"status,omitempty"`
	RetiredAt string `json:"retiredAt,omitempty"`
}

const (
	signingKeyActive  = "active"
	signingKeyRetired = "retired"
)

// signingKeySet assembles the published key set: the active signer first, then
// any verification-only keys the operator configured for an in-flight
// rotation, then the retired keys the registry itself signed with and that
// still have attestations to their name. A configured key the registry also
// has on record carries the record's status — the operator's listing is the
// rotation runbook's older step, not a reason to hide the date. A key whose
// PEM cannot be read is dropped with a log line rather than failing the
// endpoint — serving the keys that ARE valid keeps existing clients
// verifying, where a 500 would break all of them at once. The retired keys
// are read from the database on each request; the document is cached for
// five minutes and the query is one indexed probe per retired key.
func (s *Server) signingKeySet(ctx context.Context) []signingKey {
	keys := []signingKey{}
	listed := map[string]bool{}
	retired := s.retiredSigningKeys(ctx)
	if s.signer != nil {
		keys = append(keys, signingKey{
			KeyID:     s.signer.KeyID(),
			Algorithm: scan.SigningAlgorithm,
			PublicKey: s.signer.PublicKeyPEM(),
			NotBefore: s.cfg.Signing.NotBefore,
			NotAfter:  s.cfg.Signing.NotAfter,
			Status:    signingKeyActive,
		})
		listed[s.signer.KeyID()] = true
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
			alg = scan.SigningAlgorithm
		}
		entry := signingKey{
			KeyID:     k.KeyID,
			Algorithm: alg,
			PublicKey: pemText,
			NotBefore: k.NotBefore,
			NotAfter:  k.NotAfter,
		}
		if rec, ok := retired[k.KeyID]; ok {
			entry.Status, entry.RetiredAt = rec.Status, rec.RetiredAt
		}
		keys = append(keys, entry)
		listed[k.KeyID] = true
	}
	for _, k := range retired {
		if listed[k.KeyID] {
			continue
		}
		keys = append(keys, k)
	}
	return keys
}

// retiredSigningKeys reads the registry's record of retired keys that still
// have attestations to their name, keyed by id, in the served shape. Empty
// without a database, and empty with a log line when the read fails: the
// current key still serves and a client that pinned earlier keeps verifying,
// but a fresh client is refusing old releases for as long as that lasts.
func (s *Server) retiredSigningKeys(ctx context.Context) map[string]signingKey {
	out := map[string]signingKey{}
	if s.st == nil {
		return out
	}
	rows, err := s.q().ListRetiredSigningKeysInUse(ctx)
	if err != nil {
		s.log.Error("signing keys: listing retired keys", "err", err)
		return out
	}
	for _, k := range rows {
		entry := signingKey{
			KeyID:     k.KeyID,
			Algorithm: k.Algorithm,
			PublicKey: k.PublicKeyPem,
			Status:    signingKeyRetired,
		}
		if k.RetiredAt != nil {
			entry.RetiredAt = k.RetiredAt.UTC().Format(time.RFC3339)
		}
		out[k.KeyID] = entry
	}
	return out
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

	// Extension routes (DEV-091, extensions.go): /api/v1/x/<name>/ behind
	// the principal middleware, registered before the generated routes so a
	// clash with a generated path is a start-up panic, never a shadow.
	s.mountExtensions(mux)

	// Generated OpenAPI routes under /api/v1 (spec-first, D-09).
	apiHandler := HandlerWithOptions(s, StdHTTPServerOptions{
		BaseURL:    "/api/v1",
		BaseRouter: mux,
		ErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			problemBadRequest(w, r, sentence(err.Error()))
		},
		Middlewares: []MiddlewareFunc{s.principalMiddleware},
	})

	// The server's own browser surface (DEV-091, internal/ui): the device
	// authorize page, sign-in, the account basics and the operator pages,
	// served at /ui/ and acting through the same handler chain in-process.
	// Off by config, or down to the authorize page when a site fronts this
	// server. It is dispatched by prefix in front of the mux rather than
	// registered on it: a "/ui/" pattern and git's "GET /{ns}/{repo}/info/refs"
	// would be a ServeMux conflict (neither is more specific), and the
	// handle `ui` is reserved (handles.go) so no repository path can begin
	// with it.
	root := apiHandler
	if s.cfg.UI.Mode != "off" {
		var final http.Handler // bound below; the UI calls the full chain
		uiH := ui.New(ui.Options{
			API:          http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { final.ServeHTTP(w, r) }),
			Mode:         s.cfg.UI.Mode,
			SiteURL:      s.cfg.Web.URL,
			BaseURL:      s.cfg.BaseURL,
			Brand:        s.uiBrand(),
			Providers:    s.socialProviders(),
			ExternalOnly: s.cfg.Auth.ExternalOnly,
			IdPLogoutURL: s.cfg.Auth.IdPLogoutURL,
			CookieSecure: s.cfg.Auth.CookieSecure,
			Log:          s.log,
		})
		root = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/ui" || strings.HasPrefix(r.URL.Path, "/ui/") {
				uiH.ServeHTTP(w, r)
				return
			}
			apiHandler.ServeHTTP(w, r)
		})
		final = withMiddleware(root, s.log, s.Metrics, s.cfg.HTTP.TrustedProxies, s.cfg.HTTP.ProxyRequestID)
		return final
	}
	return withMiddleware(root, s.log, s.Metrics, s.cfg.HTTP.TrustedProxies, s.cfg.HTTP.ProxyRequestID)
}

// WrapMiddleware puts h behind the always-on middleware stack — request id,
// panic recovery, security headers, the access line, RED metrics — with this
// server's logger, metrics and trusted-proxy depth. The split `git` role
// mounts its bare mux through it so a git deployment logs like an api one.
func (s *Server) WrapMiddleware(h http.Handler) http.Handler {
	return withMiddleware(h, s.log, s.Metrics, s.cfg.HTTP.TrustedProxies, s.cfg.HTTP.ProxyRequestID)
}

func (s *Server) uiBrand() ui.Brand {
	b := s.cfg.Brand
	return ui.Brand{Name: s.cfg.DisplayName(), LogoURL: b.LogoURL, CSSURL: b.CSSURL, SupportEmail: b.SupportEmail, SecurityEmail: b.SecurityEmail, PrivacyURL: b.PrivacyURL, TermsURL: b.TermsURL}
}

// socialProviders lists the configured individual-login providers in the
// order the sign-in page offers them: the directory first when there is
// one (it is THE way in under externalOnly, agentry#164), then the rest.
func (s *Server) socialProviders() []ui.Provider {
	soc := s.cfg.Social
	all := []struct {
		id, label string
		cfg       config.SocialProvider
	}{
		{"authentik", "your " + s.cfg.DisplayName() + " account", soc.Authentik},
		{"google", "Google", soc.Google},
		{"github", "GitHub", soc.GitHub},
		{"microsoft", "Microsoft", soc.Microsoft},
		{"openai", "OpenAI", soc.OpenAI},
		{"claude", "Claude", soc.Claude},
	}
	var out []ui.Provider
	for _, p := range all {
		if p.cfg.ClientID != "" {
			out = append(out, ui.Provider{ID: p.id, Label: p.label})
		}
	}
	return out
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
		problemBadRequest(w, r, "Could not decode the request body: "+err.Error())
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
// osvClient builds S7's vulnerability database client (agentry#177):
// api.osv.dev unless the operator points elsewhere, offline when told so.
func osvClient(c config.Scan, log *slog.Logger) scan.OSVClient {
	u := strings.TrimSpace(c.OSVURL)
	switch strings.ToLower(u) {
	case "none", "off", "false", "disabled":
		log.Info("scan: MCP server vulnerability lookup disabled (AGENTRY_SCAN_OSV_URL)")
		return scan.OfflineOSV{}
	case "":
		u = "https://api.osv.dev"
	}
	log.Info("scan: MCP server vulnerability lookup enabled", "osv", u)
	return &scan.HTTPOSV{BaseURL: u}
}

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
