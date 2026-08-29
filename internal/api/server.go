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
	"time"

	"github.com/google/uuid"

	"github.com/PLACEHOLDER_ORG/agentry/internal/audit"
	"github.com/PLACEHOLDER_ORG/agentry/internal/auth"
	samlsp "github.com/PLACEHOLDER_ORG/agentry/internal/auth/saml"
	"github.com/PLACEHOLDER_ORG/agentry/internal/config"
	"github.com/PLACEHOLDER_ORG/agentry/internal/dnsx"
	"github.com/PLACEHOLDER_ORG/agentry/internal/notify"
	"github.com/PLACEHOLDER_ORG/agentry/internal/queue"
	"github.com/PLACEHOLDER_ORG/agentry/internal/registry"
	"github.com/PLACEHOLDER_ORG/agentry/internal/render"
	"github.com/PLACEHOLDER_ORG/agentry/internal/scan"
	"github.com/PLACEHOLDER_ORG/agentry/internal/scan/ruleset"
	"github.com/PLACEHOLDER_ORG/agentry/internal/store"
	storegen "github.com/PLACEHOLDER_ORG/agentry/internal/store/gen"
	"github.com/PLACEHOLDER_ORG/agentry/internal/version"
	"github.com/PLACEHOLDER_ORG/agentry/internal/webhook"
)

// Server implements the generated ServerInterface plus non-spec endpoints
// (health, well-known). It is assembled once per process by NewHandler.
type Server struct {
	cfg      config.Config
	st       *store.Store // nil when running without a database (limited dev mode)
	log      *slog.Logger
	auditW   *audit.Writer
	notifier notify.Notifier
	sealer   *auth.Sealer
	signer   scan.Signer
	limits   *rateLimits
	classes  limitClasses
	reg      *registry.Service
	blobs    registry.BlobStore
	pipeline *scan.Pipeline
	renderer *render.Renderer
	// Enterprise (M6/WG-J): webhook fan-out, DNS resolver for domain
	// verification, and the shared SAML assertion replay cache.
	webhooks   *webhook.Dispatcher
	resolver   dnsx.Resolver
	samlReplay samlsp.ReplayCache
	// jobs is the enqueue-side queue client (webhook deliveries, audit
	// exports). The worker role drains it; nil without a database.
	jobs queue.Client
	// oidcHTTPClient, when set, is the HTTP client OIDC discovery/JWKS/token
	// calls use (tests point it at an httptest IdP). nil = default client.
	oidcHTTPClient *http.Client
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
	srv := &Server{
		cfg:      cfg,
		st:       st,
		log:      log,
		auditW:   aud,
		notifier: notify.LogNotifier{Log: log},
		sealer:   sealer,
		renderer: render.New(),
		limits:   newRateLimits(),
		classes:  classesFromConfig(cfg.Limits),
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
		})
		srv.reg.SetEventSink(srv.emitAgentEvent)
		if cfg.Storage.Kind == "local" {
			blobs, berr := registry.NewLocalFS(cfg.Storage.LocalDir)
			if berr != nil {
				panic(berr) // startup-time config failure, never mid-request
			}
			srv.blobs = blobs
			srv.reg.SetBlobStore(blobs)
		}
		// M4 security pipeline (§8): the orchestrator + gate replace the M3
		// dev stub. Ruleset embedded (§8.3); judge + signer per config.
		if srv.blobs == nil {
			return srv // no archive store (e.g. s3 kind, WG-K): pipeline wired there
		}
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
		judge := scan.NewJudgeProvider(judgeProviderName(cfg))
		signer, serr := scan.NewSigner(cfg.Signing.Kind, cfg.Signing.KeyFile, cfg.DevMode)
		if serr != nil {
			panic(serr)
		}
		srv.signer = signer
		orch := scan.NewOrchestrator(bundle, judge, log)
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
		srv.reg.SetPublicPublish2FA(!cfg.DevMode)
		srv.reg.SetLogger(log)
		// A ruleset semver we have never seen means the catalogue was judged
		// by older rules (§8.7).
		scan.EnqueueRescanSweepOnNewRuleset(context.Background(), srv.jobs, log, rulesetReg)
	}
	return srv
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

// RegisterQueueHandlers wires this server's async job handlers onto a queue
// worker (the worker role, and tests): webhook delivery (§9.3) and audit
// export (§12.6).
func (s *Server) RegisterQueueHandlers(q queue.Client) {
	if s.webhooks != nil {
		s.webhooks.RegisterHandlers(q)
	}
	q.Register(jobAuditExport, s.runAuditExport)
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
	}
	writeJSON(w, http.StatusOK, Meta{
		Version:    version.Version,
		ApiVersion: "v1",
		Features:   features,
	})
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
	type key struct {
		KeyID     string `json:"keyId"`
		Algorithm string `json:"algorithm"`
		PublicKey string `json:"publicKeyPem"`
	}
	out := struct {
		Keys []key `json:"keys"`
	}{Keys: []key{}}
	if s.signer != nil {
		out.Keys = append(out.Keys, key{
			KeyID:     s.signer.KeyID(),
			Algorithm: "ecdsa-p256-sha256",
			PublicKey: s.signer.PublicKeyPEM(),
		})
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, out)
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

	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("GET /readyz", s.readyz)
	mux.HandleFunc("GET /.well-known/agentry/registry.json", s.wellKnownRegistry)
	mux.HandleFunc("GET /.well-known/agentry/signing-keys.json", s.wellKnownSigningKeys)

	// SCIM 2.0 data plane (§12.5). Mounted outside the generated /api/v1
	// handler: it uses its own base path, application/scim+json media type, and
	// authenticates by SCIM bearer token (not the RBAC chokepoint), so it is
	// deliberately not part of the OpenAPI surface (see handlers_scim.go).
	s.mountSCIM(mux)

	// Generated OpenAPI routes under /api/v1 (spec-first, D-09).
	apiHandler := HandlerWithOptions(s, StdHTTPServerOptions{
		BaseURL:    "/api/v1",
		BaseRouter: mux,
		ErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			problemBadRequest(w, r, err.Error())
		},
		Middlewares: []MiddlewareFunc{s.principalMiddleware},
	})

	return withMiddleware(apiHandler, s.log)
}

// judgeProviderName picks the judge provider: config value, or "static" in
// dev so the pipeline is exercisable without a live model (DEV-007).
func judgeProviderName(cfg config.Config) string {
	if cfg.Judge.Provider == "none" && cfg.DevMode {
		return "static"
	}
	return cfg.Judge.Provider
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
