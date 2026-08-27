// Package api is the HTTP layer (§2.1 L2/L3 seam): generated OpenAPI server
// stubs, middleware, health endpoints, and well-known documents. Route
// authorization declarations live in authz_routes.go per §12.2.
package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/PLACEHOLDER_ORG/agentry/internal/audit"
	"github.com/PLACEHOLDER_ORG/agentry/internal/auth"
	"github.com/PLACEHOLDER_ORG/agentry/internal/config"
	"github.com/PLACEHOLDER_ORG/agentry/internal/notify"
	"github.com/PLACEHOLDER_ORG/agentry/internal/registry"
	"github.com/PLACEHOLDER_ORG/agentry/internal/store"
	storegen "github.com/PLACEHOLDER_ORG/agentry/internal/store/gen"
	"github.com/PLACEHOLDER_ORG/agentry/internal/version"
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
	limits   *rateLimits
	classes  limitClasses
	reg      *registry.Service
	blobs    registry.BlobStore
}

// New creates the API server. st may be nil in database-less dev mode; any
// handler that needs the store fails closed with 503 in that case.
func New(cfg config.Config, st *store.Store, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	sealer, err := auth.NewSealer(cfg.Auth.SealingKey, cfg.DevMode)
	if err != nil {
		// Config validation already enforces key presence outside dev; an
		// invalid key value is a hard startup error surfaced by panicking
		// here during construction (never mid-request).
		panic(err)
	}
	aud := audit.NewWriter(log)
	srv := &Server{
		cfg:      cfg,
		st:       st,
		log:      log,
		auditW:   aud,
		notifier: notify.LogNotifier{Log: log},
		sealer:   sealer,
		limits:   newRateLimits(),
		classes:  classesFromConfig(cfg.Limits),
	}
	if st != nil {
		srv.reg = registry.NewService(st, aud)
		if cfg.Storage.Kind == "local" {
			blobs, err := registry.NewLocalFS(cfg.Storage.LocalDir)
			if err != nil {
				panic(err) // startup-time config failure, never mid-request
			}
			srv.blobs = blobs
			srv.reg.SetBlobStore(blobs)
		}
		// M3 pipeline stub (§18.2): auto-approve in dev mode ONLY. Outside
		// dev, versions wait in `scanning` until the M4 orchestrator lands
		// (fail closed, §7).
		if cfg.DevMode {
			srv.reg.SetPipeline(registry.DevAutoApprovePipeline{Svc: srv.reg})
		}
	}
	return srv
}

// Reg exposes the registry service so role wiring can share one instance
// (git role injects its archiver; auto-publish uses the same pipeline).
func (s *Server) Reg() *registry.Service { return s.reg }

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
