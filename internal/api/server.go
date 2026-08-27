// Package api is the HTTP layer (§2.1 L2/L3 seam): generated OpenAPI server
// stubs, middleware, health endpoints, and well-known documents. Route
// authorization declarations live beside handlers per §12.2.
package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/PLACEHOLDER_ORG/agentry/internal/config"
	"github.com/PLACEHOLDER_ORG/agentry/internal/store"
	"github.com/PLACEHOLDER_ORG/agentry/internal/version"
)

// Server implements the generated ServerInterface plus non-spec endpoints
// (health, well-known). It is assembled once per process by NewHandler.
type Server struct {
	cfg config.Config
	st  *store.Store // nil when running without a database (limited dev mode)
	log *slog.Logger
}

// New creates the API server. st may be nil in database-less dev mode; any
// handler that needs the store must fail closed with 503 in that case.
func New(cfg config.Config, st *store.Store, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	return &Server{cfg: cfg, st: st, log: log}
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

// Health mounts /healthz (liveness: process up) and /readyz (readiness:
// dependencies reachable). LBs use /healthz; deploys gate on /readyz.
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
	mux := http.NewServeMux()

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
