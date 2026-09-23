package extension

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/metrics"
	"github.com/blaktron/agentry/internal/store"
)

// TestGitRoleServesHealthAndReadiness pins what the chart's git Deployment
// probes: /healthz (liveness) and /readyz (readiness, the database ping) on
// the git role's own mux. The first live install (agentry#450) had a git pod
// that never became Ready because only /healthz was mounted there.
func TestGitRoleServesHealthAndReadiness(t *testing.T) {
	url := os.Getenv("AGENTRY_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("AGENTRY_TEST_DATABASE_URL not set; skipping integration test")
	}
	ctx := context.Background()
	if err := store.Migrate(ctx, url); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	st, err := store.Connect(ctx, url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(st.Close)

	cfg := config.Default()
	cfg.DevMode = true
	cfg.Scan.OSVURL = "none"
	cfg.Git.DataDir = t.TempDir()
	cfg.Git.SSHAddr = "" // no listener in a test
	mx, err := metrics.New(ctx, metrics.Config{ServiceName: "agentryd", Role: "git", Env: cfg.Env})
	if err != nil {
		t.Fatalf("metrics: %v", err)
	}
	h, closeAll, err := buildHandler(ctx, cfg, st, slog.New(slog.DiscardHandler), "git", mx, nil)
	if err != nil {
		t.Fatalf("buildHandler(git): %v", err)
	}
	t.Cleanup(func() { _ = closeAll() })

	for _, path := range []string{"/healthz", "/readyz"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s on the git role: %d %s", path, rec.Code, rec.Body.String())
		}
	}
}
