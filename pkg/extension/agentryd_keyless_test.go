package extension

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/metrics"
	"github.com/blaktron/agentry/internal/store"
)

// TestOnlyTheKeyHolderNeedsTheSigningKey pins, at the role seam, that
// with signing.kind file and no key file on disk the api and git roles
// build their handlers (they hold no key), and `all`, which is also the
// worker, refuses to start. The worker role builds the same server as
// `all` for its queue and refuses the same way.
func TestOnlyTheKeyHolderNeedsTheSigningKey(t *testing.T) {
	st := migratedStore(t)
	ctx := context.Background()
	cfg := config.Default()
	cfg.DevMode = true
	cfg.Scan.OSVURL = "none"
	cfg.Git.DataDir = t.TempDir()
	cfg.Git.HooksDir = t.TempDir()
	cfg.Git.SSHAddr = ""
	cfg.Signing.Kind = "file"
	cfg.Signing.KeyFile = filepath.Join(t.TempDir(), "absent", "signing-key.pem")
	log := slog.New(slog.DiscardHandler)

	for _, role := range []string{"api", "git"} {
		mx, err := metrics.New(ctx, metrics.Config{ServiceName: "agentryd", Role: role, Env: cfg.Env})
		if err != nil {
			t.Fatal(err)
		}
		_, closeAll, err := buildHandler(ctx, cfg, st, log, role, mx, nil)
		if err != nil {
			t.Fatalf("buildHandler(%s) with no key file: %v", role, err)
		}
		_ = closeAll()
	}

	defer func() {
		if recover() == nil {
			t.Fatal("the all role started with no key file")
		}
	}()
	mx, err := metrics.New(ctx, metrics.Config{ServiceName: "agentryd", Role: "all", Env: cfg.Env})
	if err != nil {
		t.Fatal(err)
	}
	_, _, _ = buildHandler(ctx, cfg, st, log, "all", mx, nil)
}

// migratedStore connects to the test database, migrated, or skips.
func migratedStore(t *testing.T) *store.Store {
	t.Helper()
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
	return st
}
