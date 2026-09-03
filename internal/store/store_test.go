package store

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// testDatabaseURL returns the integration-test DSN or skips. Real-Postgres
// tests per §17.1 (DSN-driven; see DEVIATIONS.md DEV-001 for the mechanism).
func testDatabaseURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("AGENTRY_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("AGENTRY_TEST_DATABASE_URL not set; skipping DB integration test")
	}
	return url
}

func TestMigrateAndConnect(t *testing.T) {
	url := testDatabaseURL(t)
	// Two minutes, not thirty seconds: the shared test database's advisory
	// lock is held by whichever package migrates first, and with three core
	// CI jobs on one host a full migration under load can take longer than
	// this test's own budget (agentry#137).
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	if err := Migrate(ctx, url); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	ver, err := MigrationStatus(ctx, url)
	if err != nil {
		t.Fatalf("MigrationStatus: %v", err)
	}
	if ver < 1 {
		t.Fatalf("expected migration version >= 1, got %d", ver)
	}

	st, err := Connect(ctx, url)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer st.Close()
	if err := st.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}

	// citext must be available after 00001 (needed by M1 schema).
	var n int
	if err := st.Pool().QueryRow(ctx, `SELECT count(*) FROM pg_extension WHERE extname IN ('citext','pg_trgm')`).Scan(&n); err != nil {
		t.Fatalf("extension query: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected citext+pg_trgm installed, got %d", n)
	}
}

// TestMigrateConcurrentFreshDatabase pins Migrate's doc promise: N migrators
// racing at a database that has never been migrated must all succeed. Before
// the advisory lock (DEV-052) the run raced through goose's version-table
// bootstrap and all but one failed inside the first migrations with
// duplicate pg_type rows — which is exactly what every multi-replica first
// boot does when migrateOnStart is set, and what `go test ./...` does to a
// fresh shared test database.
func TestMigrateConcurrentFreshDatabase(t *testing.T) {
	baseURL := testDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cfg, err := pgx.ParseConfig(baseURL)
	if err != nil {
		t.Fatalf("parse test DSN: %v", err)
	}
	// Name is generated, so it is safe to interpolate: digits and one
	// underscore only. CREATE/DROP DATABASE cannot take parameters.
	scratch := fmt.Sprintf("agentry_migrate_race_%d", time.Now().UnixNano())
	scratchURL := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
		cfg.User, url.PathEscape(cfg.Password), cfg.Host, cfg.Port, scratch)

	admin, err := Connect(ctx, baseURL)
	if err != nil {
		t.Fatalf("connect (admin): %v", err)
	}
	if _, err := admin.Pool().Exec(ctx, "CREATE DATABASE "+scratch); err != nil {
		admin.Close()
		t.Fatalf("create scratch database: %v", err)
	}
	admin.Close()
	defer func() {
		cleanup, err := Connect(context.WithoutCancel(ctx), baseURL)
		if err != nil {
			t.Errorf("connect (cleanup): %v", err)
			return
		}
		if _, err := cleanup.Pool().Exec(context.Background(), "DROP DATABASE IF EXISTS "+scratch); err != nil {
			t.Errorf("drop scratch database: %v", err)
		}
		cleanup.Close()
	}()

	const migrators = 4
	errs := make([]error, migrators)
	var wg sync.WaitGroup
	for i := 0; i < migrators; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = Migrate(ctx, scratchURL)
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("migrator %d failed: %v", i, err)
		}
	}

	ver, err := MigrationStatus(ctx, scratchURL)
	if err != nil {
		t.Fatalf("MigrationStatus: %v", err)
	}
	if ver < 1 {
		t.Fatalf("expected migration version >= 1 after concurrent run, got %d", ver)
	}
}
