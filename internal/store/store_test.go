package store

import (
	"context"
	"os"
	"testing"
	"time"
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
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
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
