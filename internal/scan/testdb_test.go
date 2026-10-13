package scan_test

import (
	"context"
	"os"
	"sync"
	"testing"

	"github.com/blaktron/agentry/internal/store"
	"github.com/blaktron/agentry/internal/testdb"
	"github.com/jackc/pgx/v5"
)

// Sweeps and signing-key changes act on a whole database. A fresh database
// for this binary separates them from API fixtures and previous test runs.
func TestMain(m *testing.M) { os.Exit(testdb.Main(m)) }

var scanMigration = sync.OnceValues(func() (string, error) {
	u := os.Getenv(testdb.Environment)
	return u, store.Migrate(context.Background(), u)
})

func scanTestDatabaseURL(t *testing.T) string {
	t.Helper()
	if os.Getenv(testdb.Environment) == "" {
		t.Skip(testdb.Environment + " not set")
	}
	u, err := scanMigration()
	if err != nil {
		t.Fatalf("scan test database: %v", err)
	}
	return u
}

func TestScanTestsRunInTheirOwnDatabase(t *testing.T) {
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, scanTestDatabaseURL(t))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	var current string
	if err := conn.QueryRow(ctx, "SELECT current_database()").Scan(&current); err != nil {
		t.Fatal(err)
	}
	if testdb.ParentDatabase() == "" || current == testdb.ParentDatabase() {
		t.Fatal("scan tests run on the configured parent instead of their own database")
	}
}
