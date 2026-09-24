package scan_test

import (
	"context"
	"errors"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// This package's tests run in a database of their own, not in the one
// AGENTRY_TEST_DATABASE_URL names (agentry#482).
//
// `go test ./...` runs packages in parallel, and every package with
// database tests used to share that one database. This package is the one
// whose tests act on the whole database rather than on rows they made: the
// rescan sweep re-scans every published version in it, and
// RegisterSigningKey retires every key but the one it records. Beside
// internal/api that raced both ways: a sweep's fresh `running` run hid the
// verdict of a version internal/api had just published
// (TestAccountInstallNeedsTheReleasesAcceptances read verdict=<nil>), and a
// key registered by an internal/api test server retired the key a test
// here had just made active (TestReattestSweepCountersignsWithTheNewKey:
// "the active key is listed among the retired"). A database of its own
// keeps the sweeps' reach to this package's rows.
//
// The name is the shared database's with a "_scan" suffix, created on first
// use and kept, as the shared one is: tests here already live with what
// earlier runs left behind.
const scanDatabaseSuffix = "_scan"

var (
	scanDBOnce sync.Once
	scanDBURL  string
	scanDBErr  error
)

// scanTestDatabaseURL returns the URL of this package's database, creating
// the database on first use, or skips the test when no test database is
// configured.
func scanTestDatabaseURL(t *testing.T) string {
	t.Helper()
	base := os.Getenv("AGENTRY_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("AGENTRY_TEST_DATABASE_URL not set")
	}
	scanDBOnce.Do(func() { scanDBURL, scanDBErr = ensureSuffixedDatabase(base, scanDatabaseSuffix) })
	if scanDBErr != nil {
		t.Fatalf("scan test database: %v", scanDBErr)
	}
	return scanDBURL
}

// ensureSuffixedDatabase creates <db><suffix> beside the database base names
// if it does not exist, and returns base with its database swapped for it.
func ensureSuffixedDatabase(base, suffix string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	name := strings.TrimPrefix(u.Path, "/") + suffix
	u.Path = "/" + name
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, base)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close(ctx) }()
	var exists bool
	if err := conn.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)", name).Scan(&exists); err != nil {
		return "", err
	}
	if !exists {
		// CREATE DATABASE takes no parameters; the name is quoted as an
		// identifier. Another process creating it first is not an error.
		_, err := conn.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize())
		var pgErr *pgconn.PgError
		if err != nil && (!errors.As(err, &pgErr) || pgErr.Code != "42P04") {
			return "", err
		}
	}
	return u.String(), nil
}

// The guard on the isolation itself: a helper that stopped swapping the
// database would put this package's whole-database sweeps back beside
// every other package's tests, and nothing else would notice until the
// flakes came back.
func TestScanTestsRunInTheirOwnDatabase(t *testing.T) {
	got := scanTestDatabaseURL(t)
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, got)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	var current string
	if err := conn.QueryRow(ctx, "SELECT current_database()").Scan(&current); err != nil {
		t.Fatal(err)
	}
	shared, err := url.Parse(os.Getenv("AGENTRY_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	if want := strings.TrimPrefix(shared.Path, "/") + scanDatabaseSuffix; current != want {
		t.Fatalf("scan tests run in %q, want %q (their own, not the shared database)", current, want)
	}
}
