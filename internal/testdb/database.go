// Package testdb gives integration-test binaries fresh Postgres databases.
// Whole-database sweeps and cleanup may share a binary, but cannot reach
// another package's fixtures or a previous invocation's state.
package testdb

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// Environment names the server database before Main and the private database
// inside that test binary. Without it integration tests retain their skips.
const Environment = "AGENTRY_TEST_DATABASE_URL"

var parentDatabase string

// ParentDatabase is the configured database's name, for guards that prove
// their package actually ran through Main rather than on the shared parent.
func ParentDatabase() string { return parentDatabase }

// Main runs a package's tests with an isolated database and removes it after
// they finish. A TestMain calls os.Exit(testdb.Main(m)); migrations remain the
// package's responsibility, so migration tests can still start from nothing.
func Main(m *testing.M) int {
	server := os.Getenv(Environment)
	if server == "" {
		return m.Run()
	}
	parent, err := url.Parse(server)
	if err == nil {
		parentDatabase = strings.TrimPrefix(parent.Path, "/")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	database, remove, err := create(ctx, server)
	cancel()
	if err != nil {
		fmt.Fprintln(os.Stderr, "test database:", err)
		return 1
	}
	if err := os.Setenv(Environment, database); err != nil {
		_ = remove()
		fmt.Fprintln(os.Stderr, "test database: set environment:", err)
		return 1
	}
	code := m.Run()
	_ = os.Setenv(Environment, server)
	if err := remove(); err != nil {
		fmt.Fprintln(os.Stderr, "test database:", err)
		return 1
	}
	return code
}

func databaseURL(server, name string) (string, error) {
	u, err := url.Parse(server)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		// Parse errors may echo the DSN, including its password.
		return "", fmt.Errorf("%s must be a postgres:// URL", Environment)
	}
	u.Path, u.RawPath = "/"+name, ""
	return u.String(), nil
}

func create(ctx context.Context, server string) (string, func() error, error) {
	var random [12]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", nil, fmt.Errorf("name the test database: %w", err)
	}
	name := "agentry_test_" + hex.EncodeToString(random[:])
	database, err := databaseURL(server, name)
	if err != nil {
		return "", nil, err
	}
	conn, err := pgx.Connect(ctx, server)
	if err != nil {
		return "", nil, fmt.Errorf("connect to the test server: %w", err)
	}
	_, err = conn.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize())
	_ = conn.Close(context.Background())
	if err != nil {
		return "", nil, fmt.Errorf("create the test database: %w", err)
	}
	remove := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		conn, err := pgx.Connect(ctx, server)
		if err != nil {
			return fmt.Errorf("connect for test database cleanup: %w", err)
		}
		defer func() { _ = conn.Close(context.Background()) }()
		// A failed fixture can leave a pool open. FORCE reaches only the
		// random database created above, never the configured parent.
		_, err = conn.Exec(ctx, "DROP DATABASE IF EXISTS "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)")
		if err != nil {
			return fmt.Errorf("remove the test database: %w", err)
		}
		return nil
	}
	return database, remove, nil
}
