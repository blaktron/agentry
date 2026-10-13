package testdb

import (
	"context"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestDatabaseURLPreservesConnectionOptions(t *testing.T) {
	base := "postgresql://fixture:password@127.0.0.1:5432/base?sslmode=verify-full&sslrootcert=%2Fcert.pem&application_name=fixture"
	got, err := databaseURL(base, "agentry_test_1234")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(got)
	if u.Path != "/agentry_test_1234" || u.RawQuery != "sslmode=verify-full&sslrootcert=%2Fcert.pem&application_name=fixture" || u.Host != "127.0.0.1:5432" || u.User.String() != "fixture:password" || u.Scheme != "postgresql" {
		t.Fatal("changing the database changed another connection option")
	}
	for _, bad := range []string{"", "host=localhost dbname=base", "https://fixture.invalid/base", "postgres://%zz/base"} {
		if _, err := databaseURL(bad, "agentry_test_1234"); err == nil {
			t.Errorf("invalid test server accepted: %q", bad)
		}
	}
}

// A run's sweeping fixtures must not reach another binary or an earlier run.
// These are real databases: distinct names alone would not prove isolation or
// that the process cleanup removes the state it created.
func TestDatabasesAreFreshIndependentAndRemoved(t *testing.T) {
	server := os.Getenv(Environment)
	if server == "" {
		t.Skip(Environment + " not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	first, removeFirst, err := create(ctx, server)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := removeFirst(); err != nil {
			t.Error(err)
		}
	})
	second, removeSecond, err := create(ctx, server)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := removeSecond(); err != nil {
			t.Error(err)
		}
	})
	if first == second || first == server || second == server {
		t.Fatal("test binaries share a database")
	}
	conn, err := pgx.Connect(ctx, first)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(context.Background()) }()
	if _, err := conn.Exec(ctx, "CREATE TABLE fixture (value text); INSERT INTO fixture VALUES ('only first')"); err != nil {
		t.Fatal(err)
	}
	other, err := pgx.Connect(ctx, second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = other.Close(context.Background()) }()
	var exists bool
	if err := other.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'fixture')").Scan(&exists); err != nil || exists {
		t.Fatalf("another binary sees the fixture: %v (%v)", exists, err)
	}
	// Drop with an open client too: a killed fixture may leave a pool open.
	if err := removeFirst(); err != nil {
		t.Fatal(err)
	}
	parent, err := pgx.Connect(ctx, server)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = parent.Close(context.Background()) }()
	u, _ := url.Parse(first)
	if err := parent.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)", u.Path[1:]).Scan(&exists); err != nil || exists {
		t.Fatalf("a test run left its database behind: %v (%v)", exists, err)
	}
}
