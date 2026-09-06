package store

import (
	"context"
	"os"
	"testing"
	"testing/fstest"
)

// An extension's migrations run under their own version table and own
// their schema; running them twice is a no-op (pkg/extension, DEV-091).
func TestMigrateExtension(t *testing.T) {
	url := os.Getenv("AGENTRY_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("AGENTRY_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	fsys := fstest.MapFS{
		"00001_init.sql": &fstest.MapFile{Data: []byte("-- +goose Up\nCREATE SCHEMA IF NOT EXISTS ent_probe;\nCREATE TABLE IF NOT EXISTS ent_probe.marks (id serial PRIMARY KEY, note text);\n-- +goose Down\nDROP TABLE ent_probe.marks;\n")},
	}
	for i := 0; i < 2; i++ {
		if err := MigrateExtension(ctx, url, "probe", fsys); err != nil {
			t.Fatalf("run %d: %v", i+1, err)
		}
	}
	db, err := connectStd(url)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var n int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM information_schema.tables WHERE table_schema='ent_probe' AND table_name='marks'").Scan(&n); err != nil || n != 1 {
		t.Fatalf("table: n=%d err=%v", n, err)
	}
	var v int64
	if err := db.QueryRowContext(ctx, "SELECT max(version_id) FROM ent_probe_goose_version").Scan(&v); err != nil || v != 1 {
		t.Fatalf("version table: v=%d err=%v", v, err)
	}
	// The core's own migration state is untouched by the extension's run.
	if _, err := MigrationStatus(ctx, url); err != nil {
		t.Fatalf("core status after extension: %v", err)
	}
}
