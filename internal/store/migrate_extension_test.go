package store

import (
	"context"
	"fmt"
	"hash/fnv"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/pressly/goose/v3"
)

// extensionLockID is the advisory lock MigrateExtension takes for an
// extension: the core's lock number mixed with a hash of the extension's
// name, so two extensions, and an extension and the core, never wait on one
// another.
func extensionLockID(name string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(name))
	return migrateLockID ^ int64(h.Sum64()&0x7fffffff)
}

// stepsFS is an extension's migrations: n steps, each creating one table in
// the schema the extension owns, ent_<name with underscores>.
func stepsFS(name string, n int) fstest.MapFS {
	schema := "ent_" + strings.ReplaceAll(name, "-", "_")
	fsys := fstest.MapFS{}
	for i := 1; i <= n; i++ {
		fsys[fmt.Sprintf("%05d_step.sql", i)] = &fstest.MapFile{Data: []byte(fmt.Sprintf(
			"-- +goose Up\nCREATE SCHEMA IF NOT EXISTS %[1]s;\nCREATE TABLE %[1]s.step%[2]d (id int);\n-- +goose Down\nDROP TABLE %[1]s.step%[2]d;\n", schema, i))}
	}
	return fsys
}

// An extension's migrations run under their own version table and own
// their schema; running them twice is a no-op (pkg/extension).
func TestMigrateExtension(t *testing.T) {
	url := os.Getenv("AGENTRY_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("AGENTRY_TEST_DATABASE_URL not set")
	}
	ctx, cancelAll := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancelAll()
	if err := Migrate(ctx, url); err != nil {
		t.Fatalf("core migrate: %v", err)
	}
	core, err := connectStd(url)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = core.Close() }()
	var coreRows int
	if err := core.QueryRowContext(ctx, "SELECT count(*) FROM goose_db_version").Scan(&coreRows); err != nil {
		t.Fatalf("core version table: %v", err)
	}
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
	// The extension's run is recorded once in its own table, and not at all
	// in the core's, and the core's migrator still reads the core's table
	// afterwards (the extension's table name is not left set).
	var applied int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM ent_probe_goose_version WHERE version_id > 0 AND is_applied").Scan(&applied); err != nil || applied != 1 {
		t.Fatalf("applied migrations in the extension's table: %d (%v), want 1 after two runs", applied, err)
	}
	var rows int
	if err := core.QueryRowContext(ctx, "SELECT count(*) FROM goose_db_version").Scan(&rows); err != nil || rows != coreRows {
		t.Fatalf("rows in the core's version table: %d (%v), want the %d it had before the extension ran", rows, err, coreRows)
	}
	if status, err := MigrationStatus(ctx, url); err != nil || status < newestMigration(t) {
		t.Fatalf("core status after the extension = %d (%v), want at least the newest core migration %d", status, err, newestMigration(t))
	}
	if err := Migrate(ctx, url); err != nil {
		t.Fatalf("core migrate after the extension: %v", err)
	}

	// Everything below runs on a database of its own, which the test drops.
	scratch := scratchDatabase(t, url, "agentry_ext")
	queryInt := func(q string, args ...any) int {
		t.Helper()
		sdb, err := connectStd(scratch)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = sdb.Close() }()
		var n int
		if err := sdb.QueryRowContext(ctx, q, args...).Scan(&n); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		return n
	}
	appliedIn := func(name string) int {
		t.Helper()
		return queryInt("SELECT count(*) FROM ent_" + strings.ReplaceAll(name, "-", "_") + "_goose_version WHERE version_id > 0 AND is_applied")
	}
	tableCount := func(schema string) int {
		t.Helper()
		return queryInt("SELECT count(*) FROM information_schema.tables WHERE table_schema = $1", schema)
	}

	// Each extension numbers its migrations in its own table and owns its
	// own schema, whatever number another extension, or the core, is at; a
	// dash in the name becomes an underscore in both.
	t.Run("extensions number their migrations independently", func(t *testing.T) {
		for _, name := range []string{"alpha-one", "beta"} {
			for run := 0; run < 2; run++ {
				if err := MigrateExtension(ctx, scratch, name, stepsFS(name, 2)); err != nil {
					t.Fatalf("%s run %d: %v", name, run+1, err)
				}
			}
		}
		for name, schema := range map[string]string{"alpha-one": "ent_alpha_one", "beta": "ent_beta"} {
			if n := appliedIn(name); n != 2 {
				t.Errorf("%s: %d applied migrations in its version table, want 2 (the second run changes nothing)", name, n)
			}
			if n := tableCount(schema); n != 2 {
				t.Errorf("%s: %d tables in schema %s, want its 2 steps", name, n, schema)
			}
		}
		if n := queryInt("SELECT count(*) FROM pg_class WHERE relname = 'goose_db_version'"); n != 0 {
			t.Errorf("the core's version table was created by an extension's migration")
		}
	})

	// A migration that fails is reported under the extension's name, and the
	// steps before it stay applied.
	t.Run("a failing migration", func(t *testing.T) {
		fsys := stepsFS("broken", 1)
		fsys["00002_bad.sql"] = &fstest.MapFile{Data: []byte("-- +goose Up\nSELEKT 1;\n-- +goose Down\nSELECT 1;\n")}
		err := MigrateExtension(ctx, scratch, "broken", fsys)
		if err == nil || !strings.Contains(err.Error(), "store: migrate broken: ") {
			t.Fatalf("MigrateExtension with a bad step: %v, want an error under the extension's name", err)
		}
		if n := appliedIn("broken"); n != 1 {
			t.Errorf("applied migrations after the failure = %d, want the 1 before the bad step", n)
		}
	})

	// An extension's lock is its own: it keeps another migrator of the same
	// extension waiting, and nobody else.
	t.Run("an extension's lock", func(t *testing.T) {
		release := holdAdvisoryLock(t, scratch, extensionLockID("lockme"))
		short, cancelShort := context.WithTimeout(ctx, 3*time.Second)
		defer cancelShort()
		if err := MigrateExtension(short, scratch, "lockme", stepsFS("lockme", 1)); err == nil || !strings.Contains(err.Error(), "store: migrate lockme: advisory lock") {
			t.Fatalf("MigrateExtension while its lock was held: %v, want it to wait and fail at the lock", err)
		}
		other, cancelOther := context.WithTimeout(ctx, 30*time.Second)
		defer cancelOther()
		if err := MigrateExtension(other, scratch, "free", stepsFS("free", 1)); err != nil {
			t.Fatalf("another extension while lockme's lock was held: %v", err)
		}
		release()
		if err := MigrateExtension(ctx, scratch, "lockme", stepsFS("lockme", 1)); err != nil {
			t.Fatalf("MigrateExtension once the lock was free: %v", err)
		}
	})
	t.Run("the core's lock", func(t *testing.T) {
		release := holdAdvisoryLock(t, scratch, migrateLockID)
		defer release()
		beside, cancelBeside := context.WithTimeout(ctx, 30*time.Second)
		defer cancelBeside()
		if err := MigrateExtension(beside, scratch, "beside-core", stepsFS("beside-core", 1)); err != nil {
			t.Fatalf("an extension while the core's migration lock was held: %v", err)
		}
	})

	// goose keeps its filesystem and table name in package variables, so one
	// process migrates one thing at a time. A migrator that waits on the
	// database's lock still holds its place: an extension asked to migrate
	// then waits for it, whatever the lock it would take is free.
	t.Run("one migration at a time in a process", func(t *testing.T) {
		release := holdAdvisoryLock(t, scratch, migrateLockID)
		defer release()
		waiting := func(id int64) int {
			return queryInt(`SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND NOT granted AND ((classid::bigint << 32) | objid::bigint) = $1`, id)
		}
		coreCtx, cancelCore := context.WithCancel(ctx)
		defer cancelCore()
		coreDone := make(chan error, 1)
		go func() { coreDone <- Migrate(coreCtx, scratch) }()
		waitCtx, giveUp := context.WithTimeout(ctx, 30*time.Second)
		defer giveUp()
		for waiting(migrateLockID) == 0 {
			if waitCtx.Err() != nil {
				t.Fatal("the core migrator never started waiting for the lock")
			}
			runtime.Gosched()
		}
		extDone := make(chan error, 1)
		extCtx, cancelExt := context.WithTimeout(ctx, 30*time.Second)
		defer cancelExt()
		go func() { extDone <- MigrateExtension(extCtx, scratch, "queued", stepsFS("queued", 1)) }()
		// Long enough to connect, take its own lock and run one step.
		grace, endGrace := context.WithTimeout(ctx, 1500*time.Millisecond)
		defer endGrace()
		select {
		case err := <-extDone:
			t.Fatalf("an extension migrated (%v) while the core migrator was in progress in the same process", err)
		case <-grace.Done():
		}
		cancelCore()
		if err := <-coreDone; err == nil {
			t.Error("the core migrator finished although the lock was held")
		}
		if err := <-extDone; err != nil {
			t.Fatalf("the extension once the core migrator was gone: %v", err)
		}
		if n := tableCount("ent_queued"); n != 1 {
			t.Errorf("tables of the extension that waited = %d, want 1", n)
		}
	})

	// Extensions started together, as the processes of one deployment are,
	// each end with their own steps in their own tables.
	t.Run("extensions migrating together", func(t *testing.T) {
		names := []string{"co-a", "co-b", "co-c", "co-d", "co-e", "co-f"}
		errs := make([]error, len(names))
		var wg sync.WaitGroup
		for i, name := range names {
			wg.Add(1)
			go func() {
				defer wg.Done()
				errs[i] = MigrateExtension(ctx, scratch, name, stepsFS(name, 3))
			}()
		}
		wg.Wait()
		for i, name := range names {
			if errs[i] != nil {
				t.Errorf("%s: %v", name, errs[i])
				continue
			}
			if n := appliedIn(name); n != 3 {
				t.Errorf("%s: %d applied migrations in its own table, want 3", name, n)
			}
			if n := tableCount("ent_" + strings.ReplaceAll(name, "-", "_")); n != 3 {
				t.Errorf("%s: %d tables in its schema, want 3", name, n)
			}
		}
	})

	// Once an extension has migrated, goose is back on the core's migrations
	// and the core's version table, for whoever drives it next. (Last, since
	// it creates the core's table in this database.)
	t.Run("goose is left on the core's migrations", func(t *testing.T) {
		if err := MigrateExtension(ctx, scratch, "leaves-goose", stepsFS("leaves-goose", 1)); err != nil {
			t.Fatal(err)
		}
		sdb, err := connectStd(scratch)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = sdb.Close() }()
		if err := goose.UpToContext(ctx, sdb, "migrations", 1); err != nil {
			t.Fatalf("goose after an extension: %v", err)
		}
		if v, err := goose.GetDBVersionContext(ctx, sdb); err != nil || v != 1 {
			t.Fatalf("version in the core's table = %d (%v), want 1", v, err)
		}
	})
}
