package store

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivermigrate"

	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// testDatabaseURL returns the integration-test DSN
// (AGENTRY_TEST_DATABASE_URL) or skips. The tests run against a real
// Postgres.
func testDatabaseURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("AGENTRY_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("AGENTRY_TEST_DATABASE_URL not set; skipping DB integration test")
	}
	return url
}

// closeStore closes the store, giving up on a pool in which a failing test
// left a transaction open: its Close never returns.
func closeStore(st *Store) {
	closed := make(chan struct{})
	go func() { st.Close(); close(closed) }()
	limit, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	select {
	case <-closed:
	case <-limit.Done():
	}
}

// scratchDatabase creates a database of its own for one test on the server
// the test DSN names, drops it when the test ends, and returns a DSN for it
// that keeps every other option of the test DSN.
func scratchDatabase(t *testing.T, baseURL, prefix string) string {
	t.Helper()
	ctx := context.Background()
	name := fmt.Sprintf("%s_%d", prefix, time.Now().UnixNano())
	admin, err := Connect(ctx, baseURL)
	if err != nil {
		t.Fatalf("connect (admin): %v", err)
	}
	if _, err := admin.Pool().Exec(ctx, "CREATE DATABASE "+name); err != nil {
		admin.Close()
		t.Fatalf("create scratch database: %v", err)
	}
	admin.Close()
	t.Cleanup(func() {
		cleanup, err := Connect(context.Background(), baseURL)
		if err != nil {
			t.Errorf("connect (cleanup): %v", err)
			return
		}
		defer cleanup.Close()
		if _, err := cleanup.Pool().Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)"); err != nil {
			t.Errorf("drop scratch database: %v", err)
		}
	})
	if !strings.Contains(baseURL, "://") {
		return baseURL + " dbname=" + name
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		t.Fatalf("parse test DSN: %v", err)
	}
	u.Path = "/" + name
	return u.String()
}

// newestMigration is the number of the newest core migration the binary
// embeds.
func newestMigration(t *testing.T) int64 {
	t.Helper()
	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	var newest int64
	for _, e := range entries {
		num, _, ok := strings.Cut(e.Name(), "_")
		if !ok || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		n, err := strconv.ParseInt(num, 10, 64)
		if err != nil {
			t.Fatalf("migration %s: %v", e.Name(), err)
		}
		newest = max(newest, n)
	}
	return newest
}

// holdAdvisoryLock takes a session advisory lock on its own connection, the
// way another replica's migrator holds one, and gives it back when the
// returned function is called or the test ends.
func holdAdvisoryLock(t *testing.T, databaseURL string, id int64) (release func()) {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect (lock holder): %v", err)
	}
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", id); err != nil {
		_ = conn.Close(ctx)
		t.Fatalf("take advisory lock: %v", err)
	}
	var once sync.Once
	release = func() { once.Do(func() { _ = conn.Close(ctx) }) }
	t.Cleanup(release)
	return release
}

func TestMigrateAndConnect(t *testing.T) {
	url := testDatabaseURL(t)
	// Two minutes, not thirty seconds: the shared test database's advisory
	// lock is held by whichever package migrates first, and with three core
	// CI jobs on one host a full migration under load can take longer than
	// this test's own budget.
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

	// citext must be available after 00001 (the schema uses it).
	var n int
	if err := st.Pool().QueryRow(ctx, `SELECT count(*) FROM pg_extension WHERE extname IN ('citext','pg_trgm')`).Scan(&n); err != nil {
		t.Fatalf("extension query: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected citext+pg_trgm installed, got %d", n)
	}

	// The database is at the newest migration the binary carries (or at a
	// newer one a later build of the same database applied).
	if newest := newestMigration(t); ver < newest {
		t.Fatalf("migration version %d, want at least the newest embedded migration, %d", ver, newest)
	}
	// Connections are recycled every hour, so a replica never keeps one
	// across a database failover or a credential rotation for good.
	if got := st.Pool().Config().MaxConnLifetime; got != time.Hour {
		t.Errorf("MaxConnLifetime = %s, want 1h", got)
	}
	// The generated queries run on that pool.
	if now, err := st.Queries().Now(ctx); err != nil || time.Since(now) > time.Minute || time.Until(now) > time.Minute {
		t.Errorf("Queries().Now = %v, %v, want the server's time", now, err)
	}
	st.Close()
	if err := st.Ping(ctx); err == nil {
		t.Error("Ping on a closed store succeeded")
	}

	// What a bad DSN or an unreachable server looks like to the caller.
	unparsable := "postgres://user:secret@localhost:not-a-port/db"
	unreachable := "postgres://user:secret@127.0.0.1:1/db?sslmode=disable&connect_timeout=5"
	t.Run("a DSN that does not parse", func(t *testing.T) {
		if got, err := Connect(ctx, unparsable); err == nil || got != nil || !strings.Contains(err.Error(), "store: parse database url") {
			t.Errorf("Connect: store %v, err %v, want no store and a parse error", got, err)
		}
		if err := Migrate(ctx, unparsable); err == nil || !strings.Contains(err.Error(), "store: parse database url") {
			t.Errorf("Migrate: %v, want a parse error", err)
		}
		if _, err := MigrationStatus(ctx, unparsable); err == nil || !strings.Contains(err.Error(), "store: parse database url") {
			t.Errorf("MigrationStatus: %v, want a parse error", err)
		}
		if err := MigrateExtension(ctx, unparsable, "probe", nil); err == nil || !strings.Contains(err.Error(), "store: parse database url") {
			t.Errorf("MigrateExtension: %v, want a parse error", err)
		}
	})
	t.Run("a server that is not there", func(t *testing.T) {
		if got, err := Connect(ctx, unreachable); err == nil || got != nil || !strings.Contains(err.Error(), "store: ping") {
			t.Errorf("Connect: store %v, err %v, want no store and a ping error", got, err)
		}
		if err := Migrate(ctx, unreachable); err == nil || !strings.Contains(err.Error(), "advisory lock") {
			t.Errorf("Migrate: %v, want the failure to take the migration lock", err)
		}
		if _, err := MigrationStatus(ctx, unreachable); err == nil {
			t.Error("MigrationStatus on an unreachable server succeeded")
		}
	})
	// Core migrations apply in order and stop at the first that fails, and
	// River's tables are migrated only after all of them: a database that
	// already holds one of the core's tables fails at that migration.
	t.Run("a core migration that fails", func(t *testing.T) {
		scratch := scratchDatabase(t, url, "agentry_corefail")
		pool, err := pgxpool.New(ctx, scratch)
		if err != nil {
			t.Fatal(err)
		}
		defer pool.Close()
		if _, err := pool.Exec(ctx, `CREATE TABLE handles (x int)`); err != nil {
			t.Fatal(err)
		}
		if err := Migrate(ctx, scratch); err == nil || !strings.Contains(err.Error(), "store: migrate: ") || !strings.Contains(err.Error(), "00002_identity.sql") {
			t.Fatalf("Migrate over a conflicting table: %v, want a migrate error naming the migration that failed", err)
		}
		if status, err := MigrationStatus(ctx, scratch); err != nil || status != 1 {
			t.Errorf("version after the failure = %d (%v), want 1: the first migration applied, the second did not", status, err)
		}
		var river *string
		if err := pool.QueryRow(ctx, `SELECT to_regclass('public.river_job')::text`).Scan(&river); err != nil || river != nil {
			t.Errorf("river_job after a failed core migration: %v (%v), want River left alone", river, err)
		}
		// The failed run gave up its lock: once the conflict is gone the
		// next one goes all the way.
		if _, err := pool.Exec(ctx, `DROP TABLE handles`); err != nil {
			t.Fatal(err)
		}
		if err := Migrate(ctx, scratch); err != nil {
			t.Fatalf("Migrate after the conflict was removed: %v", err)
		}
		if status, err := MigrationStatus(ctx, scratch); err != nil || status != newestMigration(t) {
			t.Errorf("version after the retry = %d (%v), want %d", status, err, newestMigration(t))
		}
		if err := pool.QueryRow(ctx, `SELECT to_regclass('public.river_job')::text`).Scan(&river); err != nil || river == nil {
			t.Errorf("river_job after the retry: %v (%v), want it migrated", river, err)
		}
	})
	t.Run("a migrator whose context is already done", func(t *testing.T) {
		done, cancelDone := context.WithCancel(ctx)
		cancelDone()
		if err := Migrate(done, url); err == nil || !strings.Contains(err.Error(), "advisory lock") {
			t.Errorf("Migrate: %v, want it to fail at the migration lock", err)
		}
	})
}

// A transaction commits when its function returns nil and is rolled back,
// connection returned, when it returns an error or panics; its queries are
// the transaction's own; a failed commit and a failed begin are reported.
func TestWithTxCommitsOnNilAndRollsBackOtherwise(t *testing.T) {
	baseURL := testDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	txURL := scratchDatabase(t, baseURL, "agentry_tx")
	st, err := Connect(ctx, txURL)
	if err != nil {
		t.Fatal(err)
	}
	defer closeStore(st)
	if _, err := st.Pool().Exec(ctx, `CREATE TABLE marks (v int, UNIQUE (v) DEFERRABLE INITIALLY DEFERRED)`); err != nil {
		t.Fatal(err)
	}
	marks := func() (n int) {
		t.Helper()
		if err := st.Pool().QueryRow(ctx, `SELECT count(*) FROM marks`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	insert := func(tx pgx.Tx, values ...int) {
		t.Helper()
		for _, v := range values {
			if _, err := tx.Exec(ctx, `INSERT INTO marks VALUES ($1)`, v); err != nil {
				t.Fatal(err)
			}
		}
	}
	released := func(what string) {
		t.Helper()
		if n := st.Pool().Stat().AcquiredConns(); n != 0 {
			t.Errorf("%s: %d connection(s) still held by the transaction", what, n)
		}
	}

	if err := st.WithPgxTx(ctx, func(tx pgx.Tx, _ *storegen.Queries) error { insert(tx, 1); return nil }); err != nil {
		t.Fatalf("a function that returns nil: %v", err)
	}
	if n := marks(); n != 1 {
		t.Fatalf("rows after a committed transaction = %d, want 1", n)
	}
	released("after a commit")

	boom := errors.New("boom")
	if err := st.WithPgxTx(ctx, func(tx pgx.Tx, _ *storegen.Queries) error { insert(tx, 2); return boom }); err != boom {
		t.Fatalf("a function that fails returned %v, want its own error", err)
	}
	if n := marks(); n != 1 {
		t.Fatalf("rows after a failed transaction = %d, want 1 (the failed one rolled back)", n)
	}
	released("after an error")

	func() {
		defer func() {
			if r := recover(); r != "kaboom" {
				t.Fatalf("recovered %v, want the function's panic passed on", r)
			}
		}()
		_ = st.WithPgxTx(ctx, func(tx pgx.Tx, _ *storegen.Queries) error { insert(tx, 3); panic("kaboom") })
	}()
	if n := marks(); n != 1 {
		t.Fatalf("rows after a panicking transaction = %d, want 1", n)
	}
	released("after a panic")

	// WithTx is the same transaction with the queries only.
	var calls int
	if err := st.WithTx(ctx, func(*storegen.Queries) error { calls++; return boom }); err != boom || calls != 1 {
		t.Fatalf("WithTx with a failing function: %v after %d call(s), want its error after one", err, calls)
	}
	if err := st.WithTx(ctx, func(*storegen.Queries) error { calls++; return nil }); err != nil || calls != 2 {
		t.Fatalf("WithTx: %v after %d call(s), want nil after the function ran once more", err, calls)
	}
	released("after WithTx")

	// The queries handed to the function run inside the transaction: the
	// server's time in them is the transaction's own, not a later statement's.
	if err := st.WithPgxTx(ctx, func(tx pgx.Tx, q *storegen.Queries) error {
		var inTx time.Time
		if err := tx.QueryRow(ctx, `SELECT now()`).Scan(&inTx); err != nil {
			return err
		}
		viaQueries, err := q.Now(ctx)
		if err != nil {
			return err
		}
		if !viaQueries.Equal(inTx) {
			t.Errorf("queries saw the server's time as %v, the transaction as %v: they did not run in it", viaQueries, inTx)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// A commit the server refuses (the deferred uniqueness is checked then).
	if err := st.WithPgxTx(ctx, func(tx pgx.Tx, _ *storegen.Queries) error { insert(tx, 7, 7); return nil }); err == nil || !strings.Contains(err.Error(), "store: commit") {
		t.Fatalf("a transaction the server refuses at commit returned %v, want a commit error", err)
	}
	if n := marks(); n != 1 {
		t.Fatalf("rows after a refused commit = %d, want 1", n)
	}
	released("after a refused commit")

	// A store that cannot begin a transaction says so and runs nothing.
	closed, err := Connect(ctx, txURL)
	if err != nil {
		t.Fatal(err)
	}
	closed.Close()
	ran := false
	if err := closed.WithTx(ctx, func(*storegen.Queries) error { ran = true; return nil }); err == nil || !strings.Contains(err.Error(), "store: begin") || ran {
		t.Fatalf("WithTx on a closed store: %v (ran=%v), want a begin error and no call", err, ran)
	}
}

// TestMigrateConcurrentFreshDatabase pins Migrate's doc promise: N migrators
// racing at a database that has never been migrated must all succeed. Without
// the advisory lock the run races through goose's version-table bootstrap
// and all but one fail inside the first migrations with duplicate pg_type
// rows. That is what every multi-replica first boot does when migrateOnStart
// is set, and what `go test ./...` does to a fresh shared test database.
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
	// A database that was empty ends at exactly the newest core migration,
	// with River's own tables migrated to River's newest version.
	if newest := newestMigration(t); ver != newest {
		t.Fatalf("migration version %d after the concurrent run, want the newest embedded migration, %d", ver, newest)
	}
	pool, err := pgxpool.New(ctx, scratchURL)
	if err != nil {
		t.Fatalf("pool (river check): %v", err)
	}
	defer pool.Close()
	river, err := rivermigrate.New(riverpgxv5.New(pool), nil)
	if err != nil {
		t.Fatal(err)
	}
	all := river.AllVersions()
	var riverMax, riverRows int
	if err := pool.QueryRow(ctx, `SELECT coalesce(max(version), 0), count(*) FROM river_migration WHERE line = 'main'`).Scan(&riverMax, &riverRows); err != nil {
		t.Fatalf("river_migration: %v", err)
	}
	if riverMax != all[len(all)-1].Version || riverRows != len(all) {
		t.Fatalf("River migrated to version %d in %d step(s), want %d in %d", riverMax, riverRows, all[len(all)-1].Version, len(all))
	}
	for _, table := range []string{"river_job", "river_leader", "river_queue", "river_migration"} {
		var found *string
		if err := pool.QueryRow(ctx, `SELECT to_regclass($1)::text`, "public."+table).Scan(&found); err != nil || found == nil {
			t.Errorf("table %s missing after the concurrent run (%v)", table, err)
		}
	}

	// Migrators in other processes serialize on the database's migration
	// lock, which this process's mutex cannot stand in for: one that
	// is holding it keeps a migrator waiting until it lets go.
	release := holdAdvisoryLock(t, scratchURL, migrateLockID)
	short, cancelShort := context.WithTimeout(ctx, 3*time.Second)
	err = Migrate(short, scratchURL)
	cancelShort()
	if err == nil || !strings.Contains(err.Error(), "advisory lock") {
		t.Fatalf("Migrate while another session held the migration lock: %v, want it to wait and fail at the lock", err)
	}
	release()
	if err := Migrate(ctx, scratchURL); err != nil {
		t.Fatalf("Migrate once the lock was free: %v", err)
	}
}
