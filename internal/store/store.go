// Package store owns PostgreSQL access: the pgx pool, goose migrations, and
// sqlc-generated typed queries. All SQL lives here; no other package builds
// SQL strings.
package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"hash/fnv"
	"io/fs"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivermigrate"

	storegen "github.com/blaktron/agentry/internal/store/gen"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Store wraps the connection pool. Domain packages depend on Store, never on
// pgx directly, so the tenancy helpers have one place to live.
type Store struct {
	pool *pgxpool.Pool
}

// Connect opens a pgx pool and verifies connectivity.
func Connect(ctx context.Context, databaseURL string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("store: parse database url: %w", err)
	}
	cfg.MaxConnLifetime = time.Hour
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("store: connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: ping: %w", err)
	}
	return &Store{pool: pool}, nil
}

// Pool exposes the underlying pool for sqlc-generated code and tests.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// Queries returns the sqlc query layer bound to the pool.
func (s *Store) Queries() *storegen.Queries { return storegen.New(s.pool) }

// WithTx runs fn inside a transaction, passing transaction-bound queries.
// Commit on nil, rollback on error or panic.
func (s *Store) WithTx(ctx context.Context, fn func(q *storegen.Queries) error) error {
	return s.WithPgxTx(ctx, func(_ pgx.Tx, q *storegen.Queries) error { return fn(q) })
}

// WithPgxTx is WithTx that also hands fn the transaction itself, for a step
// that is not a generated query: an extension's own writes in the core's
// erasure (pkg/extension.ErasesAccounts).
func (s *Store) WithPgxTx(ctx context.Context, fn func(tx pgx.Tx, q *storegen.Queries) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := fn(tx, storegen.New(tx)); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}
	return nil
}

// Ping verifies database connectivity (readyz).
func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

// Close releases the pool.
func (s *Store) Close() { s.pool.Close() }

// migrateMu serializes Migrate within a process. goose.SetBaseFS /
// SetDialect below mutate package-global state in goose, so two in-process
// migrators are unsafe even with a database-level lock.
var migrateMu sync.Mutex

// migrateLockID is the advisory lock under which migrations run. Any stable
// int64 works; it only has to be the same across every process that migrates
// this schema. Session-scoped: closing the connection releases it.
const migrateLockID int64 = 0xA6E7_2710 // "agentry migrate"

// Migrate runs all pending goose migrations from the embedded FS.
// Safe to run concurrently within a process (migrateMu) and across
// processes/instances (a Postgres session advisory lock held for the whole
// run): waiters block until the leader finishes, then observe an up-to-date
// schema and no-op. This matters at first boot — api, git and worker
// replicas all start with migrateOnStart — and for test binaries sharing one
// database. Locking lives here, not in goose, because goose's own lock does
// not cover the version-table bootstrap: on a fresh database two concurrent
// migrators raced through it and collided inside the first migrations.
func Migrate(ctx context.Context, databaseURL string) error {
	migrateMu.Lock()
	defer migrateMu.Unlock()

	db, err := connectStd(databaseURL)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	// One connection so the advisory lock, the migrations and the unlock all
	// share the session that holds the lock.
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, "SELECT pg_advisory_lock($1)", migrateLockID); err != nil {
		return fmt.Errorf("store: migrate: advisory lock: %w", err)
	}
	defer func() {
		// The ctx may be done by now (that is why the run failed); the pool
		// close below releases the lock regardless, so ignore errors here.
		_, _ = db.ExecContext(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock($1)", migrateLockID)
	}()

	goose.SetBaseFS(migrationsFS)
	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("store: goose dialect: %w", err)
	}
	if err := goose.UpContext(ctx, db, "migrations"); err != nil {
		return fmt.Errorf("store: migrate: %w", err)
	}
	// River's own tables and version table (river_job, river_queue,
	// river_leader, river_client, river_migration). Under the same
	// advisory lock; River's migrator runs on its own pgx connection
	// because it speaks the pgx driver, not database/sql.
	return migrateRiver(ctx, databaseURL)
}

func migrateRiver(ctx context.Context, databaseURL string) error {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return fmt.Errorf("store: river migrate: pool: %w", err)
	}
	defer pool.Close()
	m, err := rivermigrate.New(riverpgxv5.New(pool), &rivermigrate.Config{Logger: slog.Default()})
	if err != nil {
		return fmt.Errorf("store: river migrate: %w", err)
	}
	if _, err := m.Migrate(ctx, rivermigrate.DirectionUp, nil); err != nil {
		return fmt.Errorf("store: river migrate: %w", err)
	}
	return nil
}

// MigrateExtension runs an extension's goose migrations (pkg/extension)
// under the extension's own version table
// (ent_<name>_goose_version), so the core's numbering and an extension's
// never collide; the SQL owns its schema (CREATE SCHEMA IF NOT EXISTS
// ent_<name>). Same in-process mutex as Migrate and a per-extension
// advisory lock, for the same reasons.
func MigrateExtension(ctx context.Context, databaseURL, name string, fsys fs.FS) error {
	migrateMu.Lock()
	defer migrateMu.Unlock()

	db, err := connectStd(databaseURL)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(1)
	h := fnv.New64a()
	_, _ = h.Write([]byte(name))
	lockID := migrateLockID ^ int64(h.Sum64()&0x7fffffff)
	if _, err := db.ExecContext(ctx, "SELECT pg_advisory_lock($1)", lockID); err != nil {
		return fmt.Errorf("store: migrate %s: advisory lock: %w", name, err)
	}
	defer func() {
		_, _ = db.ExecContext(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock($1)", lockID)
	}()

	goose.SetBaseFS(fsys)
	defer goose.SetBaseFS(migrationsFS)
	goose.SetTableName("ent_" + strings.ReplaceAll(name, "-", "_") + "_goose_version")
	defer goose.SetTableName("goose_db_version")
	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("store: goose dialect: %w", err)
	}
	if err := goose.UpContext(ctx, db, "."); err != nil {
		return fmt.Errorf("store: migrate %s: %w", name, err)
	}
	return nil
}

// MigrationStatus returns the current goose version (diagnostics).
func MigrationStatus(ctx context.Context, databaseURL string) (int64, error) {
	db, err := connectStd(databaseURL)
	if err != nil {
		return 0, err
	}
	defer func() { _ = db.Close() }()
	goose.SetBaseFS(migrationsFS)
	if err := goose.SetDialect("postgres"); err != nil {
		return 0, err
	}
	return goose.GetDBVersionContext(ctx, db)
}

// connectStd opens a database/sql handle for goose (which requires *sql.DB),
// keeping that dependency confined to this file.
func connectStd(databaseURL string) (*sql.DB, error) {
	cfg, err := pgx.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("store: parse database url: %w", err)
	}
	return stdlib.OpenDB(*cfg), nil
}
