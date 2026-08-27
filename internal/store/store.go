// Package store owns PostgreSQL access: the pgx pool, goose migrations, and
// (from M1) sqlc-generated typed queries. All SQL lives here (D-04); no other
// package builds SQL strings.
package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Store wraps the connection pool. Domain packages depend on Store, never on
// pgx directly, so the tenancy helpers (D-24) have one place to live.
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

// Ping verifies database connectivity (readyz).
func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

// Close releases the pool.
func (s *Store) Close() { s.pool.Close() }

// Migrate runs all pending goose migrations from the embedded FS.
// Safe to run concurrently across instances: goose takes a session lock.
func Migrate(ctx context.Context, databaseURL string) error {
	db, err := connectStd(databaseURL)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	goose.SetBaseFS(migrationsFS)
	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("store: goose dialect: %w", err)
	}
	if err := goose.UpContext(ctx, db, "migrations"); err != nil {
		return fmt.Errorf("store: migrate: %w", err)
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
