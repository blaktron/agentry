// agentryd is the Agentry server binary: a modular monolith whose role is
// selected at start (D-02): `agentryd api|git|worker|all`.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/PLACEHOLDER_ORG/agentry/internal/api"
	"github.com/PLACEHOLDER_ORG/agentry/internal/config"
	"github.com/PLACEHOLDER_ORG/agentry/internal/store"
	"github.com/PLACEHOLDER_ORG/agentry/internal/version"
)

func main() {
	if err := rootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	var cfgPath string

	root := &cobra.Command{
		Use:           "agentryd",
		Short:         "Agentry server (api | git | worker | all)",
		Version:       version.Version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&cfgPath, "config", "", "path to agentry.yaml (default: $AGENTRY_CONFIG or ./agentry.yaml)")

	for _, role := range []string{"api", "git", "worker", "all"} {
		role := role
		root.AddCommand(&cobra.Command{
			Use:   role,
			Short: "run the " + role + " role",
			RunE: func(cmd *cobra.Command, _ []string) error {
				return run(cmd.Context(), cfgPath, role)
			},
		})
	}

	root.AddCommand(&cobra.Command{
		Use:   "migrate",
		Short: "run database migrations and exit",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(cfgPath)
			if err != nil {
				return err
			}
			return store.Migrate(cmd.Context(), cfg.Database.URL)
		},
	})

	return root
}

func run(ctx context.Context, cfgPath, role string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	log := newLogger(cfg.Log.Level)
	log.Info("starting agentryd", "role", role, "version", version.Version, "env", cfg.Env)

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Database: required for prod roles; the api role tolerates absence in
	// dev so `agentryd api` works before `make db-up` (readyz reports it).
	var st *store.Store
	if cfg.Database.MigrateOnStart {
		if err := store.Migrate(ctx, cfg.Database.URL); err != nil {
			if cfg.Env == "dev" {
				log.Warn("migrations skipped (database unreachable in dev)", "err", err)
			} else {
				return fmt.Errorf("migrate on start: %w", err)
			}
		}
	}
	st, err = store.Connect(ctx, cfg.Database.URL)
	if err != nil {
		if cfg.Env == "dev" {
			log.Warn("running without database (dev only)", "err", err)
			st = nil
		} else {
			return err
		}
	}
	if st != nil {
		defer st.Close()
	}

	switch role {
	case "api", "all":
		return serveHTTP(ctx, cfg, st, log, role)
	case "git":
		// M2 (WG-C) mounts the smart-HTTP handler here.
		return errors.New("git role: not implemented until M2 (WG-C)")
	case "worker":
		// M4 (WG-H) mounts queue workers here.
		return errors.New("worker role: not implemented until M4 (WG-H)")
	default:
		return fmt.Errorf("unknown role %q", role)
	}
}

func serveHTTP(ctx context.Context, cfg config.Config, st *store.Store, log *slog.Logger, role string) error {
	s := api.New(cfg, st, log)
	srv := &http.Server{
		Addr:              cfg.HTTP.Addr,
		Handler:           api.NewHandler(s),
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("http listening", "addr", cfg.HTTP.Addr, "role", role)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		log.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
	slog.SetDefault(log)
	return log
}
