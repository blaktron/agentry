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

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/PLACEHOLDER_ORG/agentry/internal/api"
	"github.com/PLACEHOLDER_ORG/agentry/internal/audit"
	"github.com/PLACEHOLDER_ORG/agentry/internal/config"
	"github.com/PLACEHOLDER_ORG/agentry/internal/gitsrv"
	"github.com/PLACEHOLDER_ORG/agentry/internal/queue"
	"github.com/PLACEHOLDER_ORG/agentry/internal/registry"
	"github.com/PLACEHOLDER_ORG/agentry/internal/scan"
	"github.com/PLACEHOLDER_ORG/agentry/internal/scan/ruleset"
	"github.com/PLACEHOLDER_ORG/agentry/internal/store"
	storegen "github.com/PLACEHOLDER_ORG/agentry/internal/store/gen"
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

	root.AddCommand(hookCmd())

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
	case "api", "git", "all":
		return serveHTTP(ctx, cfg, st, log, role)
	case "worker":
		return runWorker(ctx, cfg, st, log)
	default:
		return fmt.Errorf("unknown role %q", role)
	}
}

// runWorker runs the async scan/notification worker (§8.2, §13.3). It wires
// the pipeline's job handlers onto the Postgres queue and works the sandbox
// and core queues until the context is cancelled.
func runWorker(ctx context.Context, cfg config.Config, st *store.Store, log *slog.Logger) error {
	if st == nil {
		return errors.New("the worker role requires a database")
	}
	bundle, err := ruleset.Load()
	if err != nil {
		return err
	}
	blobs, err := registry.NewLocalFS(cfg.Storage.LocalDir)
	if err != nil {
		return err
	}
	aud := audit.NewWriter(log)
	reg := registry.NewService(st, aud)
	reg.SetBlobStore(blobs)
	signer, err := scan.NewSigner(cfg.Signing.Kind, cfg.Signing.KeyFile, cfg.DevMode)
	if err != nil {
		return err
	}
	judge := scan.NewJudgeProvider(cfg.Judge.Provider)
	orch := scan.NewOrchestrator(bundle, judge, log)

	rulesetID, _ := uuid.NewV7()
	if row, rerr := st.Queries().CreateRulesetRelease(ctx, storegen.CreateRulesetReleaseParams{
		ID: rulesetID, Semver: bundle.Version(), BundleDigest: bundle.Digest(),
	}); rerr == nil {
		rulesetID = row.ID
	}
	pipeline := scan.NewPipeline(scan.PipelineDeps{
		Store: st, Registry: reg, Blobs: blobs, Orchestrator: orch, Signer: signer,
		Audit: aud, Log: log, RegistryURL: cfg.BaseURL, RulesetID: rulesetID, RulesetVer: bundle.Version(),
	})
	q := queue.NewPGClient(st, log)
	pipeline.RegisterHandlers(q)
	// Enterprise async handlers (M6/WG-J): webhook delivery (§9.3) and audit
	// export (§12.6). An api.Server assembles the same dependencies; we borrow
	// it only to register its queue handlers.
	api.New(cfg, st, log).RegisterQueueHandlers(q)
	log.Info("worker started", "queues", "core,sandbox")
	return q.Work(ctx, "core", "sandbox", "judge")
}

func serveHTTP(ctx context.Context, cfg config.Config, st *store.Store, log *slog.Logger, role string) error {
	handler, err := buildHandler(cfg, st, log, role)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Addr:              cfg.HTTP.Addr,
		Handler:           handler,
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

// buildHandler assembles the HTTP surface for a role: api routes, git
// smart-HTTP routes, or both (`all`, the self-host default).
func buildHandler(cfg config.Config, st *store.Store, log *slog.Logger, role string) (http.Handler, error) {
	switch role {
	case "api":
		return api.NewHandler(api.New(cfg, st, log)), nil
	case "git", "all":
		if st == nil {
			return nil, errors.New("the git role requires a database")
		}
		repos, err := gitsrv.NewRepoStore(cfg)
		if err != nil {
			return nil, err
		}
		s := api.New(cfg, st, log)
		reg := s.Reg()
		reg.SetGitArchiver(repos)
		aud := audit.NewWriter(log)
		git := gitsrv.NewHandler(cfg, st, repos, reg, aud, log)
		if role == "git" {
			mux := http.NewServeMux()
			mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"status":"ok"}`))
			})
			git.Mount(mux)
			return mux, nil
		}
		return api.NewHandlerWithGit(s, git.Mount), nil
	default:
		return nil, fmt.Errorf("unknown http role %q", role)
	}
}

// hookCmd implements the git hook shim (`agentryd hook pre-receive`),
// invoked by git inside bare repos (§6.3).
func hookCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "hook", Hidden: true, Short: "git hook shims (invoked by git)"}
	cmd.AddCommand(&cobra.Command{
		Use: "pre-receive",
		RunE: func(_ *cobra.Command, _ []string) error {
			if code := gitsrv.RunPreReceiveHook(os.Stdin, os.Stderr); code != 0 {
				os.Exit(code)
			}
			return nil
		},
	})
	return cmd
}
