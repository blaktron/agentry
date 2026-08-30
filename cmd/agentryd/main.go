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
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/gitsrv"
	"github.com/blaktron/agentry/internal/metrics"
	"github.com/blaktron/agentry/internal/queue"
	"github.com/blaktron/agentry/internal/scan"
	"github.com/blaktron/agentry/internal/store"
	"github.com/blaktron/agentry/internal/version"
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

	// §16.2 telemetry. OTLP export is opt-in (AGENTRY_OTEL_ENDPOINT); the
	// Prometheus /metrics endpoint is always on (D-25), so a self-hosted
	// instance is never dark even without a collector.
	mx, err := metrics.New(ctx, metrics.Config{
		OTLPEndpoint:   cfg.Telemetry.OTLPEndpoint,
		ServiceName:    "agentryd",
		ServiceVersion: version.Version,
		Role:           role,
		Env:            cfg.Env,
		ExportInterval: cfg.Telemetry.ExportInterval,
	})
	if err != nil {
		return fmt.Errorf("telemetry: %w", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := mx.Shutdown(shutdownCtx); err != nil {
			log.Warn("telemetry shutdown", "err", err)
		}
	}()
	if cfg.Telemetry.OTLPEndpoint != "" {
		log.Info("otlp metrics enabled", "endpoint", cfg.Telemetry.OTLPEndpoint)
	}

	switch role {
	case "api", "git", "all":
		return serveHTTP(ctx, cfg, st, log, role, mx)
	case "worker":
		return runWorker(ctx, cfg, st, log, mx)
	default:
		return fmt.Errorf("unknown role %q", role)
	}
}

// runWorker runs the async scan/notification worker (§8.2, §13.3). It wires
// the pipeline's job handlers onto the Postgres queue and works the sandbox
// and core queues until the context is cancelled.
func runWorker(ctx context.Context, cfg config.Config, st *store.Store, log *slog.Logger, mx *metrics.Metrics) error {
	if st == nil {
		return errors.New("the worker role requires a database")
	}
	// One assembly site for the pipeline, shared with the api role. The worker
	// used to build its own registry service and its own ruleset registration:
	// the two copies had already drifted, and the worker's registry had NO
	// event sink, so every rescan-driven agent.quarantined webhook — the
	// notification path §8.7 relies on — was dropped on the floor.
	srv := api.New(cfg, st, log)
	srv.SetMetrics(mx)
	defer func() { _ = srv.Close() }()
	q, err := newWorkerQueue(ctx, cfg, srv, st, log, mx)
	if err != nil {
		return err
	}

	// Queues: "core" (webhooks, audit exports, reconcile) and "sandbox"
	// (scans — §8.2's untrusted-content task profile). There is no "judge"
	// queue: S5 runs inside the orchestrator's DAG, and §8.4's separate task
	// profile for it is a deployment boundary, not a second queue. Working a
	// queue nothing enqueues to only burns claim attempts.
	log.Info("worker started", "queues", "core,sandbox")
	return q.Work(ctx, workerQueues...)
}

// workerQueues are the queues a worker drains.
var workerQueues = []string{"core", "sandbox"}

// newWorkerQueue registers every async handler on a queue client and starts
// the §7 watchdog ticker. Shared by the `worker` role and by `all`, so the
// single-process shape runs exactly the handler set the split shape does.
func newWorkerQueue(ctx context.Context, cfg config.Config, srv *api.Server, st *store.Store, log *slog.Logger, mx *metrics.Metrics) (*queue.PGClient, error) {
	pipeline := srv.Pipeline()
	if pipeline == nil {
		return nil, fmt.Errorf("the worker role requires archive storage (storage.kind=%q has none wired)", cfg.Storage.Kind)
	}
	q := queue.NewPGClient(st, log)
	q.SetMetrics(mx, cfg.Telemetry.QueueSampleInterval)
	pipeline.RegisterHandlers(q)
	// Enterprise async handlers (M6/WG-J): webhook delivery (§9.3) and audit
	// export (§12.6).
	srv.RegisterQueueHandlers(q)

	// §7 watchdog. Enqueued rather than called inline so that across worker
	// replicas exactly one runs it per interval (SKIP LOCKED), and so an
	// operator can trigger a reconcile by hand.
	go reconcileTicker(ctx, q, log)
	return q, nil
}

// reconcileWindow is how often the watchdog job is enqueued. Versions become
// eligible at the §7 30-minute cap, so checking every few minutes is prompt
// without being chatty.
const reconcileWindow = 5 * time.Minute

func reconcileTicker(ctx context.Context, q queue.Client, log *slog.Logger) {
	enqueue := func() {
		if _, err := q.Enqueue(ctx, scan.JobScanReconcile, "core", struct{}{}); err != nil {
			log.Error("worker: enqueue scan reconcile", "err", err)
		}
	}
	enqueue()
	t := time.NewTicker(reconcileWindow)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			enqueue()
		}
	}
}

func serveHTTP(ctx context.Context, cfg config.Config, st *store.Store, log *slog.Logger, role string, mx *metrics.Metrics) error {
	handler, closeHandler, err := buildHandler(ctx, cfg, st, log, role, mx)
	if err != nil {
		return err
	}
	defer func() { _ = closeHandler() }()
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
// smart-HTTP routes, or both (`all`, the self-host default). The returned
// close function releases the background goroutines the handler's components
// own (rate-limit collectors, exporters).
func buildHandler(ctx context.Context, cfg config.Config, st *store.Store, log *slog.Logger, role string, mx *metrics.Metrics) (http.Handler, func() error, error) {
	switch role {
	case "api":
		s := api.New(cfg, st, log)
		s.SetMetrics(mx)
		return api.NewHandler(s), s.Close, nil
	case "git", "all":
		if st == nil {
			return nil, nil, errors.New("the git role requires a database")
		}
		repos, err := gitsrv.NewRepoStore(cfg)
		if err != nil {
			return nil, nil, err
		}
		s := api.New(cfg, st, log)
		s.SetMetrics(mx)
		reg := s.Reg()
		reg.SetGitArchiver(repos)
		aud := audit.NewWriter(log)
		git := gitsrv.NewHandler(cfg, st, repos, reg, aud, log)
		git.SetMetrics(mx)
		closeAll := func() error { return errors.Join(git.Close(), s.Close()) }
		if role == "git" {
			mux := http.NewServeMux()
			mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"status":"ok"}`))
			})
			// The git role has no /api/v1 surface, so /metrics is mounted
			// here too — a git deployment is exactly the one whose clone
			// first-byte SLI (§16.1) needs scraping.
			mux.Handle("GET /metrics", mx.Handler())
			git.Mount(mux)
			return mux, closeAll, nil
		}

		// §2.4: `all` runs EVERY role in-process. Without this the
		// single-process self-host shape started no worker at all, so webhook
		// deliveries, audit exports and queue-driven scans were enqueued and
		// never claimed — enqueued work that silently never runs is worse than
		// work that fails, because nothing reports it.
		q, err := newWorkerQueue(ctx, cfg, s, st, log, mx)
		if err != nil {
			return nil, nil, err
		}
		go func() {
			log.Info("in-process worker started", "queues", strings.Join(workerQueues, ","))
			if err := q.Work(ctx, workerQueues...); err != nil && ctx.Err() == nil {
				log.Error("in-process worker stopped", "err", err)
			}
		}()
		return api.NewHandlerWithGit(s, git.Mount), closeAll, nil
	default:
		return nil, nil, fmt.Errorf("unknown http role %q", role)
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
