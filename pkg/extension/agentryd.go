// agentryd is the Agentry server binary: a modular monolith whose role is
// selected at start (D-02): `agentryd api|git|worker|all`.
// The agentryd entry point, parameterised by extensions (DEV-091): the
// core build is Main() with none, a closed build is Main(theirs...).
package extension

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"slices"
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

// Main runs agentryd with the given extensions: the `api | git | worker |
// all` roles, `migrate`, and the git hook shim.
func Main(exts ...Extension) {
	if err := rootCmd(exts).Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func rootCmd(exts []Extension) *cobra.Command {
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
		var queues string
		cmd := &cobra.Command{
			Use:   role,
			Short: "run the " + role + " role",
			RunE: func(cmd *cobra.Command, _ []string) error {
				qs, err := parseQueues(queues)
				if err != nil {
					return err
				}
				return RunWith(cmd.Context(), cfgPath, role, Options{Queues: qs}, exts...)
			},
		}
		if role == "worker" {
			// The §13.3 SaaS split runs the sandbox queue on its own task
			// profile (no egress); a worker deployment names the queue it
			// drains. The default drains both, the self-host shape.
			cmd.Flags().StringVar(&queues, "queues", "", "comma-separated queues to drain: core, sandbox (default: both)")
		}
		root.AddCommand(cmd)
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
			if err := store.Migrate(cmd.Context(), cfg.Database.URL); err != nil {
				return err
			}
			return migrateExtensions(cmd.Context(), cfg.Database.URL, exts)
		},
	})

	return root
}

// Run is one role of agentryd until ctx ends.
func Run(ctx context.Context, cfgPath, role string, exts ...Extension) error {
	return RunWith(ctx, cfgPath, role, Options{}, exts...)
}

// Options are the per-invocation choices a role takes beside its config.
type Options struct {
	// Queues are the queues a worker drains (core, sandbox); nil means both.
	Queues []string
}

// parseQueues reads the worker's --queues flag: a comma-separated subset of
// the queues that exist. A name that is not a queue — "judge" among them,
// since S5 runs inside the scan DAG and has no queue of its own — is an
// error rather than a worker that drains nothing.
func parseQueues(flag string) ([]string, error) {
	if strings.TrimSpace(flag) == "" {
		return nil, nil
	}
	var out []string
	seen := map[string]bool{}
	for _, part := range strings.Split(flag, ",") {
		q := strings.TrimSpace(part)
		if q == "" {
			continue
		}
		if !slices.Contains(workerQueues, q) {
			return nil, fmt.Errorf("--queues: %q is not a queue (the queues are %s)", q, strings.Join(workerQueues, ", "))
		}
		if !seen[q] {
			seen[q] = true
			out = append(out, q)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("--queues names no queue")
	}
	return out, nil
}

// RunWith is Run with Options.
func RunWith(ctx context.Context, cfgPath, role string, opts Options, exts ...Extension) error {
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
		} else if err := migrateExtensions(ctx, cfg.Database.URL, exts); err != nil {
			if cfg.Env == "dev" {
				log.Warn("extension migrations skipped", "err", err)
			} else {
				return fmt.Errorf("extension migrations on start: %w", err)
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
		return serveHTTP(ctx, cfg, st, log, role, mx, exts)
	case "worker":
		return runWorker(ctx, cfg, st, log, mx, exts, opts.Queues)
	default:
		return fmt.Errorf("unknown role %q", role)
	}
}

// runWorker runs the async scan/notification worker (§8.2, §13.3). It wires
// the pipeline's job handlers onto the Postgres queue and works the sandbox
// and core queues until the context is cancelled.
func runWorker(ctx context.Context, cfg config.Config, st *store.Store, log *slog.Logger, mx *metrics.Metrics, exts []Extension, queues []string) error {
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
	applyExtensions(srv, exts)
	defer func() { _ = srv.Close() }()
	q, err := newWorkerQueue(ctx, cfg, srv, st, log, mx, exts)
	if err != nil {
		return err
	}

	// Queues: "core" (webhooks, audit exports, reconcile) and "sandbox"
	// (scans — §8.2's untrusted-content task profile). There is no "judge"
	// queue: S5 runs inside the orchestrator's DAG, and §8.4's separate task
	// profile for it is a deployment boundary, not a second queue. Working a
	// queue nothing enqueues to only burns claim attempts. --queues narrows
	// the set for the split deployment (§13.3).
	if len(queues) == 0 {
		queues = workerQueues
	}
	log.Info("worker started", "queues", strings.Join(queues, ","))
	return q.Work(ctx, queues...)
}

// workerQueues are the queues a worker drains.
var workerQueues = []string{"core", "sandbox"}

// newWorkerQueue registers every async handler on a queue client and starts
// the §7 watchdog ticker. Shared by the `worker` role and by `all`, so the
// single-process shape runs exactly the handler set the split shape does.
func newWorkerQueue(ctx context.Context, cfg config.Config, srv *api.Server, st *store.Store, log *slog.Logger, mx *metrics.Metrics, exts []Extension) (queue.Worker, error) {
	pipeline := srv.Pipeline()
	if pipeline == nil {
		return nil, fmt.Errorf("the worker role requires archive storage (storage.kind=%q has none wired)", cfg.Storage.Kind)
	}
	// A worker that shares the git data directory (compose `all`, EFS in
	// ECS) can scan git history for secrets; one that does not simply
	// reports S2/history-not-scanned (agentry#54).
	repos, rerr := gitsrv.NewRepoStore(cfg)
	if rerr == nil {
		pipeline.SetGitHistory(repos)
	} else {
		log.Warn("worker: git history scan unavailable", "err", rerr)
		repos = nil
	}

	q, qerr := queue.Open(cfg.Queue.Driver, cfg.Queue.Workers, st, log)
	if qerr != nil {
		return nil, qerr
	}
	q.SetMetrics(mx, cfg.Telemetry.QueueSampleInterval)
	pipeline.RegisterHandlers(q)
	// repo.pushed bookkeeping (§6.3, agentry#43): size when this role can
	// see the repositories, last_push_at + audit either way.
	gitsrv.NewPushBookkeeper(st, repos, audit.NewWriter(log), log).Register(q)
	// Enterprise async handlers (M6/WG-J): webhook delivery (§9.3) and audit
	// export (§12.6).
	srv.RegisterQueueHandlers(q)
	// Extension jobs (DEV-091), on the queue each names; a periodic one is
	// enqueued on its period like the core's own tickers (agentry#324).
	for _, e := range exts {
		for _, j := range e.Jobs() {
			q.Register(j.Kind, j.Handler)
			if j.Every > 0 {
				go periodicTicker(ctx, q, j.Kind, j.Queue, j.Every, log)
			}
		}
	}

	// §7 watchdog. Enqueued rather than called inline so that across worker
	// replicas exactly one runs it per interval (SKIP LOCKED), and so an
	// operator can trigger a reconcile by hand.
	go reconcileTicker(ctx, q, log)
	go mcpSweepTicker(ctx, q, log)
	return q, nil
}

// auditWriterFunc adapts the server's audit closure to AuditWriter.
type auditWriterFunc func(context.Context, audit.Event) error

func (f auditWriterFunc) Write(ctx context.Context, e audit.Event) error { return f(ctx, e) }

// periodicTicker enqueues an extension's periodic job once now and then on
// its period; the queue's SKIP LOCKED claim makes one replica run each.
func periodicTicker(ctx context.Context, q queue.Client, kind, queueName string, every time.Duration, log *slog.Logger) {
	if queueName == "" {
		queueName = "core"
	}
	enqueue := func() {
		if _, err := q.Enqueue(ctx, kind, queueName, struct{}{}); err != nil {
			log.Error("worker: enqueue extension job", "kind", kind, "err", err)
		}
	}
	enqueue()
	t := time.NewTicker(every)
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

// mcpSweepWindow is how often the MCP server vulnerability sweep is
// enqueued (agentry#177): daily, and once shortly after start-up so a
// worker that was down for a day catches up; the handler re-checks only
// rows older than its own threshold, so an early run is cheap.
const mcpSweepWindow = 24 * time.Hour

func mcpSweepTicker(ctx context.Context, q queue.Client, log *slog.Logger) {
	enqueue := func() {
		if _, err := q.Enqueue(ctx, scan.JobMCPSweep, "core", struct{}{}); err != nil {
			log.Error("worker: enqueue mcp sweep", "err", err)
		}
	}
	select {
	case <-ctx.Done():
		return
	case <-time.After(time.Minute):
		enqueue()
	}
	t := time.NewTicker(mcpSweepWindow)
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

func serveHTTP(ctx context.Context, cfg config.Config, st *store.Store, log *slog.Logger, role string, mx *metrics.Metrics, exts []Extension) error {
	handler, closeHandler, err := buildHandler(ctx, cfg, st, log, role, mx, exts)
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
func buildHandler(ctx context.Context, cfg config.Config, st *store.Store, log *slog.Logger, role string, mx *metrics.Metrics, exts []Extension) (http.Handler, func() error, error) {
	switch role {
	case "api":
		s := api.New(cfg, st, log)
		s.SetMetrics(mx)
		applyExtensions(s, exts)
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
		applyExtensions(s, exts)
		reg := s.Reg()
		reg.SetGitArchiver(repos)
		if pl := s.Pipeline(); pl != nil {
			pl.SetGitHistory(repos) // S2 history scan on git-tag publishes (agentry#54)
		}
		aud := audit.NewWriter(log)
		git := gitsrv.NewHandler(cfg, st, repos, reg, aud, log)
		git.SetMetrics(mx)
		// Push bookkeeping rides the queue as repo.pushed (§6.3, agentry#43);
		// the worker (in-process for `all`) runs it.
		gq, qerr := queue.Open(cfg.Queue.Driver, cfg.Queue.Workers, st, log)
		if qerr != nil {
			return nil, nil, qerr
		}
		git.SetQueue(gq)
		closeAll := func() error { return errors.Join(git.Close(), s.Close()) }
		// The SSH transport (§6.1 Q7, agentry#70) rides beside smart HTTP
		// when configured; same handler, same authorization and hooks.
		if cfg.Git.SSHAddr != "" {
			sshSrv, err := git.NewSSHServer(cfg.Git.SSHAddr, cfg.Git.SSHHostKeyFile)
			if err != nil {
				return nil, nil, err
			}
			log.Info("git ssh listening", "addr", sshSrv.Addr().String(), "hostkey", sshSrv.HostKeyFingerprint())
			go func() {
				if err := sshSrv.Serve(ctx); err != nil {
					log.Error("git ssh server", "err", err)
				}
			}()
			httpClose := closeAll
			closeAll = func() error { return errors.Join(sshSrv.Close(), httpClose()) }
		}
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
		q, err := newWorkerQueue(ctx, cfg, s, st, log, mx, exts)
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

// applyExtensions wires what an extension adds to a server: its routes,
// its entitlements resolver, its hooks. Jobs are the worker's
// (newWorkerQueue) and migrations run before the server exists
// (migrateExtensions).
func applyExtensions(srv *api.Server, exts []Extension) {
	for _, e := range exts {
		if b, ok := e.(Binds); ok {
			pool, log, write := srv.ExtensionDeps()
			b.Bind(Deps{DB: pool, Log: log.With("extension", e.Name()), Audit: auditWriterFunc(write)})
		}
		srv.RegisterExtension(e.Name(), e.Routes)
		if u, ok := e.(Unthrottles); ok {
			srv.SetExtensionUnthrottled(e.Name(), u.UnthrottledRoutes())
		}
		if r := e.Entitlements(); r != nil {
			srv.SetEntitlements(r)
		}
		if a, ok := e.(Admits); ok {
			if adm := a.Admitter(); adm != nil {
				srv.Reg().SetAdmitter(adm)
			}
		}
		if h := e.Hooks().Event; h != nil {
			srv.AddEventHook(h)
		}
	}
}

// migrateExtensions applies each extension's migrations after the core's.
func migrateExtensions(ctx context.Context, databaseURL string, exts []Extension) error {
	for _, e := range exts {
		fsys := e.Migrations()
		if fsys == nil {
			continue
		}
		if err := store.MigrateExtension(ctx, databaseURL, e.Name(), fsys); err != nil {
			return err
		}
	}
	return nil
}
