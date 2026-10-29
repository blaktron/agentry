// agentryd is the Agentry server binary: a modular monolith whose role
// is selected at start: `agentryd api|git|worker|all`. The entry point
// is parameterised by extensions: the core build is Main() with none,
// an extended build is Main(theirs...).
package extension

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/blaktron/agentry/internal/api"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel/metric"
	noopmetric "go.opentelemetry.io/otel/metric/noop"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/gitsrv"
	"github.com/blaktron/agentry/internal/knowledge"
	"github.com/blaktron/agentry/internal/logx"
	"github.com/blaktron/agentry/internal/metrics"
	"github.com/blaktron/agentry/internal/queue"
	"github.com/blaktron/agentry/internal/registry"
	"github.com/blaktron/agentry/internal/scan"
	"github.com/blaktron/agentry/internal/store"
	"github.com/blaktron/agentry/internal/version"
	"github.com/blaktron/agentry/internal/voice"
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
			// The split deployment runs the sandbox queue on its own
			// task profile (no egress); a worker deployment names the
			// queue it drains. The default drains both, the self-host
			// shape.
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
	// The contract's logger (docs/logging.md): JSON on stderr, the service,
	// role and version on every line, the request id from the context,
	// tokens and secrets masked before a line is written.
	log := logx.New(logx.Options{Level: cfg.Log.Level, Service: filepath.Base(os.Args[0]), Role: role, Version: version.Version})
	slog.SetDefault(log)
	log.Info("starting agentryd", "env", cfg.Env)

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

	// Telemetry. OTLP export is opt-in (AGENTRY_OTEL_ENDPOINT); the
	// Prometheus /metrics endpoint is always on, so a self-hosted
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

// runWorker runs the async scan/notification worker. It wires the
// pipeline's job handlers onto the Postgres queue and works the sandbox
// and core queues until the context is cancelled.
func runWorker(ctx context.Context, cfg config.Config, st *store.Store, log *slog.Logger, mx *metrics.Metrics, exts []Extension, queues []string) error {
	if st == nil {
		return errors.New("the worker role requires a database")
	}
	// One assembly site for the pipeline, shared with the api role. Two
	// separate assemblies would drift: the worker's registry needs the
	// same event sink as the api role's, or every rescan-driven
	// agent.quarantined webhook is dropped.
	srv := api.New(cfg, st, log)
	srv.SetMetrics(mx)
	applyExtensions(srv, exts)
	defer func() { _ = srv.Close() }()
	staffAtStart(ctx, cfg, srv, log)
	q, err := newWorkerQueue(ctx, cfg, srv, st, log, mx, exts)
	if err != nil {
		return err
	}

	// Queues: "core" (webhooks, audit exports, reconcile) and "sandbox"
	// (scans, which run under the untrusted-content task profile).
	// There is no "judge" queue: S5 runs inside the orchestrator's DAG,
	// and a separate task profile for it is a deployment boundary, not
	// a second queue. Working a queue nothing enqueues to only burns
	// claim attempts. --queues narrows the set for the split
	// deployment.
	if len(queues) == 0 {
		queues = workerQueues
	}
	log.Info("worker started", "queues", strings.Join(queues, ","))
	return q.Work(ctx, queues...)
}

// workerQueues are the queues a worker drains.
var workerQueues = []string{"core", "sandbox"}

// newWorkerQueue registers every async handler on a queue client and
// starts the watchdog ticker. Shared by the `worker` role and by `all`,
// so the single-process shape runs exactly the handler set the split
// shape does.
func newWorkerQueue(ctx context.Context, cfg config.Config, srv *api.Server, st *store.Store, log *slog.Logger, mx *metrics.Metrics, exts []Extension) (queue.Worker, error) {
	pipeline := srv.Pipeline()
	if pipeline == nil {
		return nil, fmt.Errorf("the worker role requires archive storage (storage.kind=%q has none wired)", cfg.Storage.Kind)
	}
	// A worker that shares the git data directory (compose `all`, a
	// shared volume in a cloud deployment) can scan git history for
	// secrets; one that does not simply reports S2/history-not-scanned.
	repos, rerr := gitsrv.NewRepoStore(cfg)
	if rerr == nil {
		pipeline.SetGitHistory(repos)
		// A git role's tag submission is stored by the worker, which
		// rebuilds its archive from the repository, and a fork's
		// repository is copied here.
		srv.Reg().SetGitArchiver(repos)
		srv.Reg().SetForkRepos(repos)
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
	// repo.pushed bookkeeping: size when this role can see the
	// repositories, last_push_at + audit either way.
	gitsrv.NewPushBookkeeper(st, repos, audit.NewWriter(log), log).Register(q)
	// Enterprise async handlers: webhook delivery and audit export.
	srv.RegisterQueueHandlers(q)
	// Extension jobs, on the queue each names; a periodic one is
	// enqueued on its period like the core's own tickers. The api
	// queue's are the api role's (apiQueue).
	registerJobs(ctx, q, extensionJobs(exts, false), log)

	// Watchdog. Enqueued rather than called inline so that across
	// worker replicas exactly one runs it per interval (SKIP LOCKED),
	// and so an operator can trigger a reconcile by hand.
	go reconcileTicker(ctx, q, log)
	go mcpSweepTicker(ctx, q, log)
	// The organization decommission sweep: hourly, and once at start;
	// the handler erases only what is past its hold.
	go periodicTicker(ctx, q, api.JobOrgDecommissionSweep, "core", time.Hour, log)
	// The pending members digest: daily by default, and once at start;
	// the handler mails only what no digest has named yet.
	go periodicTicker(ctx, q, api.JobPendingMembersDigest, "core", api.PendingDigestPeriod(cfg), log)
	// Remembered browsers past their expiry: hourly, and once at start;
	// the handler deletes only what has expired.
	go periodicTicker(ctx, q, api.JobTrustedDeviceSweep, "core", time.Hour, log)
	// Writing Voice reviews left in review since their last try:
	// hourly, and once at start; a judge that could not answer is asked
	// again, never skipped.
	go periodicTicker(ctx, q, voice.JobSweep, "core", time.Hour, log)
	// Jobs River's rescuer discarded at their last attempt, without
	// calling their handler: every ten minutes, and once at start, each is
	// given that last attempt, so its handler's settling runs.
	if rc, ok := q.(*queue.RiverClient); ok {
		rc.RegisterRescueSettling()
		go periodicTicker(ctx, q, queue.JobSettleRescued, "core", 10*time.Minute, log)
	}
	// Knowledge packs left scanning by a scan never queued or a job lost:
	// hourly, and once at start; the handler queues only what has waited
	// past the stall period.
	go periodicTicker(ctx, q, knowledge.JobScanSweep, "core", time.Hour, log)
	return q, nil
}

// auditWriter adapts the server's audit closures to AuditWriter.
type auditWriter struct {
	write   func(context.Context, audit.Event) error
	writeIn func(context.Context, pgx.Tx, audit.Event) error
}

func (w auditWriter) Write(ctx context.Context, e audit.Event) error { return w.write(ctx, e) }
func (w auditWriter) WriteIn(ctx context.Context, tx pgx.Tx, e audit.Event) error {
	return w.writeIn(ctx, tx, e)
}

// orgsOf adapts the server's organization acts to Orgs: nil without a
// database, the way Deps.DB is.
func orgsOf(srv *api.Server, pool *pgxpool.Pool) Orgs {
	if pool == nil {
		return nil
	}
	return serverOrgs{srv}
}

type serverOrgs struct{ srv *api.Server }

func (o serverOrgs) Activate(ctx context.Context, orgID uuid.UUID) (bool, error) {
	return o.srv.ActivateOrg(ctx, orgID)
}

func (o serverOrgs) Decommission(ctx context.Context, orgID uuid.UUID, reason string) (bool, error) {
	return o.srv.DecommissionOrgByExtension(ctx, orgID, reason)
}

// orgGateOf adapts the server's organization gate to OrgGate: nil without
// a database, the way Deps.DB is.
func orgGateOf(srv *api.Server, pool *pgxpool.Pool) OrgGate {
	if pool == nil {
		return nil
	}
	return serverOrgGate{srv}
}

type serverOrgGate struct{ srv *api.Server }

func (g serverOrgGate) Readable(ctx context.Context, orgID uuid.UUID) (bool, error) {
	return g.srv.OrgReadable(ctx, orgID)
}

func (g serverOrgGate) Writable(ctx context.Context, orgID uuid.UUID) (bool, error) {
	return g.srv.OrgWritable(ctx, orgID)
}

// agentsOf adapts the server's agent read to Agents: nil without a
// database, the way Deps.DB is.
func agentsOf(srv *api.Server, pool *pgxpool.Pool) Agents {
	if pool == nil {
		return nil
	}
	return serverAgents{srv}
}

type serverAgents struct{ srv *api.Server }

// agentRefOf is what the seams say of a resolved agent, its origin
// included when it is a fork.
func agentRefOf(ag registry.Agent) AgentRef {
	ref := AgentRef{ID: ag.ID, NamespaceID: ag.NamespaceID, NamespaceKind: NamespaceKind(ag.NamespaceKind), Public: ag.Visibility == "public"}
	if ag.ForkedFromAgentID != nil && ag.OriginNamespaceID != nil && ag.OriginNamespaceKind != nil {
		ref.ForkedFrom = &AgentOrigin{
			AgentID:       *ag.ForkedFromAgentID,
			NamespaceID:   *ag.OriginNamespaceID,
			NamespaceKind: NamespaceKind(*ag.OriginNamespaceKind),
		}
	}
	return ref
}

func (a serverAgents) Readable(ctx context.Context, p *Principal, namespace, name string) (AgentRef, bool, error) {
	ag, ok, err := a.srv.AgentReadable(ctx, p, namespace, name)
	if err != nil || !ok {
		return AgentRef{}, false, err
	}
	return agentRefOf(ag), true, nil
}

func (a serverAgents) Maintainable(ctx context.Context, p *Principal, namespace, name string) (AgentRef, bool, error) {
	ag, ok, err := a.srv.AgentMaintainable(ctx, p, namespace, name)
	if err != nil || !ok {
		return AgentRef{}, false, err
	}
	return agentRefOf(ag), true, nil
}

func (a serverAgents) Publishable(ctx context.Context, p *Principal, namespace, name string) (AgentRef, bool, error) {
	ag, ok, err := a.srv.AgentPublishable(ctx, p, namespace, name)
	if err != nil || !ok {
		return AgentRef{}, false, err
	}
	return agentRefOf(ag), true, nil
}

// principalsOf adapts the server's principal loading to Principals: nil
// without a database, the way Deps.DB is.
func principalsOf(srv *api.Server, pool *pgxpool.Pool) Principals {
	if pool == nil {
		return nil
	}
	return serverPrincipals{srv}
}

type serverPrincipals struct{ srv *api.Server }

func (p serverPrincipals) ForUser(ctx context.Context, userID uuid.UUID) (*Principal, bool, error) {
	return p.srv.PrincipalForUser(ctx, userID)
}

// scheduleCredentialsOf adapts the server's principal loading to
// ScheduleCredentials: nil without a database, as principalsOf is.
func scheduleCredentialsOf(srv *api.Server, pool *pgxpool.Pool) ScheduleCredentials {
	if pool == nil {
		return nil
	}
	return serverScheduleCredentials{srv}
}

type serverScheduleCredentials struct{ srv *api.Server }

func (c serverScheduleCredentials) ForSchedule(ctx context.Context, userID, scheduleID uuid.UUID) (*Principal, bool, error) {
	return c.srv.PrincipalForSchedule(ctx, userID, scheduleID)
}

// notifierOf adapts the server's notifier to Notifier: nil without a
// database, the way Deps.DB is, since the rule reads the user's row.
func notifierOf(srv *api.Server, pool *pgxpool.Pool) Notifier {
	if pool == nil {
		return nil
	}
	return serverNotifier{srv}
}

type serverNotifier struct{ srv *api.Server }

func (n serverNotifier) Send(ctx context.Context, userID uuid.UUID, kind NotifyKind, subject, text string) (bool, error) {
	return n.srv.SendToUser(ctx, userID, string(kind), subject, text)
}

func (n serverNotifier) OrgAdmins(ctx context.Context, orgID uuid.UUID) ([]uuid.UUID, error) {
	return n.srv.OrgAdminIDs(ctx, orgID)
}

// knowledgeOf adapts the server's knowledge store to Knowledge: nil
// without a database, the way Deps.DB is. It is set whether or not the
// store is on yet: a wrapper an extension adds after this Bind (the
// knowledge extension's) turns it on, and the store says so per call.
func knowledgeOf(srv *api.Server, pool *pgxpool.Pool) Knowledge {
	if pool == nil || srv.Knowledge() == nil {
		return nil
	}
	return serverKnowledge{srv.Knowledge()}
}

type serverKnowledge struct{ svc *knowledge.Service }

func (k serverKnowledge) Create(ctx context.Context, owner KeyOwner, name string) (KnowledgePack, error) {
	return k.svc.CreateSealed(ctx, owner, name)
}

func (k serverKnowledge) Pack(ctx context.Context, owner KeyOwner, id uuid.UUID) (KnowledgePack, error) {
	return k.svc.Info(ctx, owner, id)
}

func (k serverKnowledge) Tree(ctx context.Context, owner KeyOwner, id uuid.UUID) (KnowledgePack, []byte, error) {
	return k.svc.TreeOf(ctx, owner, id)
}

func (k serverKnowledge) Replace(ctx context.Context, owner KeyOwner, id uuid.UUID, from string, files []KnowledgeFile) (KnowledgePack, bool, error) {
	return k.svc.Replace(ctx, owner, id, from, files)
}

func (k serverKnowledge) Usage(ctx context.Context, owner KeyOwner) (KnowledgeUsage, error) {
	return k.svc.Usage(ctx, owner)
}

// voiceOf adapts the server's voice store to Voice: nil without a
// database, the way Deps.DB is. Set whether or not the store is on yet,
// as knowledgeOf is: a key wrapper an extension adds later turns it on.
func voiceOf(srv *api.Server, pool *pgxpool.Pool) Voice {
	if pool == nil || srv.Voice() == nil {
		return nil
	}
	return serverVoice{srv.Voice()}
}

// reportSettingsOf adapts the server's report settings to ReportSettings:
// nil without a database, the way Deps.DB is.
func reportSettingsOf(srv *api.Server, pool *pgxpool.Pool) ReportSettings {
	if pool == nil {
		return nil
	}
	return serverReportSettings{srv}
}

type serverReportSettings struct{ srv *api.Server }

func (r serverReportSettings) Design(ctx context.Context, user uuid.UUID) ([]byte, error) {
	return r.srv.ReportDesign(ctx, user)
}

func (r serverReportSettings) DesignWithLogo(ctx context.Context, user uuid.UUID) ([]byte, error) {
	return r.srv.ReportDesignWithLogo(ctx, user)
}

func (r serverReportSettings) Theme(ctx context.Context, user uuid.UUID) (string, error) {
	return r.srv.ReportTheme(ctx, user)
}

// meterOf is the server's meter under the extension's scope, or a no-op
// one when the server runs without a database, as every other
// dependency is absent then.
func meterOf(srv *api.Server, pool *pgxpool.Pool, name string) metric.Meter {
	if pool == nil {
		return noopmetric.NewMeterProvider().Meter(name)
	}
	return srv.Metrics().ExtensionMeter(name)
}

type serverVoice struct{ svc *voice.Service }

func (v serverVoice) Live(ctx context.Context, user uuid.UUID) (*VoiceVersion, error) {
	return v.svc.Live(ctx, user)
}

func (v serverVoice) State(ctx context.Context, user uuid.UUID) (VoiceState, error) {
	return v.svc.Get(ctx, user)
}

func (v serverVoice) Propose(ctx context.Context, user uuid.UUID, text []byte, source VoiceSource) (VoiceState, error) {
	if source != VoiceSourceBuild && source != VoiceSourceAIEdit {
		return VoiceState{}, fmt.Errorf("extension: a Voice Writer run proposes a voice as build or ai-edit, not %q", source)
	}
	return v.svc.Put(ctx, user, text, source)
}

// webhooksOf adapts the server's webhook transport to Webhooks: nil
// without a database, the way Deps.DB is.
func webhooksOf(srv *api.Server, pool *pgxpool.Pool) Webhooks {
	if pool == nil {
		return nil
	}
	return serverWebhooks{srv}
}

type serverWebhooks struct{ srv *api.Server }

func (w serverWebhooks) Endpoints(ctx context.Context, orgID uuid.UUID) ([]WebhookEndpointRef, error) {
	return w.srv.WebhookEndpoints(ctx, orgID)
}

func (w serverWebhooks) Deliver(ctx context.Context, orgID, endpointID uuid.UUID, event string, data any) (bool, error) {
	return w.srv.DeliverWebhook(ctx, orgID, endpointID, event, data)
}

// sealerOf is the extension's own sealer. A key that cannot be derived is
// a broken build, found at start-up.
func sealerOf(srv *api.Server, name string) Sealer {
	s, err := srv.ExtensionSealer(name)
	if err != nil {
		panic("extension " + name + ": " + err.Error())
	}
	return s
}

// staffOf adapts the server's staff read to Staff: nil without a
// database, the way Deps.DB is.
func staffOf(srv *api.Server, pool *pgxpool.Pool) Staff {
	if pool == nil {
		return nil
	}
	return serverStaff{srv}
}

type serverStaff struct{ srv *api.Server }

func (s serverStaff) Members(ctx context.Context) ([]StaffMember, error) {
	return s.srv.PlatformStaff(ctx)
}

// membersOf adapts the server's membership door to Members under the
// extension's name: nil without a database, the way Deps.DB is.
func membersOf(srv *api.Server, pool *pgxpool.Pool, name string) Members {
	if pool == nil {
		return nil
	}
	return serverMembers{srv: srv, name: name}
}

type serverMembers struct {
	srv  *api.Server
	name string
}

func (m serverMembers) Provision(ctx context.Context, orgID uuid.UUID, p ProvisionedMember) (uuid.UUID, error) {
	return m.srv.ProvisionMember(ctx, m.name, orgID, p)
}

func (m serverMembers) Deprovision(ctx context.Context, orgID, userID uuid.UUID) (bool, error) {
	return m.srv.DeprovisionMember(ctx, m.name, orgID, userID)
}

// accountsOf adapts the server's account door to Accounts under the
// extension's name: nil without a database, the way Deps.DB is.
func accountsOf(srv *api.Server, pool *pgxpool.Pool, name string) Accounts {
	if pool == nil {
		return nil
	}
	return serverAccounts{srv: srv, name: name}
}

type serverAccounts struct {
	srv  *api.Server
	name string
}

func (a serverAccounts) Facts(ctx context.Context, actor *Principal, userID uuid.UUID) (AccountFacts, error) {
	return a.srv.AccountFacts(ctx, actor, userID)
}

func (a serverAccounts) Suspend(ctx context.Context, actor *Principal, userID uuid.UUID, reason string) (AccountChange, error) {
	return a.srv.SuspendAccount(ctx, a.name, actor, userID, reason)
}

func (a serverAccounts) Reinstate(ctx context.Context, actor *Principal, userID uuid.UUID, reason string) (AccountChange, error) {
	return a.srv.ReinstateAccount(ctx, a.name, actor, userID, reason)
}

func (a serverAccounts) SignOut(ctx context.Context, actor *Principal, userID uuid.UUID, reason string) (AccountChange, error) {
	return a.srv.SignOutAccount(ctx, a.name, actor, userID, reason)
}

// signInHookOf hands an extension's hook the sign-in with a remembered
// browser that is audited under the extension's name, whatever detail the
// extension asks for.
func signInHookOf(h HearsSignIn, name string) func(context.Context, SignIn) {
	return func(ctx context.Context, in SignIn) {
		mint := in.RememberBrowser
		in.RememberBrowser = func(detail map[string]any) (string, time.Duration, error) {
			d := map[string]any{}
			for k, v := range detail {
				d[k] = v
			}
			d["via"], d["extension"] = "extension", name
			return mint(d)
		}
		h.SignedIn(ctx, in)
	}
}

// rememberedBrowsersOf adapts the server's remembered browsers to
// RememberedBrowsers: nil without a database. Every record and use is
// audited with the extension's name, so an investigator can tell which
// sign-in earned or spent it.
func rememberedBrowsersOf(srv *api.Server, pool *pgxpool.Pool, name string) RememberedBrowsers {
	if pool == nil {
		return nil
	}
	return serverRememberedBrowsers{srv: srv, name: name}
}

type serverRememberedBrowsers struct {
	srv  *api.Server
	name string
}

func (b serverRememberedBrowsers) Use(r *http.Request, userID uuid.UUID, token string) (bool, error) {
	return b.srv.UseRememberedBrowser(r, userID, token, map[string]any{"via": "extension", "extension": b.name})
}

// extensionJobs returns the extensions' jobs on the api queue (api) or
// on every other queue (!api): the api role's and the worker's halves.
func extensionJobs(exts []Extension, api bool) []Job {
	var out []Job
	for _, e := range exts {
		for _, j := range e.Jobs() {
			if (j.Queue == QueueAPI) == api {
				out = append(out, j)
			}
		}
	}
	return out
}

// registerJobs registers each job's handler on q and enqueues a
// periodic one on its period.
func registerJobs(ctx context.Context, q queue.Worker, jobs []Job, log *slog.Logger) {
	for _, j := range jobs {
		q.Register(j.Kind, j.Handler)
		if j.Every > 0 {
			go periodicTicker(ctx, q, j.Kind, j.Queue, j.Every, log)
		}
	}
}

// apiQueue drains the api queue in the api role: the extension jobs that
// must reach what only the api may reach (QueueAPI), and nothing else.
// It returns a func that waits for the queue to stop once ctx ends, and
// a nil queue when no extension names the api queue or there is no
// database.
func apiQueue(ctx context.Context, cfg config.Config, st *store.Store, log *slog.Logger, mx *metrics.Metrics, exts []Extension) (func(), error) {
	jobs := extensionJobs(exts, true)
	if len(jobs) == 0 || st == nil {
		return func() {}, nil
	}
	q, err := queue.Open(cfg.Queue.Driver, cfg.Queue.Workers, st, log)
	if err != nil {
		return nil, err
	}
	q.SetMetrics(mx, cfg.Telemetry.QueueSampleInterval)
	registerJobs(ctx, q, jobs, log)
	done := make(chan struct{})
	go func() {
		defer close(done)
		log.Info("api queue started", "queue", QueueAPI, "jobs", len(jobs))
		if err := q.Work(ctx, QueueAPI); err != nil && ctx.Err() == nil {
			log.Error("api queue stopped", "err", err)
		}
	}()
	return func() { <-done }, nil
}

// periodicTicker enqueues a job once now and then on its period. Every
// replica running this enqueues on its own clock; the queue's claim runs
// each row once, so the handler must tolerate a run that finds nothing to
// do (the core's watchdog does; an extension's job must, Job.Every).
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

// reconcileWindow is how often the watchdog job is enqueued. Versions
// become eligible at the 30-minute cap, so checking every few minutes
// is prompt without being chatty.
const reconcileWindow = 5 * time.Minute

func reconcileTicker(ctx context.Context, q queue.Client, log *slog.Logger) {
	periodicTicker(ctx, q, scan.JobScanReconcile, "core", reconcileWindow, log)
}

// mcpSweepWindow is how often the MCP server vulnerability sweep is
// enqueued: daily, and once shortly after start-up so a worker that was
// down for a day catches up; the handler re-checks only rows older than
// its own threshold, so an early run is cheap.
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

// buildHandler assembles the HTTP surface for a role: api routes, git
// smart-HTTP routes, or both (`all`, the self-host default). The returned
// close function releases the background goroutines the handler's components
// own (rate-limit collectors, exporters).
func buildHandler(ctx context.Context, cfg config.Config, st *store.Store, log *slog.Logger, role string, mx *metrics.Metrics, exts []Extension) (http.Handler, func() error, error) {
	switch role {
	case "api":
		// The api role holds no signing key: it serves the key set and
		// the ruleset attestation from the record, and hands an
		// approval's publish to the worker.
		s := api.New(cfg, st, log, api.WithoutSigningKey())
		s.SetMetrics(mx)
		applyExtensions(s, exts)
		s.HandOffScans() // a submission is the worker's to scan
		staffAtStart(ctx, cfg, s, log)
		wait, err := apiQueue(ctx, cfg, st, log, mx, exts)
		if err != nil {
			_ = s.Close()
			return nil, nil, err
		}
		return api.NewHandler(s), func() error { wait(); return s.Close() }, nil
	case "git", "all":
		if st == nil {
			return nil, nil, errors.New("the git role requires a database")
		}
		repos, err := gitsrv.NewRepoStore(cfg)
		if err != nil {
			return nil, nil, err
		}
		// A git role whose pushes could not be policed does not start:
		// the hook must run from the hooks base now, rather than every
		// push being refused later.
		if err := repos.PrepareHooks(); err != nil {
			return nil, nil, err
		}
		// A process that died mid-init or mid-view-build left its work
		// directory on the volume; a crash always ends in a start, so the
		// start sweeps.
		if n, err := repos.SweepInitLeftovers(); err != nil {
			log.Warn("git: sweep repository init leftovers", "err", err, "removed", n)
		} else if n > 0 {
			log.Info("git: removed repository init leftovers", "removed", n)
		}
		if n, err := repos.SweepViewLeftovers(); err != nil {
			log.Warn("git: sweep reviewed-view build leftovers", "err", err, "removed", n)
		} else if n > 0 {
			log.Info("git: removed reviewed-view build leftovers", "removed", n)
		}
		// The git role terminates untrusted git traffic and never
		// signs, so it holds no key; `all` is also the worker and does.
		var opts []api.Option
		if role == "git" {
			opts = append(opts, api.WithoutSigningKey())
		}
		s := api.New(cfg, st, log, opts...)
		s.SetMetrics(mx)
		applyExtensions(s, exts)
		s.HandOffScans() // a submission is the worker's to scan
		if role == "git" {
			// The git pods hold no object-store credential: a tag's
			// archive is the worker's to store.
			s.DeferTagArchives()
		}
		if role == "all" {
			staffAtStart(ctx, cfg, s, log)
		}
		reg := s.Reg()
		reg.SetGitArchiver(repos)
		if role == "all" {
			reg.SetForkRepos(repos) // `all` is also the worker that copies forks
		}
		if pl := s.Pipeline(); pl != nil {
			pl.SetGitHistory(repos) // S2 history scan on git-tag publishes
		}
		aud := audit.NewWriter(log)
		git := gitsrv.NewHandler(cfg, st, repos, reg, aud, log)
		git.SetMetrics(mx)
		// Push bookkeeping rides the queue as repo.pushed; the worker
		// (in-process for `all`) runs it.
		gq, qerr := queue.Open(cfg.Queue.Driver, cfg.Queue.Workers, st, log)
		if qerr != nil {
			return nil, nil, qerr
		}
		git.SetQueue(gq)
		closeAll := func() error { return errors.Join(git.Close(), s.Close()) }
		// The SSH transport rides beside smart HTTP when configured;
		// same handler, same authorization and hooks.
		if cfg.Git.SSHAddr != "" {
			sshSrv, err := git.NewSSHServer(cfg.Git.SSHAddr, cfg.Git.SSHHostKeyFile)
			if err != nil {
				return nil, nil, err
			}
			// The fingerprint is what a self-hoster publishes for their users
			// (self-hosting.md); named so the contract's redaction of
			// secret-shaped keys leaves it readable.
			log.Info("git ssh listening", "addr", sshSrv.Addr().String(), "hostkey_fingerprint", sshSrv.HostKeyFingerprint())
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
			// Through api.Mount rather than mux.HandleFunc: this mux is
			// not the recorded one the completeness gate reads, so the
			// declaration check at start-up is the only thing tying
			// these two patterns to the gate and the api role.
			api.MountFunc(mux, "GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"status":"ok"}`))
			})
			// Readiness is the database ping, as on the api role: the
			// chart's git Deployment probes /readyz, and a git pod
			// without it never becomes Ready.
			api.MountFunc(mux, "GET /readyz", s.Readyz)
			// The git role has no /api/v1 surface, so /metrics is
			// mounted here too: a git deployment is exactly the one
			// whose clone first-byte SLI needs scraping.
			api.Mount(mux, "GET /metrics", mx.Handler())
			git.Mount(mux)
			// The same middleware stack as the api role: a git deployment
			// gets request ids and the access line too (docs/logging.md).
			return s.WrapMiddleware(mux), closeAll, nil
		}

		// `all` runs EVERY role in-process. Without this the
		// single-process self-host shape would start no worker at all,
		// so webhook deliveries, audit exports and queue-driven scans
		// would be enqueued and never claimed. Enqueued work that
		// silently never runs is worse than work that fails, because
		// nothing reports it.
		q, err := newWorkerQueue(ctx, cfg, s, st, log, mx, exts)
		if err != nil {
			return nil, nil, err
		}
		// `all` is the api role too, so it drains the api queue as well.
		queues := workerQueues
		if apiJobs := extensionJobs(exts, true); len(apiJobs) > 0 {
			registerJobs(ctx, q, apiJobs, log)
			queues = append(slices.Clone(workerQueues), QueueAPI)
		}
		go func() {
			log.Info("in-process worker started", "queues", strings.Join(queues, ","))
			if err := q.Work(ctx, queues...); err != nil && ctx.Err() == nil {
				log.Error("in-process worker stopped", "err", err)
			}
		}()
		return api.NewHandlerWithGit(s, git.Mount), closeAll, nil
	default:
		return nil, nil, fmt.Errorf("unknown http role %q", role)
	}
}

// hookCmd implements the git hook shim (`agentryd hook pre-receive`),
// invoked by git inside bare repos.
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
	directoryFrom := ""
	for _, e := range exts {
		if a, ok := e.(Audits); ok {
			for _, act := range a.AuditActions() {
				registerAuditAction(e.Name(), act)
			}
		}
		if b, ok := e.(Binds); ok {
			pool, log, write, writeIn := srv.ExtensionDeps()
			b.Bind(Deps{DB: pool, Log: log.With("extension", e.Name()), Audit: auditWriter{write: write, writeIn: writeIn},
				Entitlements: srv.CoreEntitlements(), Blobs: srv.Blobs(), Orgs: orgsOf(srv, pool), OrgGate: orgGateOf(srv, pool), Agents: agentsOf(srv, pool), Principals: principalsOf(srv, pool),
				ScheduleCredentials: scheduleCredentialsOf(srv, pool),
				Notifier:            notifierOf(srv, pool), Webhooks: webhooksOf(srv, pool), Knowledge: knowledgeOf(srv, pool),
				Voice: voiceOf(srv, pool), ReportSettings: reportSettingsOf(srv, pool), Meter: meterOf(srv, pool, e.Name()), BaseURL: srv.BaseURL(),
				Staff: staffOf(srv, pool), Members: membersOf(srv, pool, e.Name()), Accounts: accountsOf(srv, pool, e.Name()), RememberedBrowsers: rememberedBrowsersOf(srv, pool, e.Name()), Sealer: sealerOf(srv, e.Name())})
		}
		srv.RegisterExtension(e.Name(), e.Routes)
		if u, ok := e.(Unthrottles); ok {
			srv.SetExtensionUnthrottled(e.Name(), u.UnthrottledRoutes())
		}
		if t, ok := e.(TakesOwnTokens); ok {
			own := t.OwnTokens()
			srv.SetExtensionTokens(e.Name(), own.Prefix, api.ExtensionTokenResolver(own.Resolve))
		}
		if r := e.Entitlements(); r != nil {
			srv.SetEntitlements(r)
		}
		if a, ok := e.(Admits); ok {
			// No registry without a database (limited dev mode): nothing
			// to admit into.
			if adm, reg := a.Admitter(), srv.Reg(); adm != nil && reg != nil {
				reg.SetAdmitter(adm)
			}
		}
		if k, ok := e.(WrapsKeys); ok {
			srv.SetKeyWrapper(k.KeyWrapper())
		}
		if x, ok := e.(ErasesAccounts); ok {
			srv.AddAccountEraser(e.Name(), x.EraseAccount)
		}
		if v, ok := e.(AdmitsVoice); ok {
			if a := v.VoiceAdmitter(); a != nil {
				srv.SetVoiceAdmitter(a)
			}
		}
		if k, ok := e.(AdmitsKnowledge); ok {
			if a := k.KnowledgeAdmitter(); a != nil {
				srv.SetKnowledgeAdmitter(a)
			}
		}
		if d, ok := e.(ProvesDrafts); ok {
			// No pipeline without archive storage: nothing to scan.
			if dp, pl := d.DraftProvenance(), srv.Pipeline(); dp != nil && pl != nil {
				pl.SetDraftProvenance(dp)
			}
		}
		if m, ok := e.(AdmitsModelInput); ok {
			if c := m.ModelInputCallers(); c != nil {
				srv.SetModelInputCallers(c)
			}
		}
		if m, ok := e.(ManagesDirectory); ok {
			if d := m.Directory(); d != nil {
				if directoryFrom != "" {
					panic("extension: " + e.Name() + " and " + directoryFrom + " both manage the directory; a deployment has one")
				}
				directoryFrom = e.Name()
				srv.SetDirectory(d)
			}
		}
		if c, ok := e.(ReceivesCallbacks); ok {
			srv.RegisterExtensionCallbacks(e.Name(), c.Callbacks())
		}
		if h, ok := e.(HearsSignIn); ok {
			srv.AddSignInHook(signInHookOf(h, e.Name()))
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

// staffAtStart recomputes platform staff once over every account the staff
// organization's rule could change, so a configuration change takes effect
// when the server starts rather than at each person's next sign-in.
// Several replicas may run it at once; the registry serialises them on an
// advisory lock.
// A failure is logged, not fatal: the flag is recomputed again at every
// sign-in and membership change.
func staffAtStart(ctx context.Context, cfg config.Config, s *api.Server, log *slog.Logger) {
	reg := s.Reg()
	if reg == nil || !reg.StaffConfigured() {
		return
	}
	n, err := reg.ResyncStaff(ctx)
	if err != nil {
		log.Error("platform staff resync", "err", err)
		return
	}
	log.Info("platform staff resync", "org", cfg.Auth.StaffOrg, "domain", cfg.Auth.StaffDomain, "accounts", n)
	// Members the rule does not make staff are said, not removed:
	// removing a member is the organization's admins' act.
	if handles, err := reg.StaffOrgMembersNotStaff(ctx); err != nil {
		log.Error("platform staff: list the staff organization's members who are not staff", "err", err)
	} else if len(handles) > 0 {
		log.Warn("the staff organization has active members who are not platform staff (an address outside its domain or unverified, or an inactive account); they are not removed",
			"org", cfg.Auth.StaffOrg, "domain", cfg.Auth.StaffDomain, "members", handles)
	}
}
