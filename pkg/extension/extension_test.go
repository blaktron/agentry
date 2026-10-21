package extension

import (
	"bytes"
	"context"
	"errors"
	"image"
	"image/png"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/knowledge"
	"github.com/blaktron/agentry/internal/metrics"
	"github.com/blaktron/agentry/internal/queue"
	"github.com/blaktron/agentry/internal/scan"
	storegen "github.com/blaktron/agentry/internal/store/gen"
	"github.com/blaktron/agentry/internal/voice"
	"github.com/blaktron/agentry/pkg/judge"
	"github.com/blaktron/agentry/pkg/reportdesign"
)

// A minimal extension compiles against the interface using only the
// aliases this package exports: what a module outside the core can do.
type noop struct{}

func (noop) Name() string { return "noop" }
func (noop) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
}
func (noop) Migrations() fs.FS      { return nil }
func (noop) Entitlements() Resolver { return nil }
func (noop) Hooks() Hooks           { return Hooks{Event: func(context.Context, Event) {}} }
func (noop) Jobs() []Job            { return nil }

var _ Extension = noop{}

// billingLike is the shape a billing extension takes: the optional
// seams, satisfied with the aliases alone. It must compile; the
// behaviour is the API's tests.
type billingLike struct{ noop }

func (billingLike) Admitter() Admitter {
	return admitAll{}
}
func (billingLike) UnthrottledRoutes() []string { return []string{"POST /webhooks/pay"} }

type admitAll struct{}

func (admitAll) Admit(context.Context, Admission) (Ticket, *Refusal, error) {
	return Ticket{ID: "t"}, nil, nil
}
func (admitAll) Void(context.Context, Ticket) error { return nil }

func (b *bound) Bind(d Deps) { b.deps = d }

type bound struct {
	billingLike
	deps Deps
}

func (bound) Name() string { return "bound" }

// tiered is the shape an extension's resolver takes: the core's, with
// Features answered by the extension. It must compile against the
// aliases alone.
type tiered struct {
	Resolver
}

func (tiered) Features(context.Context, Subject) (Features, error) {
	return Features{PrivateAgents: Cap{Enabled: true, Max: 10}}, nil
}

var _ Resolver = tiered{}

var (
	_ Extension   = billingLike{}
	_ Admits      = billingLike{}
	_ Unthrottles = billingLike{}
	_ Binds       = (*bound)(nil)
)

// TestRegisterAuditActionKeepsTheExtensionPrefix: an extension may add its
// own actions to the audit catalog, only under its own name, and never one
// the catalog already holds.
func TestRegisterAuditActionKeepsTheExtensionPrefix(t *testing.T) {
	registerAuditAction("billing", "billing.tier_set")
	for _, bad := range []AuditAction{"tier_set", "agent.update", "billing.", "billingx.tier_set", "billing.tier_set"} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("action %q was accepted", bad)
				}
			}()
			registerAuditAction("billing", bad)
		}()
	}
	// An extension named for a core prefix cannot take a core action over.
	func() {
		defer func() {
			if recover() == nil {
				t.Error("agent.update was registered by an extension named agent")
			}
		}()
		registerAuditAction("agent", "agent.update")
	}()

	// Each refusal is its own: the name, the prefix, the verb, the catalog.
	panicked := func(name string, a AuditAction) string {
		var got string
		func() {
			defer func() {
				if r := recover(); r != nil {
					got, _ = r.(string)
					if got == "" {
						got = "panic with a value that is no string"
					}
				}
			}()
			registerAuditAction(name, a)
		}()
		return got
	}
	for _, c := range []struct {
		name   string
		action AuditAction
		want   string
	}{
		{"billing", "tier_set", "must be prefixed billing."},
		{"billing", "billingx.tier_set", "must be prefixed billing."},
		{"billing", "billing.", "must be prefixed billing."},
		{"billing", "billing.tier_set", "is already in the catalog"},
		{"agent", "agent.update", "is already in the catalog"},
		// A name is a lower-case letter, then up to 31 lower-case letters,
		// digits and dashes, and nothing before or after it.
		{"", ".verb", "invalid extension name"},
		{"Billing", "Billing.verb", "invalid extension name"},
		{"1billing", "1billing.verb", "invalid extension name"},
		{"-billing", "-billing.verb", "invalid extension name"},
		{"bill_ing", "bill_ing.verb", "invalid extension name"},
		{"bill ing", "bill ing.verb", "invalid extension name"},
		{"billing\n", "billing\n.verb", "invalid extension name"},
		{"x" + strings.Repeat("a", 32), AuditAction("x" + strings.Repeat("a", 32) + ".verb"), "invalid extension name"},
		{strings.Repeat("a", 64), AuditAction(strings.Repeat("a", 64) + ".verb"), "invalid extension name"},
	} {
		if got := panicked(c.name, c.action); !strings.Contains(got, c.want) {
			t.Errorf("registerAuditAction(%q, %q) panicked with %q, want it to say %q", c.name, c.action, got, c.want)
		}
	}
	// What the rules allow is registered, the longest name included.
	for _, ok := range []struct {
		name   string
		action AuditAction
	}{
		{"a", "a.x"},
		{"a1-b2", "a1-b2.verb.sub"},
		{"x" + strings.Repeat("a", 31), AuditAction("x" + strings.Repeat("a", 31) + ".verb")},
	} {
		if got := panicked(ok.name, ok.action); got != "" {
			t.Errorf("registerAuditAction(%q, %q) panicked: %s", ok.name, ok.action, got)
		}
		if !audit.Registered(ok.action) {
			t.Errorf("%q is not in the catalog", ok.action)
		}
	}
}

// binder keeps the deps it is bound with and registers nothing else.
type binder struct {
	noop
	deps Deps
}

func (b *binder) Bind(d Deps) { b.deps = d }

// TestBindHandsTheBaseURL: a bound extension gets the address the
// core's own links use, whether the deployment names it in the config
// file (as a chart does) or in AGENTRY_BASE_URL (as a compose file
// does), the variable winning over the file, and nothing when neither
// names one.
func TestBindHandsTheBaseURL(t *testing.T) {
	cases := []struct {
		name, file, env, want string
	}{
		{"the config file", "https://file.example/", "", "https://file.example"},
		{"the environment", "", "https://env.example", "https://env.example"},
		{"the environment over the file", "https://file.example", "https://env.example/", "https://env.example"},
		{"neither", "", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "agentry.yaml")
			body := "devMode: true\n"
			if c.file != "" {
				body += "baseURL: " + c.file + "\n"
			}
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			// Set but empty would clear the file's address, so an unset
			// case is unset (t.Setenv first, to restore it afterwards).
			t.Setenv("AGENTRY_BASE_URL", c.env)
			if c.env == "" {
				if err := os.Unsetenv("AGENTRY_BASE_URL"); err != nil {
					t.Fatal(err)
				}
			}
			cfg, err := config.Load(path)
			if err != nil {
				t.Fatal(err)
			}
			ext := &binder{}
			applyExtensions(api.New(cfg, nil, slog.New(slog.DiscardHandler)), []Extension{ext})
			if ext.deps.BaseURL != c.want || ext.deps.BaseURL != strings.TrimRight(cfg.BaseURL, "/") {
				t.Fatalf("Deps.BaseURL = %q, want %q (config %q)", ext.deps.BaseURL, c.want, cfg.BaseURL)
			}
		})
	}
}

func (bound) AuditActions() []AuditAction { return []AuditAction{"bound.tier_set"} }

// TestApplyExtensionsBindsAndRegistersActions: applyExtensions hands a
// Binds extension its deps (a nil pool without a database, a logger, an
// audit writer) and puts its audit actions in the catalog under its name,
// before anything else of it is wired.
func TestApplyExtensionsBindsAndRegistersActions(t *testing.T) {
	ext := &bound{}
	cfg := config.Default()
	cfg.DevMode = true
	var logged bytes.Buffer
	srv := api.New(cfg, nil, slog.New(slog.NewJSONHandler(&logged, nil)))
	applyExtensions(srv, []Extension{ext})
	if ext.deps.Log == nil || ext.deps.Audit == nil || ext.deps.Entitlements == nil {
		t.Fatalf("Bind did not deliver the deps: %+v", ext.deps)
	}
	if f, err := ext.deps.Entitlements.Features(context.Background(), Subject{Kind: NamespaceUser}); err != nil || f.PrivateAgents.Max != 0 {
		t.Fatalf("the core resolver must be the configured, uncapped one: %+v %v", f, err)
	}
	if ext.deps.DB != nil {
		t.Fatal("a server without a database handed out a pool")
	}
	if ext.deps.Blobs != nil {
		t.Fatal("a server without a database handed out an object store")
	}
	if ext.deps.Notifier != nil {
		t.Fatal("a server without a database handed out a notifier: the rule about who may be written to reads the user's row")
	}
	if ext.deps.Webhooks != nil {
		t.Fatal("a server without a database handed out a webhook transport: an endpoint is a row and a delivery is another")
	}
	if ext.deps.Knowledge != nil {
		t.Fatal("a server without a database handed out the knowledge store")
	}
	if ext.deps.Orgs != nil || ext.deps.OrgGate != nil || ext.deps.Agents != nil || ext.deps.Principals != nil || ext.deps.ScheduleCredentials != nil {
		t.Fatal("a server without a database handed out an organization, organization-gate, agent, principal or schedule-credential read: each reads a row")
	}
	if ext.deps.Voice != nil || ext.deps.ReportSettings != nil {
		t.Fatal("a server without a database handed out the voice store or the report settings")
	}
	if ext.deps.Meter == nil {
		t.Fatal("a server without a database handed out a nil meter: it must be a no-op one")
	}
	// The extension's logger carries its name on every line.
	ext.deps.Log.Info("bound probe")
	if line := logged.String(); !strings.Contains(line, `"extension":"bound"`) || !strings.Contains(line, "bound probe") {
		t.Fatalf("the extension's log line does not carry its name: %q", line)
	}
	// Its routes are mounted under its name and its unthrottled routes are
	// declared under it, and under no other.
	if got := srv.ExtensionNames(); len(got) != 1 || got[0] != "bound" {
		t.Fatalf("mounted extensions = %v, want [bound]", got)
	}
	if got := srv.ExtensionUnthrottled(); len(got) != 1 || !got["POST /api/v1/x/bound/webhooks/pay"] {
		t.Fatalf("unthrottled routes = %v, want only POST /api/v1/x/bound/webhooks/pay", got)
	}
	if _, err := ext.deps.Meter.Int64Counter("BoundThings"); err != nil {
		t.Fatalf("the no-op meter refused an instrument: %v", err)
	}
	if !audit.Registered("bound.tier_set") {
		t.Fatal("the extension's audit action is not in the catalog")
	}
	if err := ext.deps.Audit.Write(context.Background(), AuditEvent{Action: "bound.tier_set", ActorKind: ActorSystem}); err == nil {
		t.Fatal("an audit write with no database must fail, not vanish")
	}

	// Each extension seals under a key of its own: what one seals another
	// does not open, and its own opens.
	other := &namedBinder{name: "sealed-other"}
	applyExtensions(srv, []Extension{other})
	if got := srv.ExtensionNames(); len(got) != 2 || got[0] != "bound" || got[1] != "sealed-other" {
		t.Fatalf("mounted extensions = %v, want [bound sealed-other]", got)
	}
	if got := srv.ExtensionUnthrottled(); len(got) != 1 {
		t.Fatalf("an extension that names no unthrottled route declared some: %v", got)
	}
	sealed, err := ext.deps.Sealer.Seal([]byte("sealed by bound"))
	if err != nil {
		t.Fatal(err)
	}
	if open, err := ext.deps.Sealer.Open(sealed); err != nil || string(open) != "sealed by bound" {
		t.Fatalf("an extension's own sealer did not open its value: %q %v", open, err)
	}
	if open, err := other.deps.Sealer.Open(sealed); err == nil {
		t.Fatalf("another extension's sealer opened bound's value: %q", open)
	}
}

// namedBinder is a binder under a name of its own.
type namedBinder struct {
	binder
	name string
}

func (n *namedBinder) Name() string { return n.name }

// An extension is mounted once, under a name of the shape the core
// accepts: a repeated name, an upper-case one and none are refused while
// the extensions are applied, not later when a route is asked for.
func TestApplyExtensionsRefusesARepeatedOrMalformedName(t *testing.T) {
	for _, c := range []struct {
		name string
		exts []Extension
		want string
	}{
		{"a repeated name", []Extension{&namedBinder{name: "twin"}, &namedBinder{name: "twin"}}, "extension registered twice: twin"},
		{"an upper-case name", []Extension{&namedBinder{name: "Twin"}}, "extension name must match"},
		{"no name", []Extension{&namedBinder{}}, "extension name must match"},
	} {
		t.Run(c.name, func(t *testing.T) {
			defer func() {
				r := recover()
				if r == nil {
					t.Fatal("the extensions were applied")
				}
				if msg, _ := r.(string); !strings.Contains(msg, c.want) {
					t.Fatalf("refused with %v, want it to say %q", r, c.want)
				}
			}()
			applyExtensions(identityServer(t), c.exts)
		})
	}
	// Two names that differ are two mounts, in the order given.
	srv := identityServer(t)
	applyExtensions(srv, []Extension{&namedBinder{name: "twin"}, &namedBinder{name: "twin-two"}})
	if got := srv.ExtensionNames(); !slices.Equal(got, []string{"twin", "twin-two"}) {
		t.Fatalf("mounted extensions = %v", got)
	}
}

// The adapters the core hands an extension follow the pool: none without a
// database, one with it, as Deps.DB is; the ones that act under the
// extension's name keep it, and the knowledge and voice stores are not
// handed out while they are off. The pool dials nothing until it is used.
func TestDepsAdaptersFollowThePoolAndKeepTheExtensionsName(t *testing.T) {
	srv := identityServer(t)
	pool, err := pgxpool.New(context.Background(), "postgres://agentry:agentry@127.0.0.1:1/agentry?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	for _, c := range []struct {
		name string
		of   func(*pgxpool.Pool) any
		// off is true for the stores that are nil while the server's store
		// is off, whatever the pool.
		off bool
	}{
		{"orgs", func(p *pgxpool.Pool) any { return orgsOf(srv, p) }, false},
		{"agents", func(p *pgxpool.Pool) any { return agentsOf(srv, p) }, false},
		{"principals", func(p *pgxpool.Pool) any { return principalsOf(srv, p) }, false},
		{"schedule credentials", func(p *pgxpool.Pool) any { return scheduleCredentialsOf(srv, p) }, false},
		{"notifier", func(p *pgxpool.Pool) any { return notifierOf(srv, p) }, false},
		{"webhooks", func(p *pgxpool.Pool) any { return webhooksOf(srv, p) }, false},
		{"report settings", func(p *pgxpool.Pool) any { return reportSettingsOf(srv, p) }, false},
		{"staff", func(p *pgxpool.Pool) any { return staffOf(srv, p) }, false},
		{"members", func(p *pgxpool.Pool) any { return membersOf(srv, p, "directory") }, false},
		{"remembered browsers", func(p *pgxpool.Pool) any { return rememberedBrowsersOf(srv, p, "directory") }, false},
		{"knowledge", func(p *pgxpool.Pool) any { return knowledgeOf(srv, p) }, true},
		{"voice", func(p *pgxpool.Pool) any { return voiceOf(srv, p) }, true},
	} {
		if got := c.of(nil); got != nil {
			t.Errorf("%s without a database: %T, want nil", c.name, got)
		}
		got := c.of(pool)
		if c.off && got != nil {
			t.Errorf("%s while the store is off: %T, want nil", c.name, got)
		}
		if !c.off && got == nil {
			t.Errorf("%s with a database: nil", c.name)
		}
	}
	if m, ok := membersOf(srv, pool, "directory").(serverMembers); !ok || m.name != "directory" {
		t.Errorf("the membership door acts under %+v, want the extension's name directory", m)
	}
	if b, ok := rememberedBrowsersOf(srv, pool, "directory").(serverRememberedBrowsers); !ok || b.name != "directory" {
		t.Errorf("the remembered browsers act under %+v, want the extension's name directory", b)
	}
	// A schedule credential is for one schedule of one user, in that order.
	if _, _, err := scheduleCredentialsOf(srv, pool).ForSchedule(context.Background(), uuid.New(), uuid.Nil); err == nil || !strings.Contains(err.Error(), "needs the schedule's id") {
		t.Errorf("a credential for no schedule: %v", err)
	}
}

// migrateExtensions touches the database only for an extension that has
// migrations, under that extension's name, and stops at the first that
// fails; an extension without any is skipped without a connection.
func TestMigrateExtensionsSkipsThoseWithoutMigrationsAndReportsAFailure(t *testing.T) {
	ctx := context.Background()
	const unreachable = "postgres://agentry:agentry@127.0.0.1:1/agentry?sslmode=disable"
	if err := migrateExtensions(ctx, unreachable, []Extension{noop{}, noop{}}); err != nil {
		t.Fatalf("extensions with no migrations: %v", err)
	}
	err := migrateExtensions(ctx, unreachable, []Extension{noop{}, migrating{name: "ledger"}})
	if err == nil || !strings.Contains(err.Error(), "migrate ledger:") {
		t.Fatalf("an extension with migrations on an unreachable database: %v, want a failure naming ledger", err)
	}
}

// migrating is an extension with an (empty) migration set under its name.
type migrating struct {
	noop
	name string
}

func (m migrating) Name() string    { return m.name }
func (migrating) Migrations() fs.FS { return fstest.MapFS{} }

// TestPeriodicTickerEnqueuesNowAndOnThePeriod pins the shape of Job.Every:
// one enqueue at start-up, then one per period, until the context ends.
func TestPeriodicTickerEnqueuesNowAndOnThePeriod(t *testing.T) {
	q := &countingQueue{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		periodicTicker(ctx, q, "probe.cycle", "", 20*time.Millisecond, slog.New(slog.DiscardHandler))
		close(done)
	}()
	deadline := time.Now().Add(2 * time.Second)
	for q.count() < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	if n := q.count(); n < 3 {
		t.Fatalf("enqueued %d times in 2s at a 20ms period", n)
	}
	if k, qn := q.last(); k != "probe.cycle" || qn != "core" {
		t.Fatalf("enqueued %s on %s; want probe.cycle on core", k, qn)
	}

	// The first enqueue does not wait for the first period: with a period of
	// an hour and a context that is already done, the ticker enqueues once
	// and returns. An unnamed queue is the core queue; a named one is kept.
	ended, stop := context.WithCancel(context.Background())
	stop()
	for _, c := range []struct{ queue, want string }{{"", "core"}, {"sandbox", "sandbox"}, {QueueAPI, QueueAPI}} {
		once := &countingQueue{}
		periodicTicker(ended, once, "probe.once", c.queue, time.Hour, slog.New(slog.DiscardHandler))
		if got := once.enqueues(); len(got) != 1 || got[0] != "probe.once on "+c.want {
			t.Errorf("a ticker on queue %q enqueued %v, want [probe.once on %s]", c.queue, got, c.want)
		}
	}
}

// The watchdog ticker enqueues the scan reconcile job on the core queue
// at start-up, and nothing else.
func TestReconcileTickerEnqueuesTheWatchdogOnTheCoreQueue(t *testing.T) {
	ended, stop := context.WithCancel(context.Background())
	stop()
	q := &countingQueue{}
	reconcileTicker(ended, q, slog.New(slog.DiscardHandler))
	if got, want := q.enqueues(), []string{scan.JobScanReconcile + " on core"}; !slices.Equal(got, want) {
		t.Fatalf("enqueued %v, want %v", got, want)
	}
}

// registerJobs registers every job's handler under its kind, and enqueues
// a job with a period at start-up on the queue the job names; a job with
// no period is registered and never enqueued by it.
func TestRegisterJobsRegistersEveryHandlerAndEnqueuesOnlyPeriodicJobs(t *testing.T) {
	errOnce, errPeriodic := errors.New("the one-off handler"), errors.New("the periodic handler")
	q := &countingQueue{signal: make(chan struct{}, 4)}
	ended, stop := context.WithCancel(context.Background())
	stop() // each periodic ticker enqueues once at start-up, then returns
	registerJobs(ended, q, []Job{
		{Kind: "probe.once", Queue: "core", Handler: func(context.Context, queue.Job) error { return errOnce }},
		{Kind: "probe.periodic", Queue: QueueAPI, Every: time.Hour, Handler: func(context.Context, queue.Job) error { return errPeriodic }},
	}, slog.New(slog.DiscardHandler))
	if got, want := q.registeredKinds(), []string{"probe.once", "probe.periodic"}; !slices.Equal(got, want) {
		t.Fatalf("registered %v, want %v", got, want)
	}
	if err := q.handler("probe.once")(context.Background(), queue.Job{}); !errors.Is(err, errOnce) {
		t.Errorf("probe.once runs %v, want its own handler", err)
	}
	if err := q.handler("probe.periodic")(context.Background(), queue.Job{}); !errors.Is(err, errPeriodic) {
		t.Errorf("probe.periodic runs %v, want its own handler", err)
	}
	waited, giveUp := context.WithTimeout(context.Background(), 10*time.Second)
	defer giveUp()
	select {
	case <-q.signal:
	case <-waited.Done():
		t.Fatal("the periodic job was never enqueued")
	}
	if got, want := q.enqueues(), []string{"probe.periodic on " + QueueAPI}; !slices.Equal(got, want) {
		t.Fatalf("enqueued %v, want %v", got, want)
	}
}

// countingQueue is a queue that records what is registered on it and
// enqueued to it, and satisfies queue.Worker without working anything.
type countingQueue struct {
	mu         sync.Mutex
	n          int
	kind       string
	queue      string
	log        []string
	registered []string
	handlers   map[string]queue.Handler
	// signal, when set, is sent to after each enqueue is recorded.
	signal chan struct{}
}

func (c *countingQueue) Enqueue(_ context.Context, kind, queueName string, _ any, _ ...queue.EnqueueOption) (uuid.UUID, error) {
	c.mu.Lock()
	c.n++
	c.kind, c.queue = kind, queueName
	c.log = append(c.log, kind+" on "+queueName)
	signal := c.signal
	c.mu.Unlock()
	if signal != nil {
		select {
		case signal <- struct{}{}:
		default:
		}
	}
	return uuid.New(), nil
}
func (c *countingQueue) Register(kind string, h queue.Handler) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.handlers == nil {
		c.handlers = map[string]queue.Handler{}
	}
	c.registered = append(c.registered, kind)
	c.handlers[kind] = h
}
func (c *countingQueue) Work(context.Context, ...string) error               { return nil }
func (c *countingQueue) CountWaiting(context.Context, string) (int64, error) { return 0, nil }
func (c *countingQueue) SetMetrics(*metrics.Metrics, time.Duration)          {}
func (c *countingQueue) Drain(context.Context, ...string)                    {}
func (c *countingQueue) count() int                                          { c.mu.Lock(); defer c.mu.Unlock(); return c.n }
func (c *countingQueue) enqueues() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.log)
}
func (c *countingQueue) registeredKinds() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.registered)
}
func (c *countingQueue) handler(kind string) queue.Handler {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.handlers[kind]
}
func (c *countingQueue) last() (string, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.kind, c.queue
}

var _ queue.Worker = (*countingQueue)(nil)

func TestNoopSatisfiesTheInterface(t *testing.T) {
	var e Extension = noop{}
	if e.Name() != "noop" || e.Migrations() != nil || e.Entitlements() != nil || e.Hooks().Event == nil {
		t.Fatal("unexpected zero behaviour")
	}
}

// TestParseQueues pins the worker's --queues contract: a subset of the
// queues that exist, in the order given, duplicates folded; an unknown
// name ("judge" included, which has no queue) is refused rather than
// drained as nothing; empty means both.
func TestParseQueues(t *testing.T) {
	cases := []struct {
		in   string
		want []string
		err  string
	}{
		{"", nil, ""},
		{"core", []string{"core"}, ""},
		{"sandbox", []string{"sandbox"}, ""},
		{"sandbox, core, sandbox", []string{"sandbox", "core"}, ""},
		{"judge", nil, `"judge" is not a queue (the queues are core, sandbox)`},
		{"core,scan", nil, `"scan" is not a queue (the queues are core, sandbox)`},
		{" , ", nil, "names no queue"},
		// A blank flag is no flag: both queues, as an empty one.
		{"  ", nil, ""},
		{"core,,sandbox", []string{"core", "sandbox"}, ""},
		{" core ", []string{"core"}, ""},
		{",", nil, "names no queue"},
	}
	for _, c := range cases {
		got, err := parseQueues(c.in)
		if c.err != "" {
			if err == nil || !strings.Contains(err.Error(), c.err) {
				t.Fatalf("%q: err %v, want %q", c.in, err, c.err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%q: %v", c.in, err)
		}
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Fatalf("%q: got %v want %v", c.in, got, c.want)
		}
	}
}

// ScopeAllows is how an extension route requires a hosted-run scope
// through the seam alone: nobody anonymous; a session, which has the
// account's full authority; a PAT only with the scope.
func TestScopeAllows(t *testing.T) {
	if ScopeAllows(nil, ScopeRunWrite) || ScopeAllows(&Principal{Anonymous: true}, ScopeRunWrite) {
		t.Fatal("an anonymous caller passed")
	}
	if !ScopeAllows(&Principal{Via: "session"}, ScopeRunWrite) {
		t.Fatal("a session was refused; it carries the account's full authority")
	}
	pat := &Principal{Via: "pat", Scopes: []string{"run:read", "agent:read"}}
	if !ScopeAllows(pat, ScopeRunRead) {
		t.Fatal("a PAT carrying run:read was refused")
	}
	if ScopeAllows(pat, ScopeRunWrite) {
		t.Fatal("a PAT without run:write passed; the list is flat")
	}
	if ScopeAllows(pat, ScopeKnowledgeWrite) || !ScopeAllows(&Principal{Via: "pat", Scopes: []string{"knowledge:write"}}, ScopeKnowledgeWrite) {
		t.Fatal("knowledge:write is not read as the core reads it")
	}
	if ScopeAllows(pat, ScopeSecretWrite) || !ScopeAllows(&Principal{Via: "pat", Scopes: []string{"secret:write"}}, ScopeSecretWrite) {
		t.Fatal("secret:write is not read as the core reads it")
	}
	if ScopeAllows(&Principal{Via: "user"}, ScopeRunRead) {
		t.Fatal("a principal from Principals.ForUser passed; it is no caller")
	}
	// A schedule's credential is read as a token minted with
	// auth.ScheduleScopes: it starts and reads a run and attaches
	// knowledge, and writes nothing else, never as a session.
	sched := &Principal{Via: "schedule", ScheduleID: uuid.New(), Scopes: auth.ScheduleScopes()}
	for _, s := range []Scope{ScopeRunRead, ScopeRunWrite, ScopeKnowledgeRead} {
		if !ScopeAllows(sched, s) {
			t.Errorf("a schedule's credential was refused %s", s)
		}
	}
	for _, s := range []Scope{ScopeKnowledgeWrite, ScopeSecretWrite, auth.ScopeVoiceWrite, auth.ScopeOrgAdmin} {
		if ScopeAllows(sched, s) {
			t.Errorf("a schedule's credential passed %s; it carries only its own scopes", s)
		}
	}
	if ScopeAllows(&Principal{Via: "schedule"}, ScopeRunWrite) {
		t.Fatal("a schedule principal with no scopes passed, as if it were a session")
	}
}

// wrapperLike is the shape a knowledge wrapper takes: the WrapsKeys
// seam, satisfied with the aliases alone.
type wrapperLike struct{ noop }

func (wrapperLike) KeyWrapper() KeyWrapper { return certWrapper{} }

type certWrapper struct{}

func (certWrapper) Wrap(_ context.Context, o KeyOwner, _ []byte) (WrappedKey, error) {
	return WrappedKey{Kind: "certificate", Recipient: string(o.Kind)}, nil
}
func (certWrapper) Unwrap(context.Context, KeyOwner, WrappedKey) ([]byte, error) {
	return nil, ErrKeyNotOwner
}
func (certWrapper) Destroy(context.Context, KeyOwner) error { return nil }

var _ WrapsKeys = wrapperLike{}

// TestApplyExtensionsSetsTheKeyWrapper: a WrapsKeys extension's wrapper is
// the knowledge store's, in place of the deployment key's.
func TestApplyExtensionsSetsTheKeyWrapper(t *testing.T) {
	st := migratedStore(t)
	cfg := config.Default()
	cfg.DevMode = true
	cfg.Scan.OSVURL = "none"
	srv := api.New(cfg, st, slog.New(slog.DiscardHandler))
	if _, ok := srv.Knowledge().Wrapper().(*knowledge.DeploymentWrapper); !ok {
		t.Fatalf("with no extension the wrapper is %T, want the deployment key's", srv.Knowledge().Wrapper())
	}
	applyExtensions(srv, []Extension{wrapperLike{}})
	if _, ok := srv.Knowledge().Wrapper().(certWrapper); !ok {
		t.Fatalf("after applyExtensions the wrapper is %T, want the extension's", srv.Knowledge().Wrapper())
	}
}

// jobAdmitter is the shape a runs extension takes for the model-input
// routes: the AdmitsModelInput seam, with the aliases alone.
type jobAdmitter struct{ noop }

func (jobAdmitter) ModelInputCallers() ModelInputCallers { return jobCallers{} }

type jobCallers struct{}

func (jobCallers) AdmitModelInput(_ context.Context, cred string, call ModelInputCall) (string, *Refusal, error) {
	if call.Op == ModelInputOpSearch && call.Count > 10 {
		return "", &Refusal{Status: http.StatusTooManyRequests, Slug: "draft-searches-used"}, nil
	}
	return strings.TrimPrefix(cred, "agyj_"), nil, nil
}
func (jobCallers) RecordModelInput(context.Context, string, ModelInputUse) {}

var _ AdmitsModelInput = jobAdmitter{}

// TestApplyExtensionsSetsTheModelInputCallers: an AdmitsModelInput
// extension is what admits hosted jobs to the model-input routes; with none,
// nothing does.
func TestApplyExtensionsSetsTheModelInputCallers(t *testing.T) {
	cfg := config.Default()
	cfg.DevMode = true
	cfg.Scan.OSVURL = "none"
	srv := api.New(cfg, nil, slog.New(slog.DiscardHandler))
	if srv.ModelInputCallers() != nil {
		t.Fatal("a core server admits no job credentials")
	}
	applyExtensions(srv, []Extension{jobAdmitter{}})
	if _, ok := srv.ModelInputCallers().(jobCallers); !ok {
		t.Fatalf("after applyExtensions the callers are %T, want the extension's", srv.ModelInputCallers())
	}
	// An extension that answers no callers does not take away the ones
	// another gave.
	applyExtensions(srv, []Extension{noCallers{}})
	if _, ok := srv.ModelInputCallers().(jobCallers); !ok {
		t.Fatalf("an extension with nil callers left %T, want the first extension's to stay", srv.ModelInputCallers())
	}
}

// noCallers implements AdmitsModelInput and admits nobody.
type noCallers struct{ noop }

func (noCallers) Name() string                         { return "no-callers" }
func (noCallers) ModelInputCallers() ModelInputCallers { return nil }

// poolingResolver is the shape a resolver that pools knowledge takes:
// the PoolsKnowledge seam, with the aliases alone.
type poolingResolver struct{ tiered }

func (poolingResolver) KnowledgePool(_ context.Context, o KeyOwner) (KnowledgePool, error) {
	return KnowledgePool{Key: "org/pool", Owners: []KeyOwner{o}, Cap: Cap{Enabled: true, Max: 10 << 30}}, nil
}

var _ PoolsKnowledge = poolingResolver{}

// builder is the shape a hosted build takes over the knowledge store:
// it reads Deps.Knowledge and speaks only the seam's aliases.
type builder struct {
	noop
	store Knowledge
}

func (b *builder) Bind(d Deps) { b.store = d.Knowledge }

// TestBindHandsTheKnowledgeStore: a bound extension gets the core's
// knowledge store and can make a pack, put a tree in it — which is then
// scanning, with the registry's counts — and is refused its tree while it
// is scanned, all in the seam's own words.
func TestBindHandsTheKnowledgeStore(t *testing.T) {
	st := migratedStore(t)
	cfg := config.Default()
	cfg.DevMode = true
	cfg.Scan.OSVURL = "none"
	srv := api.New(cfg, st, slog.New(slog.DiscardHandler))
	b := &builder{}
	applyExtensions(srv, []Extension{b})
	if b.store == nil {
		t.Fatal("a server with a database handed out no knowledge store")
	}
	ctx := context.Background()
	owner := KeyOwner{Kind: KeyOwnerUser, ID: uuid.New()}
	p, err := b.store.Create(ctx, owner, "seam-"+owner.ID.String()[:8])
	if err != nil || p.State != KnowledgeEmpty {
		t.Fatalf("create: %+v %v", p, err)
	}
	files := []KnowledgeFile{
		{Path: "sources/a.md", Content: []byte("# A\n")},
		{Path: "wiki/index.md", Content: []byte("# Index\n")},
		{Path: "wiki/topics/a.md", Content: []byte("---\ntitle: A\n---\nA. [src: doc:a.md]\n")},
	}
	got, changed, err := b.store.Replace(ctx, owner, p.ID, "", files)
	if err != nil || !changed || got.State != KnowledgeScanning || got.Pages != 1 || got.Files != 3 {
		t.Fatalf("replace: %+v %v %v", got, changed, err)
	}
	if again, changed, err := b.store.Replace(ctx, owner, p.ID, "", files); err != nil || changed || again.Digest != got.Digest {
		t.Fatalf("the same tree again is unchanged, whatever its from: %+v %v %v", again, changed, err)
	}
	other := append([]KnowledgeFile{{Path: "sources/b.md", Content: []byte("# B\n")}}, files...)
	if _, _, err := b.store.Replace(ctx, owner, p.ID, "", other); !errors.Is(err, ErrKnowledgeChanged) {
		t.Fatalf("a stale replace: %v", err)
	}
	if _, _, err := b.store.Tree(ctx, owner, p.ID); !errors.Is(err, ErrKnowledgeScanning) {
		t.Fatalf("the tree of a scanning pack: %v", err)
	}
	if _, err := b.store.Pack(ctx, KeyOwner{Kind: KeyOwnerUser, ID: uuid.New()}, p.ID); !errors.Is(err, ErrKnowledgeNotFound) {
		t.Fatalf("another owner's read: %v", err)
	}
	u, err := b.store.Usage(ctx, owner)
	if err != nil || u.Used != got.Bytes {
		t.Fatalf("usage: %+v %v", u, err)
	}
}

// vaultLike is the shape a vault extension takes: it deletes an
// account's rows in the core's erasure transaction, through the aliases
// alone.
type vaultLike struct{ noop }

func (vaultLike) Name() string { return "vault" }
func (vaultLike) EraseAccount(_ context.Context, _ ErasureTx, _ uuid.UUID, kind AccountErasureKind) (int64, error) {
	if kind != AccountErased && kind != AccountDataCleared {
		return 0, errors.New("unknown clear")
	}
	return 0, nil
}

var _ ErasesAccounts = vaultLike{}

// TestApplyExtensionsRegistersTheAccountEraser: an ErasesAccounts extension
// is called from the erasure and the data clear; with none, nothing is.
func TestApplyExtensionsRegistersTheAccountEraser(t *testing.T) {
	cfg := config.Default()
	cfg.DevMode = true
	cfg.Scan.OSVURL = "none"
	srv := api.New(cfg, nil, slog.New(slog.DiscardHandler))
	applyExtensions(srv, []Extension{noop{}})
	if got := srv.AccountErasers(); len(got) != 0 {
		t.Fatalf("erasers with no ErasesAccounts extension: %v", got)
	}
	applyExtensions(srv, []Extension{vaultLike{}})
	if got := srv.AccountErasers(); len(got) != 1 || got[0] != "vault" {
		t.Fatalf("erasers = %v, want [vault]", got)
	}
}

// voiceWriter is the shape a hosted Voice Writer takes: it is handed
// the core's voice store, and admits the reviews the routes ask for.
type voiceWriter struct {
	noop
	store Voice
}

func (v *voiceWriter) Bind(d Deps)                  { v.store = d.Voice }
func (v *voiceWriter) VoiceAdmitter() VoiceAdmitter { return nil }

// stubVoiceJudge passes every voice.
type stubVoiceJudge struct{}

func (stubVoiceJudge) Scan(context.Context, string) judge.VoiceResult {
	sc := map[string]int{}
	for _, q := range judge.VoiceQuestions() {
		sc[q.ID] = 0
	}
	return judge.VoiceResult{Verdict: judge.VerdictPass, Model: judge.DefaultModel, QuestionSet: "sha256:stub", Scores: sc}
}
func (stubVoiceJudge) QuestionSet() string { return "sha256:stub" }

// TestBindHandsTheVoiceStore: a bound extension gets the core's voice
// store, proposes a Voice Writer run's output only as a build or an AI
// Edit, and reads a live voice only once it passed its review.
func TestBindHandsTheVoiceStore(t *testing.T) {
	st := migratedStore(t)
	cfg := config.Default()
	cfg.DevMode = true
	cfg.Scan.OSVURL = "none"
	srv := api.New(cfg, st, slog.New(slog.DiscardHandler))
	srv.SetVoiceJudge(stubVoiceJudge{})
	v := &voiceWriter{}
	applyExtensions(srv, []Extension{v})
	if v.store == nil {
		t.Fatal("a server with a database handed out no voice store")
	}
	ctx := context.Background()
	user := uuid.New()
	if err := st.Queries().CreateHandle(ctx, storegen.CreateHandleParams{ID: user, Handle: "vw-" + user.String()[:8], Kind: "user"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Queries().CreateUser(ctx, storegen.CreateUserParams{ID: user, Email: user.String() + "@example.test"}); err != nil {
		t.Fatal(err)
	}
	if _, err := v.store.Live(ctx, user); !errors.Is(err, ErrVoiceNotFound) {
		t.Fatalf("no voice yet: %v", err)
	}
	if _, err := v.store.Propose(ctx, user, []byte("# Voice\n"), voice.SourceEdit); err == nil {
		t.Fatal("a Voice Writer run proposed an edit")
	}
	var invalid *VoiceInvalidError
	if _, err := v.store.Propose(ctx, user, []byte(" "), VoiceSourceBuild); !errors.As(err, &invalid) {
		t.Fatalf("an empty voice: %v", err)
	}
	s, err := v.store.Propose(ctx, user, []byte("# Voice\n\nShort sentences.\n"), VoiceSourceBuild)
	if err != nil || s.Pending == nil || s.Pending.Source != VoiceSourceBuild || s.Live != nil {
		t.Fatalf("propose: %+v %v", s, err)
	}
	// Pending is never what a run attaches.
	if _, err := v.store.Live(ctx, user); !errors.Is(err, ErrVoiceNotFound) {
		t.Fatalf("a pending voice read as live: %v", err)
	}
	w := queue.NewRiverClient(st, nil)
	w.SetTestOnly(true)
	srv.Voice().RegisterHandlers(w)
	w.Drain(ctx, "sandbox")
	live, err := v.store.Live(ctx, user)
	if err != nil || string(live.Text) != "# Voice\n\nShort sentences.\n" || live.ReviewState != "passed" {
		t.Fatalf("live: %+v %v", live, err)
	}
	if _, err := v.store.State(ctx, uuid.New()); !errors.Is(err, ErrVoiceNotFound) {
		t.Fatalf("another person's voice: %v", err)
	}
}

// The voice store an extension is handed proposes a Voice Writer run's
// output only as a build or an AI edit: any other source is refused in the
// seam's own words before the store is asked, and those two reach the store
// (here one that is off, which answers for itself).
func TestVoiceStoreProposesOnlyTheSourcesAVoiceWriterHas(t *testing.T) {
	v := serverVoice{svc: &voice.Service{}}
	for _, c := range []struct {
		source  VoiceSource
		refused bool
	}{
		{VoiceSourceBuild, false},
		{VoiceSourceAIEdit, false},
		{voice.SourceEdit, true},
		{VoiceSource("upload"), true},
		{VoiceSource(""), true},
	} {
		_, err := v.Propose(context.Background(), uuid.New(), []byte("# Voice\n"), c.source)
		switch {
		case c.refused && (err == nil || errors.Is(err, ErrVoiceUnconfigured) || !strings.Contains(err.Error(), "proposes a voice as build or ai-edit")):
			t.Errorf("source %q: %v, want the seam to refuse it", c.source, err)
		case !c.refused && !errors.Is(err, ErrVoiceUnconfigured):
			t.Errorf("source %q: %v, want it handed to the store", c.source, err)
		}
	}
}

// metered records one counter on the meter it is bound with.
type metered struct {
	noop
	err error
}

func (*metered) Name() string { return "metered" }
func (m *metered) Bind(d Deps) {
	c, err := d.Meter.Int64Counter("MeteredThings", metric.WithDescription("things the stub counted"))
	if err != nil {
		m.err = err
		return
	}
	c.Add(context.Background(), 3, metric.WithAttributes(attribute.String("kind", "run")))
}

// TestBindHandsTheServersMeter: an extension bound to a server with a
// database and metrics records a counter on its meter, and the server's
// own /metrics serves it with the core's resource labels.
func TestBindHandsTheServersMeter(t *testing.T) {
	st := migratedStore(t)
	cfg := config.Default()
	cfg.DevMode = true
	cfg.Scan.OSVURL = "none"
	mx, err := metrics.New(t.Context(), metrics.Config{ServiceName: "agentryd", Role: "api", Env: "dev"})
	if err != nil {
		t.Fatalf("metrics: %v", err)
	}
	t.Cleanup(func() { _ = mx.Shutdown(context.Background()) })
	srv := api.New(cfg, st, slog.New(slog.DiscardHandler))
	srv.SetMetrics(mx)
	ext := &metered{}
	applyExtensions(srv, []Extension{ext})
	if ext.err != nil {
		t.Fatalf("the bound meter refused a counter: %v", ext.err)
	}

	rec := httptest.NewRecorder()
	api.NewHandler(srv).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/metrics answered %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "# TYPE MeteredThings counter") {
		t.Fatalf("the extension's counter is not on /metrics:\n%s", body)
	}
	if !strings.Contains(body, `MeteredThings{agentry_role="api",deployment_environment="dev",kind="run",service_name="agentryd"} 3`) {
		t.Fatalf("the extension's series is not the one it recorded, with the resource labels:\n%s", body)
	}
}

// designReader is the shape a hosted run takes for the report design:
// it is handed the core's report settings.
type designReader struct {
	noop
	settings ReportSettings
}

func (r *designReader) Bind(d Deps) { r.settings = d.ReportSettings }

// TestBindHandsTheReportSettings: a bound extension reads a person's
// report design as its canonical document, nil while they never chose
// one and again once they clear it, and another person's design is
// never theirs (no row is not Plain). Theme, the transitional read,
// answers the design's basedOn.
func TestBindHandsTheReportSettings(t *testing.T) {
	st := migratedStore(t)
	cfg := config.Default()
	cfg.DevMode = true
	cfg.Scan.OSVURL = "none"
	srv := api.New(cfg, st, slog.New(slog.DiscardHandler))
	r := &designReader{}
	applyExtensions(srv, []Extension{r})
	if r.settings == nil {
		t.Fatal("a server with a database handed out no report settings")
	}
	ctx := context.Background()
	mk := func(prefix string) uuid.UUID {
		id := uuid.New()
		if err := st.Queries().CreateHandle(ctx, storegen.CreateHandleParams{ID: id, Handle: prefix + id.String()[:8], Kind: "user"}); err != nil {
			t.Fatal(err)
		}
		if _, err := st.Queries().CreateUser(ctx, storegen.CreateUserParams{ID: id, Email: id.String() + "@example.test"}); err != nil {
			t.Fatal(err)
		}
		return id
	}
	user, other := mk("rt-"), mk("ro-")
	if got, err := r.settings.Design(ctx, user); err != nil || got != nil {
		t.Fatalf("never chosen: %q, %v", got, err)
	}
	if got, err := r.settings.Theme(ctx, user); err != nil || got != "" {
		t.Fatalf("never chosen: %q, %v", got, err)
	}
	classic, _ := reportdesign.Builtin("classic")
	technical, _ := reportdesign.Builtin("technical")
	technical.Name, technical.Accent = "Acme", "#0b5c55"
	if _, err := st.Queries().UpsertUserReportSettings(ctx, storegen.UpsertUserReportSettingsParams{UserID: other, Design: classic.Canonical()}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Queries().UpsertUserReportSettings(ctx, storegen.UpsertUserReportSettingsParams{UserID: user, Design: technical.Canonical()}); err != nil {
		t.Fatal(err)
	}
	if got, err := r.settings.Design(ctx, user); err != nil || !bytes.Equal(got, technical.Canonical()) {
		t.Fatalf("chosen: %s, %v", got, err)
	}
	if got, err := r.settings.Theme(ctx, user); err != nil || got != "technical" {
		t.Fatalf("chosen: %q, %v", got, err)
	}
	if got, err := r.settings.DesignWithLogo(ctx, user); err != nil || !bytes.Equal(got, technical.Canonical()) {
		t.Fatalf("chosen, no logo: %s, %v", got, err)
	}
	// A logo comes only with DesignWithLogo: Design stays what a reader
	// without logos can parse.
	var pb bytes.Buffer
	if err := png.Encode(&pb, image.NewNRGBA(image.Rect(0, 0, 8, 4))); err != nil {
		t.Fatal(err)
	}
	logo, err := reportdesign.NormalizeLogo(pb.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := logo.Decode()
	if _, err := st.Queries().SetUserReportLogo(ctx, storegen.SetUserReportLogoParams{UserID: user, Logo: raw}); err != nil {
		t.Fatal(err)
	}
	if got, err := r.settings.Design(ctx, user); err != nil || !bytes.Equal(got, technical.Canonical()) {
		t.Fatalf("Design with a logo stored: %s, %v", got, err)
	}
	withLogo := technical
	withLogo.Logo = logo
	if got, err := r.settings.DesignWithLogo(ctx, user); err != nil || !bytes.Equal(got, withLogo.Canonical()) {
		t.Fatalf("DesignWithLogo: %.200s, %v", got, err)
	}
	if _, err := st.Queries().DeleteUserReportSettings(ctx, user); err != nil {
		t.Fatal(err)
	}
	if got, err := r.settings.Design(ctx, user); err != nil || got != nil {
		t.Fatalf("cleared: %q, %v", got, err)
	}
	if got, _ := r.settings.Design(ctx, other); !bytes.Equal(got, classic.Canonical()) {
		t.Fatalf("the other person's design moved: %s", got)
	}
}

// membersReader keeps the membership door it was bound with.
type membersReader struct {
	noop
	members Members
}

func (m *membersReader) Name() string   { return "members-reader" }
func (m *membersReader) Bind(deps Deps) { m.members = deps.Members }

// TestBindHandsTheMembersDoor: a server with a database hands an extension
// the core's membership door, and its refusals are the ones this package
// names. What provisioning and deprovisioning do is the API's tests'.
func TestBindHandsTheMembersDoor(t *testing.T) {
	st := migratedStore(t)
	cfg := config.Default()
	cfg.DevMode = true
	cfg.Scan.OSVURL = "none"
	srv := api.New(cfg, st, slog.New(slog.DiscardHandler))
	m := &membersReader{}
	applyExtensions(srv, []Extension{m})
	if m.members == nil {
		t.Fatal("a server with a database handed out no membership door")
	}
	ctx := context.Background()
	// An organization with one admin, written the way the core's own
	// creation leaves it.
	orgID, adminID := uuid.New(), uuid.New()
	for _, stmt := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO handles (id, handle, kind) VALUES ($1, $2, 'org')`, []any{orgID, "mo-" + orgID.String()[:8]}},
		{`INSERT INTO orgs (id, display_name) VALUES ($1, 'Members door')`, []any{orgID}},
		{`INSERT INTO handles (id, handle, kind) VALUES ($1, $2, 'user')`, []any{adminID, "ma-" + adminID.String()[:8]}},
		{`INSERT INTO users (id, email, email_verified_at) VALUES ($1, $2, now())`, []any{adminID, adminID.String() + "@example.test"}},
		{`INSERT INTO memberships (org_id, user_id, role, state) VALUES ($1, $2, 'admin', 'active')`, []any{orgID, adminID}},
	} {
		if _, err := st.Pool().Exec(ctx, stmt.sql, stmt.args...); err != nil {
			t.Fatal(err)
		}
	}
	email := orgID.String()[:8] + "-person@example.test"
	userID, err := m.members.Provision(ctx, orgID, ProvisionedMember{Email: email, UserName: email})
	if err != nil {
		t.Fatalf("provision through the door: %v", err)
	}
	state := func() string {
		var s string
		if err := st.Pool().QueryRow(ctx, `SELECT state FROM memberships WHERE org_id = $1 AND user_id = $2`, orgID, userID).Scan(&s); err != nil {
			return ""
		}
		return s
	}
	if got := state(); got != "pending" {
		t.Fatalf("a member provisioned through the door is %q, want pending", got)
	}
	if kept, err := m.members.Deprovision(ctx, orgID, userID); err != nil || kept || state() != "" {
		t.Fatalf("deprovision through the door: kept %v, %v, membership %q; want it gone", kept, err, state())
	}
	if _, err := m.members.Provision(ctx, uuid.New(), ProvisionedMember{Email: "someone@example.test"}); !errors.Is(err, ErrOrgNotProvisionable) {
		t.Fatalf("provisioning into an unknown organization: %v, want ErrOrgNotProvisionable", err)
	}
	if kept, err := m.members.Deprovision(ctx, uuid.New(), uuid.New()); err != nil || kept {
		t.Fatalf("deprovisioning nobody: kept %v, %v; want a quiet no-op", kept, err)
	}
}
