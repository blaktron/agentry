package extension

import (
	"context"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/knowledge"
	"github.com/blaktron/agentry/internal/queue"
)

// A minimal extension compiles against the interface using only the
// aliases this package exports — what a closed module outside the core
// can do.
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

// billingLike is the shape the billing extension takes (plan
// subscription-tiers §5.1, §5.5): the optional seams, satisfied with the
// aliases alone. It must compile; the behaviour is the API's tests.
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

// tiered is the shape a closed resolver takes: the core's, with Features
// answered by the extension. It must compile against the aliases alone.
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
	srv := api.New(cfg, nil, slog.New(slog.DiscardHandler))
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
	if !audit.Registered("bound.tier_set") {
		t.Fatal("the extension's audit action is not in the catalog")
	}
	if err := ext.deps.Audit.Write(context.Background(), AuditEvent{Action: "bound.tier_set", ActorKind: ActorSystem}); err == nil {
		t.Fatal("an audit write with no database must fail, not vanish")
	}
}

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
}

type countingQueue struct {
	mu    sync.Mutex
	n     int
	kind  string
	queue string
}

func (c *countingQueue) Enqueue(_ context.Context, kind, queueName string, _ any, _ ...queue.EnqueueOption) (uuid.UUID, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n++
	c.kind, c.queue = kind, queueName
	return uuid.New(), nil
}
func (c *countingQueue) Register(string, queue.Handler)        {}
func (c *countingQueue) Work(context.Context, ...string) error { return nil }
func (c *countingQueue) count() int                            { c.mu.Lock(); defer c.mu.Unlock(); return c.n }
func (c *countingQueue) last() (string, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.kind, c.queue
}

func TestNoopSatisfiesTheInterface(t *testing.T) {
	var e Extension = noop{}
	if e.Name() != "noop" || e.Migrations() != nil || e.Entitlements() != nil || e.Hooks().Event == nil {
		t.Fatal("unexpected zero behaviour")
	}
}

// TestParseQueues pins the worker's --queues contract (agentry#312): a
// subset of the queues that exist, in the order given, duplicates folded;
// an unknown name — "judge" included, which has no queue — is refused
// rather than drained as nothing; empty means both.
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
		{"judge", nil, `"judge" is not a queue`},
		{"core,scan", nil, `"scan" is not a queue`},
		{" , ", nil, "names no queue"},
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
// through the seam alone (agentry#348): nobody anonymous; a session,
// which has the account's full authority; a PAT only with the scope.
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
}

// wrapperLike is the shape SecureAgentry's knowledge wrapper takes (plan
// knowledge.md §4.4): the WrapsKeys seam, satisfied with the aliases alone.
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

// poolingResolver is the shape a closed resolver that pools knowledge takes
// (agentry#612): the PoolsKnowledge seam, with the aliases alone.
type poolingResolver struct{ tiered }

func (poolingResolver) KnowledgePool(_ context.Context, o KeyOwner) (KnowledgePool, error) {
	return KnowledgePool{Key: "org/pool", Owners: []KeyOwner{o}, Cap: Cap{Enabled: true, Max: 10 << 30}}, nil
}

var _ PoolsKnowledge = poolingResolver{}
