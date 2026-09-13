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

var (
	_ Extension   = billingLike{}
	_ Admits      = billingLike{}
	_ Unthrottles = billingLike{}
	_ Binds       = (*bound)(nil)
)

// TestRegisterAuditActionKeepsTheExtensionPrefix: an extension may add its
// own actions to the audit catalog, only under its own name.
func TestRegisterAuditActionKeepsTheExtensionPrefix(t *testing.T) {
	RegisterAuditAction("billing", "billing.tier_set")
	for _, bad := range []AuditAction{"tier_set", "agent.update", "billing.", "billingx.tier_set"} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("action %q was accepted", bad)
				}
			}()
			RegisterAuditAction("billing", bad)
		}()
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
