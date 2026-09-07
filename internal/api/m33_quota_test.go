package api_test

// §19 delivery quota: 5 webhook deliveries/s per org.
//
// The dispatcher had no rate limit at all, so an org whose agents produced a
// burst of transitions would fan the whole burst at its endpoints at once.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/queue"
	"github.com/blaktron/agentry/internal/webhook"
)

// countingEndpoint accepts every delivery and counts them.
func countingEndpoint(t *testing.T) (*httptest.Server, func() int) {
	t.Helper()
	var mu sync.Mutex
	n := 0
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		n++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(ts.Close)
	return ts, func() int {
		mu.Lock()
		defer mu.Unlock()
		return n
	}
}

// registerWebhook creates a webhook endpoint for an org.
func (env *testEnv) registerWebhook(t *testing.T, sess caller, orgHandle, url string) {
	t.Helper()
	env.doJSON(sess, http.MethodPost, "/api/v1/orgs/"+orgHandle+"/webhooks",
		map[string]any{"url": url, "events": []string{"version.published"}}, nil, http.StatusCreated)
}

func TestWebhookDeliveriesAreRateLimitedPerOrg(t *testing.T) {
	env := newTestEnv(t)
	owner := env.register("whrate-o")
	env.verifyEmail(owner)
	sess := env.login(owner)
	orgH := "whrateorg" + env.sfx
	orgID := env.createOrg(sess, orgH)

	ts, delivered := countingEndpoint(t)
	env.registerWebhook(t, sess, orgH, ts.URL)

	sealer, err := auth.NewSealer("", true)
	if err != nil {
		t.Fatal(err)
	}
	q := queue.NewRiverClient(env.st, nil)
	q.SetTestOnly(true)
	disp := webhook.NewDispatcher(webhook.Deps{
		Store: env.st, Sealer: sealer, Queue: q,
		Client: webhook.NewHTTPClient(webhook.Guard{AllowLoopback: true}, tlsTrusting(ts)),
		// 1/s with the shipped burst of 1: the first delivery goes, the rest
		// are deferred. Using the §19 value of 5 would need a full second of
		// wall clock to distinguish "throttled" from "slow".
		DeliveriesPerSecond: 1,
	})
	t.Cleanup(func() { _ = disp.Close() })
	disp.RegisterHandlers(q)

	ctx := context.Background()
	const emitted = 6
	for range emitted {
		if err := disp.Emit(ctx, uuid.MustParse(orgID), "version.published",
			map[string]any{"version": "1.0.0"}); err != nil {
			t.Fatalf("emit: %v", err)
		}
	}
	// Drain claims every available job once; the throttled ones return an
	// error, which re-queues them with backoff rather than dropping them.
	q.Drain(ctx, "core")

	if got := delivered(); got == 0 {
		t.Fatal("nothing was delivered at all")
	} else if got >= emitted {
		t.Errorf("%d of %d deliveries went out in one drain; the §19 per-org "+
			"rate limit is not throttling", got, emitted)
	}

	// Throttled deliveries must be DEFERRED, not dropped: the ledger still
	// holds them and the queue still owns them.
	var deliveries []struct {
		DeliveredAt *string `json:"deliveredAt"`
	}
	env.doJSON(sess, http.MethodGet, "/api/v1/orgs/"+orgH+"/webhooks/"+
		env.firstWebhookID(t, sess, orgH)+"/deliveries", nil, &deliveries, http.StatusOK)
	if len(deliveries) != emitted {
		t.Errorf("ledger has %d rows, want %d — a throttled delivery must be "+
			"recorded and retried, never dropped", len(deliveries), emitted)
	}
}

// One org's burst must not spend another org's budget.
func TestWebhookRateLimitIsPerOrgNotGlobal(t *testing.T) {
	env := newTestEnv(t)
	owner := env.register("whiso-o")
	env.verifyEmail(owner)
	sess := env.login(owner)

	orgA := "whisoa" + env.sfx
	orgB := "whisob" + env.sfx
	idA := env.createOrg(sess, orgA)
	idB := env.createOrg(sess, orgB)

	tsA, deliveredA := countingEndpoint(t)
	tsB, deliveredB := countingEndpoint(t)
	env.registerWebhook(t, sess, orgA, tsA.URL)
	env.registerWebhook(t, sess, orgB, tsB.URL)

	sealer, err := auth.NewSealer("", true)
	if err != nil {
		t.Fatal(err)
	}
	q := queue.NewRiverClient(env.st, nil)
	q.SetTestOnly(true)
	// One client that trusts both loopback servers: they share a cert pool
	// only if we build it from both, so use the permissive dev guard with A's
	// pool and register B's cert too.
	disp := webhook.NewDispatcher(webhook.Deps{
		Store: env.st, Sealer: sealer, Queue: q,
		Client:              webhook.NewHTTPClient(webhook.Guard{AllowLoopback: true}, tlsTrustingBoth(tsA, tsB)),
		DeliveriesPerSecond: 1,
	})
	t.Cleanup(func() { _ = disp.Close() })
	disp.RegisterHandlers(q)

	ctx := context.Background()
	// Exhaust org A's budget, then emit one for org B.
	for range 4 {
		if err := disp.Emit(ctx, uuid.MustParse(idA), "version.published", map[string]any{"v": "1"}); err != nil {
			t.Fatalf("emit A: %v", err)
		}
	}
	if err := disp.Emit(ctx, uuid.MustParse(idB), "version.published", map[string]any{"v": "1"}); err != nil {
		t.Fatalf("emit B: %v", err)
	}
	q.Drain(ctx, "core")

	if deliveredA() == 0 {
		t.Error("org A received nothing")
	}
	if deliveredB() != 1 {
		t.Errorf("org B received %d deliveries, want 1 — B's budget was spent by A", deliveredB())
	}
}

// firstWebhookID returns the org's only webhook endpoint id.
func (env *testEnv) firstWebhookID(t *testing.T, sess caller, orgHandle string) string {
	t.Helper()
	var list []struct {
		Id string `json:"id"`
	}
	env.doJSON(sess, http.MethodGet, "/api/v1/orgs/"+orgHandle+"/webhooks", nil, &list, http.StatusOK)
	if len(list) == 0 {
		t.Fatalf("org %s has no webhooks", orgHandle)
	}
	return list[0].Id
}

// tlsTrustingBoth trusts two loopback test servers with one client.
func tlsTrustingBoth(a, b *httptest.Server) *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(a.Certificate())
	pool.AddCert(b.Certificate())
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
}
