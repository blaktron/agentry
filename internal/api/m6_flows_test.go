package api_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/queue"
	"github.com/blaktron/agentry/internal/webhook"
)

func tlsTrusting(ts *httptest.Server) *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(ts.Certificate())
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
}

// TestWebhookDeliveryViaQueue covers §9.3: a webhook created through the API is
// delivered by the queue worker to an https endpoint with a valid HMAC
// signature.
func TestWebhookDeliveryViaQueue(t *testing.T) {
	env := newTestEnv(t)
	owner := env.register("wh-owner")
	env.verifyEmail(owner)
	sess := env.login(owner)
	orgH := "whorg" + env.sfx
	orgID := env.createOrg(sess, orgH)

	var mu sync.Mutex
	var gotSig, gotEvent string
	var gotBody []byte
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		gotSig = r.Header.Get(webhook.SignatureHeader)
		gotEvent = r.Header.Get("X-Agentry-Event")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	var created struct {
		Id     string `json:"id"`
		Secret string `json:"secret"`
	}
	env.doJSON(sess, http.MethodPost, "/api/v1/orgs/"+orgH+"/webhooks",
		map[string]any{"url": ts.URL, "events": []string{"version.published"}}, &created, http.StatusCreated)
	if created.Secret == "" {
		t.Fatal("expected a signing secret")
	}

	// A dispatcher whose delivery client trusts the loopback TLS server.
	sealer, err := auth.NewSealer("", true) // same fixed dev key the server used
	if err != nil {
		t.Fatal(err)
	}
	q := queue.NewRiverClient(env.st, nil)
	q.SetTestOnly(true)
	disp := webhook.NewDispatcher(webhook.Deps{
		Store: env.st, Sealer: sealer, Queue: q,
		Client: webhook.NewHTTPClient(webhook.Guard{AllowLoopback: true}, tlsTrusting(ts)),
	})
	disp.RegisterHandlers(q)

	if err := disp.Emit(context.Background(), uuid.MustParse(orgID), "version.published",
		map[string]any{"version": "1.2.3"}); err != nil {
		t.Fatalf("emit: %v", err)
	}
	q.Drain(context.Background(), "core")

	mu.Lock()
	defer mu.Unlock()
	if gotEvent != "version.published" {
		t.Fatalf("event header = %q", gotEvent)
	}
	if err := webhook.Verify([]byte(created.Secret), gotBody, gotSig, time.Now()); err != nil {
		t.Fatalf("delivered signature invalid: %v (sig=%q)", err, gotSig)
	}

	// The delivery ledger records the success.
	var deliveries []struct {
		StatusCode  *int       `json:"statusCode"`
		DeliveredAt *time.Time `json:"deliveredAt"`
	}
	env.doJSON(sess, http.MethodGet, "/api/v1/orgs/"+orgH+"/webhooks/"+created.Id+"/deliveries", nil, &deliveries, http.StatusOK)
	if len(deliveries) == 0 || deliveries[0].DeliveredAt == nil || deliveries[0].StatusCode == nil || *deliveries[0].StatusCode != 200 {
		t.Fatalf("delivery ledger not updated: %+v", deliveries)
	}
}

// TestWebhookEventWiring covers that a state change that already happens
// (member.added) records a delivery for a subscribed endpoint (§9.3).
func TestWebhookEventWiring(t *testing.T) {
	env := newTestEnv(t)
	owner := env.register("we-owner")
	env.verifyEmail(owner)
	sess := env.login(owner)
	member := env.register("we-mem")
	orgH := "weorg" + env.sfx
	env.createOrg(sess, orgH)

	var created struct {
		Id string `json:"id"`
	}
	env.doJSON(sess, http.MethodPost, "/api/v1/orgs/"+orgH+"/webhooks",
		map[string]any{"url": "https://example.invalid/hook", "events": []string{"member.added"}}, &created, http.StatusCreated)

	// A membership becoming active fires member.added → a delivery row is
	// recorded. Since agentry#361 that happens when the invitation is
	// accepted, which is what joinOrg drives.
	env.joinOrg(sess, orgH, member)

	var deliveries []struct {
		EventType string `json:"eventType"`
	}
	env.doJSON(sess, http.MethodGet, "/api/v1/orgs/"+orgH+"/webhooks/"+created.Id+"/deliveries", nil, &deliveries, http.StatusOK)
	found := false
	for _, d := range deliveries {
		if d.EventType == "member.added" {
			found = true
		}
	}
	if !found {
		t.Fatalf("member.added delivery not recorded: %+v", deliveries)
	}
}

// TestAuditExport covers §12.6: an async export writes NDJSON to the blob store
// and reports completion with a download reference.
func TestAuditExport(t *testing.T) {
	var srvRef *api.Server
	env := newTestEnvWith(t, func(s *api.Server) { srvRef = s })
	owner := env.register("ae-owner")
	env.verifyEmail(owner)
	sess := env.login(owner)
	orgH := "aeorg" + env.sfx
	env.createOrg(sess, orgH) // this and membership changes generate audit events

	// Generate a few more org-scoped audit events.
	pawn := env.register("ae-pawn")
	env.joinOrg(sess, orgH, pawn)

	var exp struct {
		Id     string `json:"id"`
		Status string `json:"status"`
	}
	env.doJSON(sess, http.MethodPost, "/api/v1/orgs/"+orgH+"/audit/exports", map[string]any{}, &exp, http.StatusAccepted)
	if exp.Id == "" || exp.Status != "pending" {
		t.Fatalf("unexpected export accept: %+v", exp)
	}

	// Run the export job.
	q := queue.NewRiverClient(env.st, nil)
	q.SetTestOnly(true)
	srvRef.RegisterQueueHandlers(q)
	q.Drain(context.Background(), "core")

	var got struct {
		Status       string `json:"status"`
		EventCount   int    `json:"eventCount"`
		DownloadPath string `json:"downloadPath"`
	}
	env.doJSON(sess, http.MethodGet, "/api/v1/orgs/"+orgH+"/audit/exports/"+exp.Id, nil, &got, http.StatusOK)
	if got.Status != "completed" {
		t.Fatalf("export status = %q, want completed", got.Status)
	}
	if got.EventCount < 1 || got.DownloadPath == "" {
		t.Fatalf("export produced no events/path: %+v", got)
	}
}
