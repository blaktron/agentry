package api_test

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/logevent"
	"github.com/blaktron/agentry/internal/queue"
	"github.com/blaktron/agentry/internal/webhook"
)

func tlsTrusting(ts *httptest.Server) *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(ts.Certificate())
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
}

// hookDispatcher is a dispatcher whose delivery client trusts the loopback
// TLS server, at a delivery rate the test names.
func hookDispatcher(t *testing.T, env *testEnv, ts *httptest.Server, perSecond float64, log *slog.Logger) (*webhook.Dispatcher, *queue.RiverClient) {
	t.Helper()
	sealer, err := auth.NewSealer("", true) // same fixed dev key the server used
	if err != nil {
		t.Fatal(err)
	}
	q := queue.NewRiverClient(env.st, nil)
	q.SetTestOnly(true)
	disp := webhook.NewDispatcher(webhook.Deps{
		Store: env.st, Sealer: sealer, Queue: q, Log: log, DeliveriesPerSecond: perSecond,
		Client: webhook.NewHTTPClient(webhook.Guard{AllowLoopback: true}, tlsTrusting(ts)),
	})
	disp.RegisterHandlers(q)
	t.Cleanup(func() { _ = disp.Close() })
	return disp, q
}

// orgOwner makes a person with an organization of their own (a person
// belongs to one at a time, and each organization has its own delivery rate).
func (env *testEnv) orgOwner(tag string) (owner caller, handle, id string) {
	env.t.Helper()
	h := env.register(tag)
	env.verifyEmail(h)
	owner = env.login(h)
	handle = tag + "org" + env.sfx
	return owner, handle, env.createOrg(owner, handle)
}

// ledgerRow is one row of an endpoint's delivery log as the database holds it.
type ledgerRow struct {
	ID          string
	EventType   string
	Attempt     int
	Status      *int32
	Error       *string
	DeliveredAt *time.Time
	NextRetryAt *time.Time
}

func (env *testEnv) ledger(t *testing.T, endpointID string) []ledgerRow {
	t.Helper()
	rows, err := env.st.Pool().Query(context.Background(),
		`SELECT id::text, event_type, attempt, status_code, error, delivered_at, next_retry_at FROM webhook_deliveries WHERE endpoint_id = $1 ORDER BY created_at, id`, endpointID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []ledgerRow
	for rows.Next() {
		var r ledgerRow
		if err := rows.Scan(&r.ID, &r.EventType, &r.Attempt, &r.Status, &r.Error, &r.DeliveredAt, &r.NextRetryAt); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

// jobOf is the queue's state for one delivery and every error it kept.
func (env *testEnv) jobOf(t *testing.T, deliveryID string) (state, errs string) {
	t.Helper()
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT state::text, coalesce(errors::text, '') FROM river_job WHERE kind = $1 AND args->>'delivery_id' = $2`,
		webhook.JobDeliver, deliveryID).Scan(&state, &errs); err != nil {
		t.Fatal(err)
	}
	return state, errs
}

var signatureRE = regexp.MustCompile(`^t=([0-9]+),v1=([0-9a-f]{64})$`)

// checkSignature recomputes the signature a receiver documents —
// HMAC-SHA256 over "<t>.<body>" with the endpoint's secret, sent as
// "t=<unix seconds>,v1=<lower-case hex>" — without the code that made it.
func checkSignature(t *testing.T, secret string, body []byte, header string, notBefore, notAfter time.Time) {
	t.Helper()
	m := signatureRE.FindStringSubmatch(header)
	if m == nil {
		t.Errorf("signature header = %q, want t=<unix>,v1=<64 lower-case hex digits>", header)
		return
	}
	ts, _ := strconv.ParseInt(m[1], 10, 64)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(m[1] + "."))
	mac.Write(body)
	if want := hex.EncodeToString(mac.Sum(nil)); m[2] != want {
		t.Errorf("signature v1 = %s, want HMAC-SHA256(secret, %q + body) = %s", m[2], m[1]+".", want)
	}
	if ts < notBefore.Unix() || ts > notAfter.Unix() {
		t.Errorf("signature time %d is outside the delivery's own window [%d, %d]", ts, notBefore.Unix(), notAfter.Unix())
	}
}

// TestWebhookDeliveryViaQueue: a webhook created through the API is
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
	var gotSig, gotEvent, gotType, gotAgent, gotDelivery string
	var gotBody []byte
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		gotSig = r.Header.Get(webhook.SignatureHeader)
		gotEvent = r.Header.Get("X-Agentry-Event")
		gotType = r.Header.Get("Content-Type")
		gotAgent = r.Header.Get("User-Agent")
		gotDelivery = r.Header.Get("X-Agentry-Delivery")
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
	var logs lockedBuffer
	disp, q := hookDispatcher(t, env, ts, 0, slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))

	emitted := time.Now()
	if err := disp.Emit(context.Background(), uuid.MustParse(orgID), "version.published",
		map[string]any{"version": "1.2.3"}); err != nil {
		t.Fatalf("emit: %v", err)
	}
	q.Drain(context.Background(), "core")
	drained := time.Now()

	mu.Lock()
	defer mu.Unlock()
	if gotEvent != "version.published" {
		t.Fatalf("event header = %q", gotEvent)
	}
	if err := webhook.Verify([]byte(created.Secret), gotBody, gotSig, time.Now()); err != nil {
		t.Fatalf("delivered signature invalid: %v (sig=%q)", err, gotSig)
	}
	checkSignature(t, created.Secret, gotBody, gotSig, emitted, drained)
	// A receiver that checks as documented refuses a changed body, another
	// secret, and a signature far from its own clock in either direction.
	for name, c := range map[string]struct {
		secret string
		body   []byte
		now    time.Time
	}{
		"a changed body":              {created.Secret, append([]byte(" "), gotBody...), time.Now()},
		"another secret":              {created.Secret + "x", gotBody, time.Now()},
		"a signature ten minutes old": {created.Secret, gotBody, time.Now().Add(10 * time.Minute)},
		"a signature from the future": {created.Secret, gotBody, time.Now().Add(-10 * time.Minute)},
	} {
		if err := webhook.Verify([]byte(c.secret), c.body, gotSig, c.now); err == nil {
			t.Errorf("Verify accepts %s", name)
		}
	}
	if gotType != "application/json" || gotAgent != "agentry-webhooks/1" {
		t.Errorf("Content-Type = %q, User-Agent = %q, want application/json and agentry-webhooks/1", gotType, gotAgent)
	}
	// The body is the wire shape a consumer is documented: the event, the
	// delivery's own id (also in the header, for dedup), when it was made,
	// and the data.
	var wire struct {
		Event     string            `json:"event"`
		ID        string            `json:"id"`
		CreatedAt time.Time         `json:"created_at"`
		Data      map[string]string `json:"data"`
	}
	if err := json.Unmarshal(gotBody, &wire); err != nil {
		t.Fatal(err)
	}
	if wire.Event != "version.published" || wire.ID == "" || wire.ID != gotDelivery || len(wire.Data) != 1 || wire.Data["version"] != "1.2.3" ||
		wire.CreatedAt.Before(emitted.Add(-time.Second)) || wire.CreatedAt.After(drained) {
		t.Errorf("wire payload = %s (delivery header %q), want version.published, an id equal to the header, now, and the data", gotBody, gotDelivery)
	}

	// The delivery ledger records the success.
	var deliveries []struct {
		ID          string     `json:"id"`
		Attempt     int        `json:"attempt"`
		EventType   string     `json:"eventType"`
		StatusCode  *int       `json:"statusCode"`
		DeliveredAt *time.Time `json:"deliveredAt"`
		Error       *string    `json:"error"`
	}
	env.doJSON(sess, http.MethodGet, "/api/v1/orgs/"+orgH+"/webhooks/"+created.Id+"/deliveries", nil, &deliveries, http.StatusOK)
	if len(deliveries) == 0 || deliveries[0].DeliveredAt == nil || deliveries[0].StatusCode == nil || *deliveries[0].StatusCode != 200 {
		t.Fatalf("delivery ledger not updated: %+v", deliveries)
	}
	if d := deliveries[0]; len(deliveries) != 1 || d.ID != wire.ID || d.Attempt != 1 || d.EventType != "version.published" || d.Error != nil ||
		d.DeliveredAt.Before(emitted.Add(-time.Second)) || d.DeliveredAt.After(drained) {
		t.Errorf("delivery ledger = %+v, want the one delivery %s, on its first attempt, no error, delivered now", deliveries, wire.ID)
	}
	if state, errs := env.jobOf(t, wire.ID); state != "completed" || strings.Contains(errs, "webhook") {
		t.Errorf("the queue's job = %s with errors %q, want completed and none", state, errs)
	}
	var line map[string]any
	for _, l := range strings.Split(logs.String(), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) == nil && m["msg"] == "webhook: delivery finished" && m["delivery"] == wire.ID {
			line = m
		}
	}
	if line == nil || line[logevent.Key] != string(logevent.WebhookDelivered) || line["outcome"] != "ok" || line["status"] != float64(200) ||
		line["org"] != orgID || line["attempt"] != float64(1) {
		t.Errorf("attempt line = %v, want %s, outcome ok, status 200, org %s, attempt 1", line, logevent.WebhookDelivered, orgID)
	}

	// An answer that is not a success is recorded as it came and retried,
	// never counted as delivered, and a redirect is not followed.
	t.Run("an answer that is not a success is recorded and retried", func(t *testing.T) {
		var hmu sync.Mutex
		hits := map[string]int{}
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hmu.Lock()
			hits[r.URL.Path]++
			hmu.Unlock()
			switch r.URL.Path {
			case "/broken":
				w.WriteHeader(http.StatusInternalServerError)
			case "/moved":
				http.Redirect(w, r, "/landing", http.StatusFound)
			}
		}))
		defer srv.Close()
		owner, handle, orgID := env.orgOwner("whz")
		disp, q := hookDispatcher(t, env, srv, 1000, nil)
		for _, c := range []struct {
			path, event string
			status      int32
		}{{"/broken", "version.rejected", 500}, {"/moved", "version.yanked", 302}} {
			var ep struct {
				Id string `json:"id"`
			}
			env.doJSON(owner, http.MethodPost, "/api/v1/orgs/"+handle+"/webhooks",
				map[string]any{"url": srv.URL + c.path, "events": []string{c.event}}, &ep, http.StatusCreated)
			if err := disp.Emit(context.Background(), uuid.MustParse(orgID), c.event, map[string]any{"n": 1}); err != nil {
				t.Fatal(err)
			}
			before := time.Now()
			q.Drain(context.Background(), "core")
			after := time.Now()
			rows := env.ledger(t, ep.Id)
			want := fmt.Sprintf("non-2xx status %d", c.status)
			if len(rows) != 1 || rows[0].Attempt != 1 || rows[0].Status == nil || *rows[0].Status != c.status || rows[0].Error == nil || *rows[0].Error != want ||
				rows[0].DeliveredAt != nil || rows[0].NextRetryAt == nil ||
				rows[0].NextRetryAt.Before(before.Add(2*time.Second-5*time.Millisecond)) || rows[0].NextRetryAt.After(after.Add(2*time.Second+5*time.Millisecond)) {
				t.Fatalf("%s: ledger = %+v, want one attempt answered %d, %q, not delivered, retry in two seconds", c.path, rows, c.status, want)
			}
			// The queue holds the job for its retry, with the failure kept.
			if state, errs := env.jobOf(t, rows[0].ID); state == "completed" || state == "discarded" || !strings.Contains(errs, fmt.Sprintf("status %d", c.status)) {
				t.Errorf("%s: the queue's job = %s with errors %q, want one waiting for its retry that kept the status", c.path, state, errs)
			}
		}
		hmu.Lock()
		defer hmu.Unlock()
		if hits["/broken"] != 1 || hits["/moved"] != 1 || hits["/landing"] != 0 {
			t.Errorf("requests = %v, want one each to /broken and /moved and none to a redirect's target", hits)
		}
	})

	// A delivery recorded for an endpoint that has since stopped being one
	// is logged in its ledger and never sent.
	t.Run("a delivery whose endpoint is no longer fit for it is recorded and not sent", func(t *testing.T) {
		var hits int
		var hmu sync.Mutex
		srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			hmu.Lock()
			hits++
			hmu.Unlock()
		}))
		defer srv.Close()
		owner, handle, orgID := env.orgOwner("whu")
		disp, q := hookDispatcher(t, env, srv, 1000, nil)
		for _, c := range []struct {
			name, event, want string
			spoil             func(id string)
		}{
			{"switched off", "version.rejected", "endpoint inactive", func(id string) {
				env.doJSON(owner, http.MethodPatch, "/api/v1/orgs/"+handle+"/webhooks/"+id, map[string]any{"active": false}, nil, http.StatusOK)
			}},
			{"not https", "version.yanked", "non-https url blocked", func(id string) {
				if _, err := env.st.Pool().Exec(context.Background(), `UPDATE webhook_endpoints SET url = 'http://127.0.0.1:9/hook' WHERE id = $1`, id); err != nil {
					t.Fatal(err)
				}
			}},
			{"secret that cannot be opened", "agent.quarantined", "secret unseal failed", func(id string) {
				if _, err := env.st.Pool().Exec(context.Background(), `UPDATE webhook_endpoints SET secret_enc = '\x0102'::bytea WHERE id = $1`, id); err != nil {
					t.Fatal(err)
				}
			}},
		} {
			var ep struct {
				Id string `json:"id"`
			}
			env.doJSON(owner, http.MethodPost, "/api/v1/orgs/"+handle+"/webhooks",
				map[string]any{"url": srv.URL + "/hook", "events": []string{c.event}}, &ep, http.StatusCreated)
			if err := disp.Emit(context.Background(), uuid.MustParse(orgID), c.event, map[string]any{"n": 1}); err != nil {
				t.Fatal(err)
			}
			c.spoil(ep.Id)
			q.Drain(context.Background(), "core")
			rows := env.ledger(t, ep.Id)
			if len(rows) != 1 || rows[0].Error == nil || *rows[0].Error != c.want || rows[0].Status != nil || rows[0].DeliveredAt != nil || rows[0].NextRetryAt != nil {
				t.Errorf("%s: ledger = %+v, want one row saying %q, with no answer and no retry", c.name, rows, c.want)
				continue
			}
			// It is not retried: the queue is done with it.
			if state, _ := env.jobOf(t, rows[0].ID); state != "completed" {
				t.Errorf("%s: the queue's job = %s, want completed", c.name, state)
			}
		}
		hmu.Lock()
		defer hmu.Unlock()
		if hits != 0 {
			t.Errorf("the endpoint's server was called %d times, want none", hits)
		}
	})

	// An organization's deliveries are paced by that organization alone: one
	// goes now, the rest wait for their retry, and another organization is
	// not made to wait for them.
	t.Run("an organization's deliveries are paced by its own rate", func(t *testing.T) {
		var hmu sync.Mutex
		hits := map[string]int{}
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hmu.Lock()
			hits[r.URL.Path]++
			hmu.Unlock()
		}))
		defer srv.Close()
		// A rate so slow that the one-delivery bucket never refills in the test.
		disp, q := hookDispatcher(t, env, srv, 0.001, nil)
		type orgEP struct{ org, ep string }
		var orgs []orgEP
		for _, tag := range []string{"whp", "whq"} {
			owner, handle, id := env.orgOwner(tag)
			var ep struct {
				Id string `json:"id"`
			}
			env.doJSON(owner, http.MethodPost, "/api/v1/orgs/"+handle+"/webhooks",
				map[string]any{"url": srv.URL + "/" + tag, "events": []string{"version.published"}}, &ep, http.StatusCreated)
			orgs = append(orgs, orgEP{id, ep.Id})
		}
		for i := 0; i < 3; i++ {
			if err := disp.Emit(context.Background(), uuid.MustParse(orgs[0].org), "version.published", map[string]any{"n": i}); err != nil {
				t.Fatal(err)
			}
		}
		if err := disp.Emit(context.Background(), uuid.MustParse(orgs[1].org), "version.published", map[string]any{"n": 0}); err != nil {
			t.Fatal(err)
		}
		q.Drain(context.Background(), "core")
		hmu.Lock()
		defer hmu.Unlock()
		if hits["/whp"] != 1 || hits["/whq"] != 1 {
			t.Errorf("requests = %v, want exactly one per organization", hits)
		}
		rows := env.ledger(t, orgs[0].ep)
		sent, waiting := 0, 0
		for _, r := range rows {
			state, errs := env.jobOf(t, r.ID)
			switch {
			case r.DeliveredAt != nil:
				sent++
			case r.Attempt == 0 && r.Status == nil && r.Error == nil && state != "completed" && state != "discarded" && strings.Contains(errs, "over the delivery rate"):
				waiting++
			}
		}
		if len(rows) != 3 || sent != 1 || waiting != 2 {
			t.Errorf("the busy organization's ledger = %+v: %d sent, %d waiting for their retry, want 1 and 2 of 3", rows, sent, waiting)
		}
		if other := env.ledger(t, orgs[1].ep); len(other) != 1 || other[0].DeliveredAt == nil {
			t.Errorf("the other organization's ledger = %+v, want its one delivery sent", other)
		}
	})
}

// TestWebhookEventWiring: a state change that already happens
// (member.added) records a delivery for a subscribed endpoint.
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
	// Three endpoints the event does not reach: one subscribed to another
	// event, one switched off, and one that belongs to another organization.
	var other, off, foreign struct {
		Id string `json:"id"`
	}
	env.doJSON(sess, http.MethodPost, "/api/v1/orgs/"+orgH+"/webhooks",
		map[string]any{"url": "https://example.invalid/other", "events": []string{"member.removed"}}, &other, http.StatusCreated)
	env.doJSON(sess, http.MethodPost, "/api/v1/orgs/"+orgH+"/webhooks",
		map[string]any{"url": "https://example.invalid/off", "events": []string{"member.added"}}, &off, http.StatusCreated)
	env.doJSON(sess, http.MethodPatch, "/api/v1/orgs/"+orgH+"/webhooks/"+off.Id, map[string]any{"active": false}, nil, http.StatusOK)
	ownerB, orgB, _ := env.orgOwner("we-b")
	env.doJSON(ownerB, http.MethodPost, "/api/v1/orgs/"+orgB+"/webhooks",
		map[string]any{"url": "https://example.invalid/foreign", "events": []string{"member.added"}}, &foreign, http.StatusCreated)

	// A membership becoming active fires member.added → a delivery row is
	// recorded. That happens when the invitation is accepted,
	// which is what joinOrg drives.
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
	if len(deliveries) != 1 {
		t.Errorf("the subscribed endpoint's deliveries = %+v, want only the one member.added", deliveries)
	}
	for name, id := range map[string]string{"an endpoint subscribed to another event": other.Id, "a switched-off endpoint": off.Id, "another organization's endpoint": foreign.Id} {
		if rows := env.ledger(t, id); len(rows) != 0 {
			t.Errorf("%s was sent member.added: %+v", name, rows)
		}
	}

	// What the delivery tells a consumer: who, in what role, and how they came.
	var payload []byte
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT payload FROM webhook_deliveries WHERE endpoint_id = $1`, created.Id).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	var wire struct {
		Event string            `json:"event"`
		Data  map[string]string `json:"data"`
	}
	if err := json.Unmarshal(payload, &wire); err != nil {
		t.Fatal(err)
	}
	var memberID string
	if err := env.st.Pool().QueryRow(context.Background(), `SELECT id::text FROM handles WHERE handle = $1`, member).Scan(&memberID); err != nil {
		t.Fatal(err)
	}
	if wire.Event != "member.added" || wire.Data["user"] != memberID || wire.Data["role"] != "member" || wire.Data["via"] != "invitation" || len(wire.Data) != 3 {
		t.Errorf("member.added payload = %s, want user %s, role member, via invitation", payload, memberID)
	}
}

// TestAuditExport: an async export writes NDJSON to the blob store
// and reports completion with a download reference.
func TestAuditExport(t *testing.T) {
	var srvRef *api.Server
	env := newTestEnvWith(t, func(s *api.Server) { srvRef = s })
	owner := env.register("ae-owner")
	env.verifyEmail(owner)
	sess := env.login(owner)
	orgH := "aeorg" + env.sfx
	orgID := env.createOrg(sess, orgH) // this and membership changes generate audit events

	// Generate a few more org-scoped audit events.
	pawn := env.register("ae-pawn")
	env.joinOrg(sess, orgH, pawn)
	// One of them carries a detail: the endpoint created, by host and events.
	env.doJSON(sess, http.MethodPost, "/api/v1/orgs/"+orgH+"/webhooks",
		map[string]any{"url": "https://hooks.example.test/in/tok_AE_secret?k=1", "events": []string{"version.published"}}, nil, http.StatusCreated)
	// Another organization with events of its own, which no export of this
	// one may hold or show.
	ownerB, orgBH, orgBID := env.orgOwner("ae-b")
	env.doJSON(ownerB, http.MethodPost, "/api/v1/orgs/"+orgBH+"/webhooks",
		map[string]any{"url": "https://hooks.example.test/b", "events": []string{"version.published"}}, nil, http.StatusCreated)

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

	// The export is the organization's own events, one JSON object per
	// line, at a key named for the organization and the export.
	if want := "audit-exports/" + orgID + "/" + exp.Id + ".ndjson"; got.DownloadPath != want {
		t.Errorf("download path = %q, want %q", got.DownloadPath, want)
	}
	readExport := func(key string) []map[string]any {
		t.Helper()
		rc, err := srvRef.Blobs().Get(context.Background(), key)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = rc.Close() }()
		var out []map[string]any
		sc := bufio.NewScanner(rc)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			var m map[string]any
			if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
				t.Fatalf("export line %q: %v", sc.Bytes(), err)
			}
			out = append(out, m)
		}
		if err := sc.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}
	lines := readExport(got.DownloadPath)
	if len(lines) != got.EventCount {
		t.Errorf("the export holds %d lines but reports %d events", len(lines), got.EventCount)
	}
	var ownerID string
	if err := env.st.Pool().QueryRow(context.Background(), `SELECT id::text FROM handles WHERE handle = $1`, owner).Scan(&ownerID); err != nil {
		t.Fatal(err)
	}
	actions := map[string]int{}
	var created map[string]any
	for _, l := range lines {
		if l["org_id"] != orgID {
			t.Errorf("an export of %s holds an event of %v: %v", orgID, l["org_id"], l)
		}
		for _, k := range []string{"id", "occurred_at", "actor_kind", "action"} {
			if v, _ := l[k].(string); v == "" {
				t.Errorf("export line lacks %s: %v", k, l)
			}
		}
		if _, err := time.Parse(time.RFC3339Nano, fmt.Sprint(l["occurred_at"])); err != nil {
			t.Errorf("occurred_at %v is not a time: %v", l["occurred_at"], err)
		}
		actions[fmt.Sprint(l["action"])]++
		if l["action"] == "org.create" {
			created = l
		}
	}
	// The organization's creation names who did it, what it was done to, and
	// carries the detail it was recorded with.
	if created == nil || created["actor_id"] != ownerID || created["actor_kind"] != "user" || created["target_kind"] != "org" || created["target_id"] != orgID {
		t.Errorf("the creation event = %v, want actor %s (user) on org %s", created, ownerID, orgID)
	}
	// The webhook's creation carries its detail through to the line.
	var hookLine map[string]any
	for _, l := range lines {
		if l["action"] == "webhook.create" {
			hookLine = l
		}
	}
	detail, _ := hookLine["detail"].(map[string]any)
	if hookLine == nil || detail["host"] != "https://hooks.example.test" || fmt.Sprint(detail["events"]) != "[version.published]" ||
		strings.Contains(fmt.Sprint(hookLine), "tok_AE_secret") {
		t.Errorf("the webhook's creation event = %v, want its detail (host and events, nothing of the path)", hookLine)
	}
	// Another organization's export is not readable through this one.
	env.doJSON(ownerB, http.MethodGet, "/api/v1/orgs/"+orgBH+"/audit/exports/"+exp.Id, nil, nil, http.StatusNotFound)
	// Asking for the export is itself an event of the organization, and the
	// export of it (taken after) holds it.
	var asked map[string]any
	for _, l := range lines {
		if l["action"] == "audit.export" && l["target_id"] == exp.Id {
			asked = l
		}
	}
	if asked == nil || asked["target_kind"] != "audit_export" || asked["actor_id"] != ownerID {
		t.Errorf("the export's own request is not in it: %v", asked)
	}
	var requestedBy string
	if err := env.st.Pool().QueryRow(context.Background(), `SELECT requested_by::text FROM audit_exports WHERE id = $1`, exp.Id).Scan(&requestedBy); err != nil || requestedBy != ownerID {
		t.Errorf("the export records who asked as %q (%v), want %s", requestedBy, err, ownerID)
	}

	// An action filter keeps only that action. Here: the requests for
	// exports (the first, this one and the next), which are all this
	// organization has recorded of that action.
	var filtered struct {
		Id string `json:"id"`
	}
	env.doJSON(sess, http.MethodPost, "/api/v1/orgs/"+orgH+"/audit/exports", map[string]any{"action": "audit.export"}, &filtered, http.StatusAccepted)

	// More events than one page of the export, all at one instant: the
	// export pages by (time, id), so none is skipped or written twice.
	const seeded = 2300
	if _, err := env.st.Pool().Exec(context.Background(),
		`INSERT INTO audit_events (id, occurred_at, actor_kind, org_id, action)
		 SELECT gen_random_uuid(), '2026-01-01T00:00:00Z', 'system', $1, 'test.seeded' FROM generate_series(1, $2)`, orgID, seeded); err != nil {
		t.Fatal(err)
	}
	if _, err := env.st.Pool().Exec(context.Background(),
		`INSERT INTO audit_events (id, occurred_at, actor_kind, org_id, action)
		 SELECT gen_random_uuid(), '2026-01-01T00:00:00Z', 'system', $1, 'test.seeded' FROM generate_series(1, 5)`, orgBID); err != nil {
		t.Fatal(err)
	}
	var paged struct {
		Id string `json:"id"`
	}
	env.doJSON(sess, http.MethodPost, "/api/v1/orgs/"+orgH+"/audit/exports", map[string]any{"action": "test.seeded"}, &paged, http.StatusAccepted)
	q.Drain(context.Background(), "core")

	var fgot, pgot struct {
		Status       string `json:"status"`
		EventCount   int    `json:"eventCount"`
		DownloadPath string `json:"downloadPath"`
	}
	env.doJSON(sess, http.MethodGet, "/api/v1/orgs/"+orgH+"/audit/exports/"+filtered.Id, nil, &fgot, http.StatusOK)
	env.doJSON(sess, http.MethodGet, "/api/v1/orgs/"+orgH+"/audit/exports/"+paged.Id, nil, &pgot, http.StatusOK)
	flines := readExport(fgot.DownloadPath)
	if fgot.Status != "completed" || fgot.EventCount != 3 || len(flines) != 3 {
		t.Fatalf("filtered export = %+v with %d lines, want the three export requests", fgot, len(flines))
	}
	for _, l := range flines {
		if l["action"] != "audit.export" {
			t.Errorf("the filtered export holds %v", l)
		}
	}
	plines := readExport(pgot.DownloadPath)
	seen := map[string]bool{}
	for _, l := range plines {
		id := fmt.Sprint(l["id"])
		if seen[id] || l["action"] != "test.seeded" {
			t.Errorf("the paged export holds %v (seen before: %t)", l, seen[id])
		}
		seen[id] = true
	}
	if pgot.Status != "completed" || pgot.EventCount != seeded || len(plines) != seeded || len(seen) != seeded {
		t.Errorf("paged export = %+v with %d lines (%d distinct), want all %d", pgot, len(plines), len(seen), seeded)
	}
}
