package api_test

// The webhook seam an extension reaches (for alert routing): an
// event delivered to one endpoint the organization named, through the core's transport — the
// same ledger row and the same queued job a subscribed endpoint gets — and
// nothing of the endpoint but its id, its URL, its events and its state
// crossing the seam. A probe extension exposes the seam over HTTP so it is
// exercised the way the closed build will use it.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/queue"
	"github.com/blaktron/agentry/internal/webhook"
)

type deliverProbe struct {
	Delivered bool `json:"delivered"`
}

func TestWebhookSeamDeliversToTheEndpointNamed(t *testing.T) {
	env := newTestEnvWith(t, func(s *api.Server) {
		s.RegisterExtension("probe", func(mux *http.ServeMux) {
			// POST /deliver {org, endpoint, event, data} → {delivered}.
			mux.HandleFunc("POST /deliver", func(w http.ResponseWriter, r *http.Request) {
				var in struct {
					Org      string         `json:"org"`
					Endpoint string         `json:"endpoint"`
					Event    string         `json:"event"`
					Data     map[string]any `json:"data"`
				}
				if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				oid, err1 := uuid.Parse(in.Org)
				eid, err2 := uuid.Parse(in.Endpoint)
				if err1 != nil || err2 != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				delivered, err := s.DeliverWebhook(r.Context(), oid, eid, in.Event, in.Data)
				if err != nil {
					http.Error(w, err.Error(), http.StatusUnprocessableEntity)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(deliverProbe{Delivered: delivered})
			})
			// GET /endpoints/{org} → the seam's list, encoded as is.
			mux.HandleFunc("GET /endpoints/{org}", func(w http.ResponseWriter, r *http.Request) {
				oid, _ := uuid.Parse(r.PathValue("org"))
				eps, err := s.WebhookEndpoints(r.Context(), oid)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(eps)
			})
		})
	})
	ownerH := env.register("ws-owner")
	env.verifyEmail(ownerH)
	owner := env.login(ownerH)
	orgH := "wsorg" + env.sfx
	orgID := env.createOrg(owner, orgH)

	// The organization's endpoint subscribes to version.published only:
	// the core's own emit of agent.dependency_alert would never reach it.
	var hook struct {
		Id string `json:"id"`
	}
	env.doJSON(owner, http.MethodPost, "/api/v1/orgs/"+orgH+"/webhooks", map[string]any{
		"url": "https://example.invalid/security", "events": []string{"version.published"},
	}, &hook, http.StatusCreated)

	deliver := func(t *testing.T, org, endpoint, event string) (int, deliverProbe, string) {
		t.Helper()
		res := env.do(owner, http.MethodPost, "/api/v1/x/probe/deliver",
			map[string]any{"org": org, "endpoint": endpoint, "event": event,
				"data": map[string]any{"agent": orgH + "/thing", "severity": "critical"}})
		defer func() { _ = res.Body.Close() }()
		var out deliverProbe
		if res.StatusCode == http.StatusOK {
			_ = json.NewDecoder(res.Body).Decode(&out)
			return res.StatusCode, out, ""
		}
		raw, _ := io.ReadAll(res.Body)
		return res.StatusCode, out, strings.TrimSpace(string(raw))
	}
	deliveries := func(t *testing.T) []struct {
		EventType string `json:"eventType"`
	} {
		t.Helper()
		var out []struct {
			EventType string `json:"eventType"`
		}
		env.doJSON(owner, http.MethodGet, "/api/v1/orgs/"+orgH+"/webhooks/"+hook.Id+"/deliveries", nil, &out, http.StatusOK)
		return out
	}

	// The extension names the endpoint: one delivery, in the endpoint's
	// own log, carrying the wire shape every delivery carries.
	code, out, _ := deliver(t, orgID, hook.Id, "agent.dependency_alert")
	if code != http.StatusOK || !out.Delivered {
		t.Fatalf("the organization's active endpoint: %d delivered=%t, want 200 delivered", code, out.Delivered)
	}
	got := deliveries(t)
	if len(got) != 1 || got[0].EventType != "agent.dependency_alert" {
		t.Fatalf("deliveries = %+v, want one agent.dependency_alert", got)
	}
	var payload struct {
		Event string            `json:"event"`
		ID    string            `json:"id"`
		Data  map[string]string `json:"data"`
	}
	var raw []byte
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT payload FROM webhook_deliveries WHERE endpoint_id = $1`, hook.Id).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Event != "agent.dependency_alert" || payload.ID == "" || payload.Data["severity"] != "critical" {
		t.Fatalf("the wire payload is %s, want the catalog's shape around the extension's data", raw)
	}

	// Another organization's endpoint is not this organization's: nothing
	// is recorded, and the extension is told only that nothing went.
	otherH := env.register("ws-other")
	env.verifyEmail(otherH)
	other := env.login(otherH)
	otherOrgH := "wsother" + env.sfx
	otherOrgID := env.createOrg(other, otherOrgH)
	code, out, _ = deliver(t, otherOrgID, hook.Id, "agent.dependency_alert")
	if code != http.StatusOK || out.Delivered {
		t.Fatalf("another organization naming this endpoint: %d delivered=%t, want 200 and not delivered", code, out.Delivered)
	}
	code, out, _ = deliver(t, orgID, uuid.New().String(), "agent.dependency_alert")
	if code != http.StatusOK || out.Delivered {
		t.Fatalf("an endpoint that does not exist: %d delivered=%t, want 200 and not delivered", code, out.Delivered)
	}

	// An event the catalog does not know is refused outright: what a
	// consumer is told to expect is the core's promise, not an extension's.
	code, _, msg := deliver(t, orgID, hook.Id, "alerts.routed")
	if code != http.StatusUnprocessableEntity || !strings.Contains(msg, "not an event of the webhook catalog") {
		t.Fatalf("an event outside the catalog: %d %q, want a refusal naming the catalog", code, msg)
	}

	// A switched-off endpoint is a destination gone stale: not written to.
	env.doJSON(owner, http.MethodPatch, "/api/v1/orgs/"+orgH+"/webhooks/"+hook.Id, map[string]any{
		"active": false,
	}, nil, http.StatusOK)
	code, out, _ = deliver(t, orgID, hook.Id, "agent.dependency_alert")
	if code != http.StatusOK || out.Delivered {
		t.Fatalf("an inactive endpoint: %d delivered=%t, want 200 and not delivered", code, out.Delivered)
	}
	if got := deliveries(t); len(got) != 1 {
		t.Fatalf("deliveries = %+v, want the one that went and none of the refused", got)
	}

	// The list an extension reads: the id, the URL, the events, the state
	// — and no secret, whatever the row holds.
	var eps []map[string]any
	env.doJSON(owner, http.MethodGet, "/api/v1/x/probe/endpoints/"+orgID, nil, &eps, http.StatusOK)
	if len(eps) != 1 || eps[0]["ID"] != hook.Id || eps[0]["URL"] != "https://example.invalid/security" || eps[0]["Active"] != false {
		t.Fatalf("endpoints = %v, want the one endpoint, inactive", eps)
	}
	for k := range eps[0] {
		if strings.Contains(strings.ToLower(k), "secret") {
			t.Fatalf("the seam describes an endpoint with %q", k)
		}
	}
	env.doJSON(owner, http.MethodGet, "/api/v1/x/probe/endpoints/"+uuid.New().String(), nil, &eps, http.StatusOK)
	if len(eps) != 0 {
		t.Fatalf("an unknown organization has endpoints: %v", eps)
	}
}

// A delivery the seam records rides the core's transport: the queued job
// signs it with the endpoint's secret and posts it with the event header
// a subscription's delivery carries, and the ledger records the outcome.
func TestWebhookSeamDeliveryRidesTheCoresTransport(t *testing.T) {
	env := newTestEnv(t)
	ownerH := env.register("wt-owner")
	env.verifyEmail(ownerH)
	owner := env.login(ownerH)
	orgH := "wtorg" + env.sfx
	env.createOrg(owner, orgH)

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

	// Subscribed to nothing the alert would reach on its own.
	var created struct {
		Id     string `json:"id"`
		Secret string `json:"secret"`
	}
	env.doJSON(owner, http.MethodPost, "/api/v1/orgs/"+orgH+"/webhooks",
		map[string]any{"url": ts.URL, "events": []string{"version.published"}}, &created, http.StatusCreated)

	sealer, err := auth.NewSealer("", true)
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

	if err := disp.Deliver(context.Background(), uuid.MustParse(created.Id), "agent.dependency_alert",
		map[string]any{"agent": orgH + "/thing", "severity": "critical"}); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	q.Drain(context.Background(), "core")

	mu.Lock()
	defer mu.Unlock()
	if gotEvent != "agent.dependency_alert" {
		t.Fatalf("event header = %q, want the event the extension delivered", gotEvent)
	}
	if err := webhook.Verify([]byte(created.Secret), gotBody, gotSig, time.Now()); err != nil {
		t.Fatalf("the routed delivery's signature does not verify with the endpoint's secret: %v", err)
	}
	var deliveries []struct {
		EventType   string     `json:"eventType"`
		StatusCode  *int       `json:"statusCode"`
		DeliveredAt *time.Time `json:"deliveredAt"`
	}
	env.doJSON(owner, http.MethodGet, "/api/v1/orgs/"+orgH+"/webhooks/"+created.Id+"/deliveries", nil, &deliveries, http.StatusOK)
	if len(deliveries) != 1 || deliveries[0].EventType != "agent.dependency_alert" || deliveries[0].DeliveredAt == nil || deliveries[0].StatusCode == nil || *deliveries[0].StatusCode != 200 {
		t.Fatalf("the endpoint's log = %+v, want the one routed delivery, delivered", deliveries)
	}
}
