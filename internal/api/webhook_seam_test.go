package api_test

// The webhook seam an extension reaches (agentry#430, for M19's alert
// routing; plan organization-subscriptions.md §6): an event delivered to
// one endpoint the organization named, through the core's transport — the
// same ledger row and the same queued job a subscribed endpoint gets — and
// nothing of the endpoint but its id, its URL, its events and its state
// crossing the seam. A probe extension exposes the seam over HTTP so it is
// exercised the way the closed build will use it.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/notify"
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

// The dependency-alert kind: a routed alert goes under the person's
// dependency-alert switch, and DEV-099's rule holds for it as for billing.
func TestNotifierSeamSendsAsTheDependencyAlertKind(t *testing.T) {
	mails := &renderedNotifier{Notifier: notify.LogNotifier{}}
	env := newTestEnvWith(t, func(s *api.Server) {
		s.SetNotifier(mails)
		s.RegisterExtension("probe", func(mux *http.ServeMux) {
			mux.HandleFunc("POST /send", func(w http.ResponseWriter, r *http.Request) {
				var in struct {
					User string `json:"user"`
				}
				if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				uid, _ := uuid.Parse(in.User)
				sent, err := s.SendToUser(r.Context(), uid, "dependency_alert", "acme/thing declares a vulnerable server", "npm:left-pad@1.0.0 carries GHSA-x.")
				if err != nil {
					http.Error(w, err.Error(), http.StatusUnprocessableEntity)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(notifierProbe{Sent: sent})
			})
		})
	})
	staff := env.register("da-staff")
	env.makePlatformStaff(t, staff)
	caller := env.login(staff)
	send := func(userID string) notifierProbe {
		var out notifierProbe
		env.doJSON(caller, http.MethodPost, "/api/v1/x/probe/send", map[string]any{"user": userID}, &out, http.StatusOK)
		return out
	}

	verifiedH := env.register("da-verified")
	env.verifyEmail(verifiedH)
	if out := send(env.userID(verifiedH)); !out.Sent {
		t.Fatal("a verified person with the switch on was not sent the alert")
	}
	if mails.count() != 1 || mails.last().Kind != notify.KindDependencyAlert {
		t.Fatalf("the transport was handed %d messages, last %+v; want one as the dependency-alert kind", mails.count(), mails.last())
	}

	unverifiedH := env.register("da-unverified")
	if out := send(env.userID(unverifiedH)); out.Sent || mails.count() != 1 {
		t.Fatal("an unverified address was sent a routed alert")
	}

	env.doJSON(env.login(verifiedH), http.MethodPut, "/api/v1/user/notifications", map[string]any{
		"email": map[string]any{"dependencyAlerts": false, "quarantine": true, "reviewDecisions": true, "advisories": true, "orgInvites": true, "billing": true},
		"web":   map[string]any{"dependencyAlerts": true},
	}, nil, http.StatusOK)
	if out := send(env.userID(verifiedH)); out.Sent || mails.count() != 1 {
		t.Fatal("the dependency-alert switch off, and a routed alert went anyway")
	}
}
