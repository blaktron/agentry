package api_test

// The notifier seam an extension reaches (agentry#366, M15; plan
// organization-subscriptions.md §5.8, D17): a message the extension
// composed goes to a person only under the core's rule — DEV-099's
// verified address, and the person's switch for the kind — through the
// core's transport, in the core's frame. A probe extension exposes the
// seam over HTTP so it is exercised the way the billing extension will.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/notify"
)

// renderedNotifier records what the core's transport was handed.
type renderedNotifier struct {
	notify.Notifier
	mu   sync.Mutex
	sent []notify.RenderedNotice
}

func (n *renderedNotifier) Rendered(_ context.Context, r notify.RenderedNotice) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.sent = append(n.sent, r)
	return nil
}

func (n *renderedNotifier) count() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.sent)
}

func (n *renderedNotifier) last() notify.RenderedNotice {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.sent[len(n.sent)-1]
}

// userID resolves a registered handle to its id, as an extension holds
// people by id and never by handle.
func (env *testEnv) userID(handle string) string {
	env.t.Helper()
	var id string
	if err := env.st.Pool().QueryRow(context.Background(), `SELECT id FROM handles WHERE handle = $1`, handle).Scan(&id); err != nil {
		env.t.Fatalf("id of %s: %v", handle, err)
	}
	return id
}

// notifierProbe is the probe's answer: whether the core sent the message.
type notifierProbe struct {
	Sent bool `json:"sent"`
}

func TestNotifierSeamSendsUnderTheCoresRule(t *testing.T) {
	mails := &renderedNotifier{Notifier: notify.LogNotifier{}}
	env := newTestEnvWith(t, func(s *api.Server) {
		s.SetNotifier(mails)
		s.RegisterExtension("probe", func(mux *http.ServeMux) {
			// POST /send {user, kind, subject, text} → {sent}.
			mux.HandleFunc("POST /send", func(w http.ResponseWriter, r *http.Request) {
				var in struct {
					User    string `json:"user"`
					Kind    string `json:"kind"`
					Subject string `json:"subject"`
					Text    string `json:"text"`
				}
				if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				uid, err := uuid.Parse(in.User)
				if err != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				sent, err := s.SendToUser(r.Context(), uid, in.Kind, in.Subject, in.Text)
				if err != nil {
					http.Error(w, err.Error(), http.StatusUnprocessableEntity)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(notifierProbe{Sent: sent})
			})
		})
	})
	staff := env.register("ns-staff")
	env.makePlatformStaff(t, staff)
	caller := env.login(staff)

	send := func(t *testing.T, userID, kind, subject, text string) (int, notifierProbe, string) {
		t.Helper()
		res := env.do(caller, http.MethodPost, "/api/v1/x/probe/send",
			map[string]any{"user": userID, "kind": kind, "subject": subject, "text": text})
		defer func() { _ = res.Body.Close() }()
		var out notifierProbe
		if res.StatusCode == http.StatusOK {
			_ = json.NewDecoder(res.Body).Decode(&out)
			return res.StatusCode, out, ""
		}
		raw, _ := io.ReadAll(res.Body)
		return res.StatusCode, out, strings.TrimSpace(string(raw))
	}

	// A verified address with the switch on: the message goes, in the
	// core's frame, as the kind it was sent as.
	verifiedH := env.register("ns-verified")
	env.verifyEmail(verifiedH)
	verifiedID := env.userID(verifiedH)
	code, out, _ := send(t, verifiedID, "billing", "Your payment failed", "The card on file was declined.\nUpdate it on the console.")
	if code != http.StatusOK || !out.Sent {
		t.Fatalf("a verified, opted-in person: %d sent=%t, want 200 sent", code, out.Sent)
	}
	if mails.count() != 1 {
		t.Fatalf("the transport was handed %d messages, want 1", mails.count())
	}
	got := mails.last()
	if got.Kind != notify.KindBilling || got.Subject != "Your payment failed" || got.ToEmail == "" {
		t.Fatalf("the transport was handed %+v", got)
	}
	if got.ToEmail != verifiedH+"@example.test" {
		t.Fatalf("sent to %q, want the person's own address", got.ToEmail)
	}

	// DEV-099: an unverified address gets nothing, and the extension is
	// told only that nothing went — not why.
	unverifiedH := env.register("ns-unverified")
	code, out, _ = send(t, env.userID(unverifiedH), "billing", "Your payment failed", "x")
	if code != http.StatusOK || out.Sent {
		t.Fatalf("an unverified address: %d sent=%t, want 200 and not sent", code, out.Sent)
	}
	if mails.count() != 1 {
		t.Fatalf("the transport was handed a message for an unverified address")
	}

	// The person's switch: billing off means no billing mail, and nothing
	// else about them changes.
	env.doJSON(env.login(verifiedH), http.MethodPut, "/api/v1/user/notifications", map[string]any{
		"email": map[string]any{"dependencyAlerts": true, "quarantine": true, "reviewDecisions": true, "advisories": true, "orgInvites": true, "billing": false},
		"web":   map[string]any{"dependencyAlerts": true},
	}, nil, http.StatusOK)
	code, out, _ = send(t, verifiedID, "billing", "Seats reached", "x")
	if code != http.StatusOK || out.Sent {
		t.Fatalf("billing switched off: %d sent=%t, want not sent", code, out.Sent)
	}
	if mails.count() != 1 {
		t.Fatal("the transport was handed a message the person switched off")
	}

	// A kind the core did not give the extension is refused outright: a
	// billing notice cannot dress itself as a quarantine, and the
	// person's quarantine switch — still on — does not let it through.
	code, _, msg := send(t, verifiedID, "quarantine", "Pulled", "x")
	if code != http.StatusUnprocessableEntity || !strings.Contains(msg, "not a kind an extension may send as") {
		t.Fatalf("an extension sending as the core's own kind: %d %q, want a refusal naming the kind", code, msg)
	}
	code, _, _ = send(t, verifiedID, "", "Untitled", "x")
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("an empty kind: %d, want a refusal", code)
	}
	if mails.count() != 1 {
		t.Fatal("a refused kind reached the transport")
	}

	// The dependency-alert kind (agentry#430, M19): a routed alert goes
	// under the person's dependency-alert switch — on, it goes as that
	// kind; off, it does not; and an unverified address gets nothing.
	code, out, _ = send(t, verifiedID, "dependency_alert", "acme/thing declares a vulnerable server", "npm:left-pad@1.0.0 carries GHSA-x.")
	if code != http.StatusOK || !out.Sent || mails.count() != 2 || mails.last().Kind != notify.KindDependencyAlert {
		t.Fatalf("a routed alert to a verified, opted-in person: %d sent=%t, %d messages, last kind %q", code, out.Sent, mails.count(), mails.last().Kind)
	}
	code, out, _ = send(t, env.userID(unverifiedH), "dependency_alert", "acme/thing declares a vulnerable server", "x")
	if code != http.StatusOK || out.Sent || mails.count() != 2 {
		t.Fatal("an unverified address was sent a routed alert")
	}
	env.doJSON(env.login(verifiedH), http.MethodPut, "/api/v1/user/notifications", map[string]any{
		"email": map[string]any{"dependencyAlerts": false},
	}, nil, http.StatusOK)
	code, out, _ = send(t, verifiedID, "dependency_alert", "acme/thing declares a vulnerable server", "x")
	if code != http.StatusOK || out.Sent || mails.count() != 2 {
		t.Fatal("the dependency-alert switch off, and a routed alert went anyway")
	}

	// The schedule kind (agentry#1002, plan quickagent-scheduling D9): a
	// failed fire or a pause goes under the person's schedules switch —
	// on (the default, with billing and dependency alerts already off),
	// it goes as that kind; off, it does not; an unverified address gets
	// nothing.
	code, out, _ = send(t, verifiedID, "schedule", "A scheduled run failed", "acme/report at 07:00 UTC: the release is gone.")
	if code != http.StatusOK || !out.Sent || mails.count() != 3 || mails.last().Kind != notify.KindSchedule {
		t.Fatalf("a schedule notice to a verified, opted-in person: %d sent=%t, %d messages, last kind %q", code, out.Sent, mails.count(), mails.last().Kind)
	}
	code, out, _ = send(t, env.userID(unverifiedH), "schedule", "A scheduled run failed", "x")
	if code != http.StatusOK || out.Sent || mails.count() != 3 {
		t.Fatal("an unverified address was sent a schedule notice")
	}
	env.doJSON(env.login(verifiedH), http.MethodPut, "/api/v1/user/notifications", map[string]any{
		"email": map[string]any{"dependencyAlerts": false, "quarantine": true, "reviewDecisions": true, "advisories": true, "orgInvites": true, "schedules": false},
		"web":   map[string]any{"dependencyAlerts": true},
	}, nil, http.StatusOK)
	code, out, _ = send(t, verifiedID, "schedule", "A schedule paused", "x")
	if code != http.StatusOK || out.Sent || mails.count() != 3 {
		t.Fatal("the schedules switch off, and a schedule notice went anyway")
	}
	// "schedules" is the switch's name, not a kind an extension sends as.
	code, _, _ = send(t, verifiedID, "schedules", "A schedule paused", "x")
	if code != http.StatusUnprocessableEntity || mails.count() != 3 {
		t.Fatalf("the switch's own name as a kind: %d, want a refusal", code)
	}
}

func TestNotifierSeamNamesActiveAdminsOnly(t *testing.T) {
	env := newTestEnvWith(t, func(s *api.Server) {
		s.RegisterExtension("probe", func(mux *http.ServeMux) {
			mux.HandleFunc("GET /admins/{org}", func(w http.ResponseWriter, r *http.Request) {
				oid, _ := uuid.Parse(r.PathValue("org"))
				ids, err := s.OrgAdminIDs(r.Context(), oid)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(ids)
			})
		})
	})
	founderH := env.register("na-founder")
	env.verifyEmail(founderH)
	admin := env.login(founderH)
	orgH := "naorg" + env.sfx
	orgID := env.createOrg(admin, orgH)

	memberH := env.register("na-member")
	env.verifyEmail(memberH)
	env.seedMembership(orgH, memberH, "member", "active")
	pendingAdminH := env.register("na-pending-admin")
	env.verifyEmail(pendingAdminH)
	env.seedMembership(orgH, pendingAdminH, "admin", "pending")
	secondAdminH := env.register("na-second-admin")
	env.verifyEmail(secondAdminH)
	env.seedMembership(orgH, secondAdminH, "admin", "active")
	// A suspended account is not told the organization's business, even
	// with an active admin membership and a verified address: the same
	// condition ListOrgAdminsForMail and the last-admin guard carry.
	suspendedH := env.register("na-suspended-admin")
	env.verifyEmail(suspendedH)
	env.seedMembership(orgH, suspendedH, "admin", "active")
	if _, err := env.st.Pool().Exec(context.Background(), `UPDATE users SET state = 'suspended' WHERE id = $1`, env.userID(suspendedH)); err != nil {
		t.Fatal(err)
	}

	var ids []string
	env.doJSON(admin, http.MethodGet, "/api/v1/x/probe/admins/"+orgID, nil, &ids, http.StatusOK)
	want := map[string]bool{env.userID(founderH): true, env.userID(secondAdminH): true}
	if len(ids) != 2 || !want[ids[0]] || !want[ids[1]] {
		t.Fatalf("admins = %v, want the founder and the second admin only (no member, no pending admin, no suspended admin)", ids)
	}

	// An organization that does not exist is nobody, not an error: the
	// seam gives no way to tell one from the other.
	env.doJSON(admin, http.MethodGet, "/api/v1/x/probe/admins/"+uuid.New().String(), nil, &ids, http.StatusOK)
	if len(ids) != 0 {
		t.Fatalf("an unknown organization has admins: %v", ids)
	}
}

// The settings round trip for the switches a client may omit, and the
// hazard they were built to avoid: a client that predates a switch and
// writes the other settings back leaves it as it was, rather than turning
// it off by omission (agentry#344's shape). billing (agentry#366) and
// schedules (agentry#1002) each, and neither write touches the other.
func TestOptionalSwitchesSurviveAnOlderClientsWrite(t *testing.T) {
	for _, field := range []string{"billing", "schedules"} {
		t.Run(field, func(t *testing.T) {
			env := newTestEnv(t)
			h := env.register("bs-person")
			env.verifyEmail(h)
			sess := env.login(h)
			other := map[string]string{"billing": "schedules", "schedules": "billing"}[field]

			var got struct {
				Email map[string]*bool `json:"email"`
			}
			value := func() *bool { return got.Email[field] }
			env.doJSON(sess, http.MethodGet, "/api/v1/user/notifications", nil, &got, http.StatusOK)
			if v := value(); v == nil || !*v {
				t.Fatalf("a new account's %s switch = %v, want on by default", field, v)
			}

			// Off, explicitly.
			env.doJSON(sess, http.MethodPut, "/api/v1/user/notifications", map[string]any{
				"email": map[string]any{"dependencyAlerts": true, "quarantine": true, "reviewDecisions": true, "advisories": true, "orgInvites": true, field: false},
				"web":   map[string]any{"dependencyAlerts": true},
			}, &got, http.StatusOK)
			if v := value(); v == nil || *v {
				t.Fatalf("after switching %s off: %v", field, v)
			}
			if v := got.Email[other]; v == nil || !*v {
				t.Fatalf("switching %s off switched %s off: %v", field, other, v)
			}

			// An older client writes everything it knows, which does not
			// include the switch: it stays off.
			env.doJSON(sess, http.MethodPut, "/api/v1/user/notifications", map[string]any{
				"email": map[string]any{"dependencyAlerts": false, "quarantine": true, "reviewDecisions": true, "advisories": true, "orgInvites": true},
				"web":   map[string]any{"dependencyAlerts": true},
			}, &got, http.StatusOK)
			if v := value(); v == nil || *v {
				t.Fatalf("an older client's write turned %s back on: %v", field, v)
			}

			// And the other way: on, then an older client's write keeps it on.
			env.doJSON(sess, http.MethodPut, "/api/v1/user/notifications", map[string]any{
				"email": map[string]any{"dependencyAlerts": true, "quarantine": true, "reviewDecisions": true, "advisories": true, "orgInvites": true, field: true},
				"web":   map[string]any{"dependencyAlerts": true},
			}, &got, http.StatusOK)
			env.doJSON(sess, http.MethodPut, "/api/v1/user/notifications", map[string]any{
				"email": map[string]any{"dependencyAlerts": true, "quarantine": true, "reviewDecisions": true, "advisories": true, "orgInvites": true},
				"web":   map[string]any{"dependencyAlerts": true},
			}, &got, http.StatusOK)
			if v := value(); v == nil || !*v {
				t.Fatalf("an older client's write turned %s off: %v", field, v)
			}
		})
	}
}
