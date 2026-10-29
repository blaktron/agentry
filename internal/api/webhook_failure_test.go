package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/logevent"
	"github.com/blaktron/agentry/internal/queue"
	"github.com/blaktron/agentry/internal/webhook"
)

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// An endpoint whose address carries a token in its path and query, and which
// the egress guard refuses, leaves that token nowhere: not in the stored
// delivery error, not in the log, not in the error the queue keeps.
func TestAFailedDeliveryKeepsTheEndpointsTokenOut(t *testing.T) {
	env := newTestEnv(t)
	owner := env.register("wf-owner")
	env.verifyEmail(owner)
	sess := env.login(owner)
	orgH := "wforg" + env.sfx
	orgID := env.createOrg(sess, orgH)

	const pathToken, queryToken = "tok_PATH_5d41402abc4b", "tok_QUERY_7d793037a076"
	var created struct {
		Id string `json:"id"`
	}
	env.doJSON(sess, http.MethodPost, "/api/v1/orgs/"+orgH+"/webhooks", map[string]any{
		"url":    "https://10.0.0.1/services/" + pathToken + "?key=" + queryToken,
		"events": []string{"version.published"},
	}, &created, http.StatusCreated)

	sealer, err := auth.NewSealer("", true)
	if err != nil {
		t.Fatal(err)
	}
	q := queue.NewRiverClient(env.st, nil)
	q.SetTestOnly(true)
	var logs lockedBuffer
	disp := webhook.NewDispatcher(webhook.Deps{
		Store: env.st, Sealer: sealer, Queue: q,
		Log:    slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Client: webhook.NewHTTPClient(webhook.Guard{}, nil),
	})
	disp.RegisterHandlers(q)

	// An address the client cannot even build a request from: its port is
	// the token, and the parser quotes what it stopped at. The API refuses
	// such an address, so it is written straight to the store over one the
	// API accepted. It belongs to a second organization, whose delivery rate
	// is its own.
	const portToken = "tok_PORT_8f14e45fceea"
	owner2 := env.register("wf-owner2")
	env.verifyEmail(owner2)
	sess2 := env.login(owner2)
	org2H := "wforgb" + env.sfx
	org2ID := env.createOrg(sess2, org2H)
	var unparsable struct {
		Id string `json:"id"`
	}
	env.doJSON(sess2, http.MethodPost, "/api/v1/orgs/"+org2H+"/webhooks", map[string]any{
		"url":    "https://hooks.example.test/hook",
		"events": []string{"version.published"},
	}, &unparsable, http.StatusCreated)
	if _, err := env.st.Pool().Exec(context.Background(), `UPDATE webhook_endpoints SET url = $1 WHERE id = $2`,
		"https://hooks.example.test:"+portToken+"/hook/tok_PATH_c9f0f895fb98?key=tok_QUERY_45c48cce2e2d", unparsable.Id); err != nil {
		t.Fatal(err)
	}

	if err := disp.Emit(context.Background(), uuid.MustParse(orgID), "version.published",
		map[string]any{"version": "1.2.3"}); err != nil {
		t.Fatalf("emit: %v", err)
	}
	if err := disp.Emit(context.Background(), uuid.MustParse(org2ID), "version.published",
		map[string]any{"version": "1.2.3"}); err != nil {
		t.Fatalf("emit: %v", err)
	}
	before := time.Now()
	q.Drain(context.Background(), "core")
	after := time.Now()

	var deliveryID string
	var stored *string
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT id::text, error FROM webhook_deliveries WHERE endpoint_id = $1`, created.Id).Scan(&deliveryID, &stored); err != nil {
		t.Fatal(err)
	}
	if stored == nil || !strings.Contains(*stored, "10.0.0.1") {
		t.Fatalf("stored delivery error = %v, want the refusal naming the host", stored)
	}
	// The text keeps what went wrong and the host it went wrong for, in the
	// shape the transport gives it, rebuilt from the scheme and host.
	if !strings.HasPrefix(*stored, "Post https://10.0.0.1: ") {
		t.Fatalf("stored delivery error = %q, want it to begin \"Post https://10.0.0.1: \"", *stored)
	}
	var kept string
	rows, err := env.st.Pool().Query(context.Background(), `SELECT errors::text FROM river_job WHERE kind = $1 AND args->>'delivery_id' = $2`, webhook.JobDeliver, deliveryID)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var e string
		if err := rows.Scan(&e); err != nil {
			t.Fatal(err)
		}
		kept += e
	}
	rows.Close()
	if !strings.Contains(kept, "10.0.0.1") {
		t.Fatalf("the queue kept %q, want the refusal naming the host", kept)
	}

	for name, text := range map[string]string{"delivery row": *stored, "log": logs.String(), "queue error": kept} {
		for _, secret := range []string{pathToken, queryToken, "/services"} {
			if strings.Contains(text, secret) {
				t.Errorf("the %s carries %q: %s", name, secret, text)
			}
		}
	}

	// What was recorded: the first attempt, no answer, retried in two
	// seconds by the ledger's own reckoning and by the queue (five attempts
	// in all, the job waiting for its retry).
	var attempt int
	var status *int32
	var deliveredAt, nextRetry *time.Time
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT attempt, status_code, delivered_at, next_retry_at FROM webhook_deliveries WHERE id = $1`, deliveryID).Scan(&attempt, &status, &deliveredAt, &nextRetry); err != nil {
		t.Fatal(err)
	}
	if attempt != 1 || status != nil || deliveredAt != nil || nextRetry == nil ||
		nextRetry.Before(before.Add(2*time.Second-5*time.Millisecond)) || nextRetry.After(after.Add(2*time.Second+5*time.Millisecond)) {
		t.Errorf("ledger row = attempt %d status %v delivered %v retry %v, want attempt 1, no answer, retry two seconds after %s", attempt, status, deliveredAt, nextRetry, before.Format(time.RFC3339Nano))
	}
	var jobState string
	var maxAttempts int
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT state, max_attempts FROM river_job WHERE kind = $1 AND args->>'delivery_id' = $2`, webhook.JobDeliver, deliveryID).Scan(&jobState, &maxAttempts); err != nil {
		t.Fatal(err)
	}
	if (jobState != "retryable" && jobState != "available" && jobState != "scheduled") || maxAttempts != 5 {
		t.Errorf("the queue's job = %s with %d attempts, want one waiting for its retry, with 5", jobState, maxAttempts)
	}

	// The log says that the guard refused the host, and that the attempt
	// finished in error: the scan above is only worth anything with a log
	// to scan.
	var refused, finished map[string]any
	for _, l := range strings.Split(logs.String(), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) != nil {
			continue
		}
		switch m["msg"] {
		case "webhook: target refused by the private-range guard":
			if m["delivery"] == deliveryID {
				refused = m
			}
		case "webhook: delivery finished":
			if m["delivery"] == deliveryID {
				finished = m
			}
		}
	}
	if refused == nil || refused[logevent.Key] != string(logevent.SSRFRefused) || refused["host"] != "10.0.0.1" ||
		refused["endpoint"] != created.Id || refused["org"] != orgID {
		t.Errorf("refusal line = %v, want %s for host 10.0.0.1, endpoint %s, org %s", refused, logevent.SSRFRefused, created.Id, orgID)
	}
	if finished == nil || finished[logevent.Key] != string(logevent.WebhookDelivered) || finished["outcome"] != "error" ||
		finished["org"] != orgID || finished["attempt"] != float64(1) {
		t.Errorf("attempt line = %v, want %s, outcome error, org %s, attempt 1", finished, logevent.WebhookDelivered, orgID)
	}

	// The unbuildable address: the stored text and the queue's say that it
	// is not a valid URL, and say nothing of what it held.
	var badID string
	var badStored *string
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT id::text, error FROM webhook_deliveries WHERE endpoint_id = $1`, unparsable.Id).Scan(&badID, &badStored); err != nil {
		t.Fatal(err)
	}
	const notValid = "the endpoint's address is not a valid URL"
	if badStored == nil || *badStored != notValid {
		t.Errorf("stored text for the unbuildable address = %v, want %q", badStored, notValid)
	}
	var badKept string
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT coalesce(errors::text, '') FROM river_job WHERE kind = $1 AND args->>'delivery_id' = $2`, webhook.JobDeliver, badID).Scan(&badKept); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(badKept, notValid) {
		t.Errorf("the queue kept %q for the unbuildable address, want %q", badKept, notValid)
	}
	if badStored == nil {
		t.FailNow()
	}
	for name, text := range map[string]string{"delivery row": *badStored, "log": logs.String(), "queue error": badKept} {
		for _, secret := range []string{portToken, "tok_PATH_c9f0", "tok_QUERY_45c4", "/hook"} {
			if strings.Contains(text, secret) {
				t.Errorf("the %s carries %q for the unbuildable address: %s", name, secret, text)
			}
		}
	}
}
