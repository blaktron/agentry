package api_test

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/auth"
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

	if err := disp.Emit(context.Background(), uuid.MustParse(orgID), "version.published",
		map[string]any{"version": "1.2.3"}); err != nil {
		t.Fatalf("emit: %v", err)
	}
	q.Drain(context.Background(), "core")

	var deliveryID string
	var stored *string
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT id::text, error FROM webhook_deliveries WHERE endpoint_id = $1`, created.Id).Scan(&deliveryID, &stored); err != nil {
		t.Fatal(err)
	}
	if stored == nil || !strings.Contains(*stored, "10.0.0.1") {
		t.Fatalf("stored delivery error = %v, want the refusal naming the host", stored)
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
}
