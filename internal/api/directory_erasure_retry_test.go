package api_test

// Erasure's directory step is finished, not left behind (agentry#499): a
// failed or unreachable directory is retried by a job with backoff, every
// attempt is audited, the erasure's response says where the directory step
// stands, and an erasure still pending after its retries is recorded as
// abandoned (and raised to the operator as a fail-open line and metric).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/queue"
)

// flakyDirectory answers 503 to the first failures lookups of its one
// address, then behaves like authentik: one exact account, deleted on
// request. Any other address (a job another test left in the shared queue)
// has no account here.
type flakyDirectory struct {
	mu       sync.Mutex
	email    string
	failures int
	lookups  int
	deleted  []string
}

func (d *flakyDirectory) handler(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/v3/core/users/":
		if !strings.EqualFold(r.URL.Query().Get("search"), d.email) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"results":[]}`))
			return
		}
		d.lookups++
		if d.lookups <= d.failures {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"results": []map[string]any{
			{"pk": 41, "email": d.email, "type": "internal", "is_superuser": false},
		}})
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/v3/core/users/"):
		d.deleted = append(d.deleted, r.URL.Path)
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "unexpected", http.StatusNotFound)
	}
}

// eraseAndReadOutcome erases the caller's account and returns the
// directory outcome the 204 carries.
func eraseAndReadOutcome(t *testing.T, env *testEnv, c caller) string {
	t.Helper()
	res := env.do(c, http.MethodPost, "/api/v1/user/delete", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("erase: %d, want 204", res.StatusCode)
	}
	return res.Header.Get("X-Agentry-Directory-Erasure")
}

// drainRetries runs the queue until this user's retry job is finished,
// pulling each backed-off retry forward rather than waiting it out.
func drainRetries(t *testing.T, env *testEnv, srv *api.Server, uid string) {
	t.Helper()
	q := queue.NewRiverClient(env.st, nil)
	q.SetTestOnly(true)
	srv.RegisterQueueHandlers(q)
	for i := 0; i < 10; i++ {
		q.Drain(context.Background(), "core")
		// River parks a retry due within seconds as available with a future
		// scheduled_at rather than as retryable, so both are pulled forward.
		tag, err := env.st.Pool().Exec(context.Background(),
			`UPDATE river_job SET scheduled_at = now() WHERE kind = 'gdpr.directory_erase' AND args->>'userId' = $1
			   AND state IN ('available', 'retryable', 'scheduled')`, uid)
		if err != nil {
			t.Fatal(err)
		}
		if tag.RowsAffected() == 0 {
			return
		}
	}
	t.Fatal("the directory erasure job never finished")
}

func directoryOutcomes(t *testing.T, env *testEnv, uid string) []map[string]any {
	t.Helper()
	rows, err := env.st.Pool().Query(context.Background(),
		`SELECT detail FROM audit_events WHERE action = 'user.directory_erase' AND target_id = $1 ORDER BY occurred_at, id`, uid)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var d map[string]any
		_ = json.Unmarshal(raw, &d)
		out = append(out, d)
	}
	return out
}

func TestDirectoryErasureFailureIsRetried(t *testing.T) {
	h := "dir-retry"                    // the handle register derives from it carries a suffix
	dir := &flakyDirectory{failures: 2} // the request's attempt and the job's first
	idp := httptest.NewServer(http.HandlerFunc(dir.handler))
	defer idp.Close()

	var srv *api.Server
	env := newTestEnvCfg(t, func(c *config.Config) {
		c.Auth.IdPAdminURL = idp.URL
		c.Auth.IdPAdminToken = "idp-admin-token"
	}, func(s *api.Server) { srv = s })
	h = env.register(h)
	dir.mu.Lock()
	dir.email = h + "@example.test"
	dir.mu.Unlock()
	env.verifyEmail(h)
	sess := env.login(h)
	uid := env.selfID(sess)

	if got := eraseAndReadOutcome(t, env, sess); got != "pending" {
		t.Fatalf("X-Agentry-Directory-Erasure = %q, want pending", got)
	}
	var queued int
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM river_job WHERE kind = 'gdpr.directory_erase' AND args->>'userId' = $1`, uid).Scan(&queued); err != nil {
		t.Fatal(err)
	}
	if queued != 1 {
		t.Fatalf("directory erasure jobs queued: %d, want 1", queued)
	}
	// The job carries the address sealed: the users row no longer holds it,
	// and the jobs table must not either.
	var args string
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT args::text FROM river_job WHERE kind = 'gdpr.directory_erase' AND args->>'userId' = $1`, uid).Scan(&args); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(args, h+"@") {
		t.Fatalf("the job's args hold the erased address in the clear: %s", args)
	}

	drainRetries(t, env, srv, uid)

	dir.mu.Lock()
	deleted := append([]string(nil), dir.deleted...)
	dir.mu.Unlock()
	if len(deleted) != 1 || deleted[0] != "/api/v3/core/users/41/" {
		t.Fatalf("directory deletes = %v, want the account deleted once", deleted)
	}
	got := directoryOutcomes(t, env, uid)
	var seq []string
	for _, d := range got {
		seq = append(seq, d["directoryErasure"].(string))
		if e, _ := d["error"].(string); strings.Contains(e, h+"@") {
			t.Errorf("an audited error carries the erased address: %q", e)
		}
	}
	if strings.Join(seq, ",") != "failed,failed,deleted" {
		t.Fatalf("audited directory outcomes = %v, want failed,failed,deleted", seq)
	}
	if got[2]["attempt"] != float64(2) {
		t.Errorf("the success's audit detail = %v, want attempt 2", got[2])
	}
}

func TestDirectoryErasureAbandonedAfterItsRetries(t *testing.T) {
	// A directory that is not there at all: every attempt is a connection
	// error, whose text must not carry the lookup URL (and so the address).
	idp := httptest.NewServer(http.NotFoundHandler())
	idp.Close()

	var srv *api.Server
	env := newTestEnvCfg(t, func(c *config.Config) {
		c.Auth.IdPAdminURL = idp.URL
		c.Auth.IdPAdminToken = "idp-admin-token"
	}, func(s *api.Server) {
		srv = s
		s.SetDirectoryErasureAttempts(2)
	})
	h := env.register("dir-abandon")
	env.verifyEmail(h)
	sess := env.login(h)
	uid := env.selfID(sess)
	if got := eraseAndReadOutcome(t, env, sess); got != "pending" {
		t.Fatalf("X-Agentry-Directory-Erasure = %q, want pending", got)
	}

	drainRetries(t, env, srv, uid)

	var seq []string
	for _, d := range directoryOutcomes(t, env, uid) {
		seq = append(seq, d["directoryErasure"].(string))
		e, _ := d["error"].(string)
		if e == "" || strings.Contains(e, h+"@") || strings.Contains(e, "email=") {
			t.Errorf("audited error %q: want the failure without the lookup URL or the address", e)
		}
	}
	if strings.Join(seq, ",") != "failed,failed,abandoned" {
		t.Fatalf("audited directory outcomes = %v, want failed,failed,abandoned", seq)
	}
}

func TestDirectoryErasureOutcomeInTheResponse(t *testing.T) {
	env := newTestEnv(t)
	h := env.register("dir-resp")
	env.verifyEmail(h)
	sess := env.login(h)
	if got := eraseAndReadOutcome(t, env, sess); got != "not-configured" {
		t.Fatalf("X-Agentry-Directory-Erasure = %q, want not-configured", got)
	}
}
