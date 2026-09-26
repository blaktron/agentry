package api_test

// The account-erasure seam (agentry#638): an extension's eraser runs inside
// the erasure's and the data clear's own transaction, so its delete commits
// with the core's and an eraser that fails rolls the whole thing back.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/blaktron/agentry/internal/api"
)

// probeEraser records each call in its own table through the transaction it
// is handed, the way an extension's delete of its own rows would, and fails
// after the write when told to.
type probeEraser struct {
	table string
	fail  bool
	// ended is set when the handle it was given could end the core's
	// transaction.
	ended bool
}

func (p *probeEraser) erase(ctx context.Context, tx api.ErasureTx, userID uuid.UUID, kind api.AccountErasureKind) (int64, error) {
	if _, ok := tx.(interface{ Commit(context.Context) error }); ok {
		p.ended = true
	}
	if _, err := tx.Exec(ctx, `INSERT INTO `+p.table+` (user_id, kind) VALUES ($1, $2)`, userID, string(kind)); err != nil {
		return 0, err
	}
	if p.fail {
		return 0, errors.New("probe: refused")
	}
	return 1, nil
}

func newErasureProbe(t *testing.T, env *testEnv) *probeEraser {
	t.Helper()
	p := &probeEraser{table: "erasure_probe_" + env.sfxDigits()}
	ctx := context.Background()
	if _, err := env.st.Pool().Exec(ctx, `CREATE TABLE `+p.table+` (user_id uuid NOT NULL, kind text NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = env.st.Pool().Exec(context.Background(), `DROP TABLE IF EXISTS `+p.table) })
	return p
}

func (p *probeEraser) rows(t *testing.T, env *testEnv, userID string) []string {
	t.Helper()
	rows, err := env.st.Pool().Query(context.Background(), `SELECT kind FROM `+p.table+` WHERE user_id = $1`, userID)
	if err != nil {
		t.Fatal(err)
	}
	kinds, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	return kinds
}

func auditDetail(t *testing.T, env *testEnv, action, userID string) map[string]any {
	t.Helper()
	var detail []byte
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT detail FROM audit_events WHERE action = $1 AND target_id = $2`, action, userID).Scan(&detail); err != nil {
		t.Fatalf("audit %s: %v", action, err)
	}
	var d map[string]any
	if err := json.Unmarshal(detail, &d); err != nil {
		t.Fatal(err)
	}
	return d
}

// TestAccountEraserCommitsWithTheErasure: the eraser is called once, with
// the account and AccountErased and a handle that cannot commit, its write
// lands with the erasure, and the user.delete event counts its rows under
// its name.
func TestAccountEraserCommitsWithTheErasure(t *testing.T) {
	var probe *probeEraser
	env := newTestEnvWith(t, func(s *api.Server) {
		s.AddAccountEraser("probe", func(ctx context.Context, tx api.ErasureTx, id uuid.UUID, k api.AccountErasureKind) (int64, error) {
			return probe.erase(ctx, tx, id, k)
		})
	})
	probe = newErasureProbe(t, env)

	h := env.register("es-erase")
	env.verifyEmail(h)
	sess := env.login(h)
	uid := env.selfID(sess)
	env.doJSON(sess, http.MethodPost, "/api/v1/user/delete", nil, nil, http.StatusNoContent)

	if got := probe.rows(t, env, uid); len(got) != 1 || got[0] != string(api.AccountErased) {
		t.Fatalf("eraser calls = %v, want one %q", got, api.AccountErased)
	}
	if probe.ended {
		t.Fatal("the eraser was handed a transaction it could commit")
	}
	d := auditDetail(t, env, "user.delete", uid)
	if ext, _ := d["extensions"].(map[string]any); ext["probe"] != float64(1) {
		t.Fatalf("user.delete detail = %v, want extensions.probe = 1", d)
	}
}

// TestAccountEraserFailureRollsBackTheErasure: an eraser that fails after
// writing leaves nothing erased — the account active, its PAT alive, its
// own write gone — and the caller gets a 500.
func TestAccountEraserFailureRollsBackTheErasure(t *testing.T) {
	var probe *probeEraser
	env := newTestEnvWith(t, func(s *api.Server) {
		s.AddAccountEraser("probe", func(ctx context.Context, tx api.ErasureTx, id uuid.UUID, k api.AccountErasureKind) (int64, error) {
			return probe.erase(ctx, tx, id, k)
		})
	})
	probe = newErasureProbe(t, env)
	probe.fail = true

	h := env.register("es-fail")
	env.verifyEmail(h)
	sess := env.login(h)
	uid := env.selfID(sess)
	_, pat := env.mintPAT(sess, "es-pat", "user:profile")

	res := env.do(sess, http.MethodPost, "/api/v1/user/delete", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusInternalServerError {
		t.Fatalf("erasure with a failing eraser: %d, want 500", res.StatusCode)
	}
	var state string
	if err := env.st.Pool().QueryRow(context.Background(), `SELECT state FROM users WHERE id = $1`, uid).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "active" {
		t.Fatalf("account state = %q after a rolled-back erasure, want active", state)
	}
	res = env.do(caller{name: "pat", pat: pat}, http.MethodGet, "/api/v1/user", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("PAT after a rolled-back erasure: %d, want 200", res.StatusCode)
	}
	if got := probe.rows(t, env, uid); len(got) != 0 {
		t.Fatalf("the failing eraser's own write survived: %v", got)
	}

	// The same failure refuses a data clear, which keeps the PAT too.
	res = env.do(sess, http.MethodPost, "/api/v1/user/clear-data", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusInternalServerError {
		t.Fatalf("clear with a failing eraser: %d, want 500", res.StatusCode)
	}
	res = env.do(caller{name: "pat", pat: pat}, http.MethodGet, "/api/v1/user", nil)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("PAT after a rolled-back clear: %d, want 200", res.StatusCode)
	}
}

// TestAccountEraserHearsTheDataClear: a data clear calls the eraser with
// AccountDataCleared, in its transaction, and records the count.
func TestAccountEraserHearsTheDataClear(t *testing.T) {
	var probe *probeEraser
	env := newTestEnvWith(t, func(s *api.Server) {
		s.AddAccountEraser("probe", func(ctx context.Context, tx api.ErasureTx, id uuid.UUID, k api.AccountErasureKind) (int64, error) {
			return probe.erase(ctx, tx, id, k)
		})
	})
	probe = newErasureProbe(t, env)

	h := env.register("es-clear")
	env.verifyEmail(h)
	sess := env.login(h)
	uid := env.selfID(sess)
	env.doJSON(sess, http.MethodPost, "/api/v1/user/clear-data", nil, nil, http.StatusNoContent)

	if got := probe.rows(t, env, uid); len(got) != 1 || got[0] != string(api.AccountDataCleared) {
		t.Fatalf("eraser calls = %v, want one %q", got, api.AccountDataCleared)
	}
	d := auditDetail(t, env, "user.data_clear", uid)
	if ext, _ := d["extensions"].(map[string]any); ext["probe"] != float64(1) {
		t.Fatalf("user.data_clear detail = %v, want extensions.probe = 1", d)
	}
}
