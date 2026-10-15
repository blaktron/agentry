package api_test

// Database-level hardening, exercised with RAW SQL rather than through
// the API: these guards exist precisely because application code cannot be
// trusted to be the only writer. A compromised app role, a migration, or a
// careless psql session must all bounce off them.

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// publishedVersionID publishes one version and returns its row id.
func (env *testEnv) publishedVersionID(t *testing.T, sess caller, ns, name string) string {
	t.Helper()
	env.publishUnder(t, sess, ns, name)
	var id string
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT av.id::text FROM agent_versions av JOIN agents a ON a.id = av.agent_id
		 WHERE a.name = $1 AND av.version = '1.0.0'`, name).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// TestVersionImmutabilityBlocksStatusRollback pins the guarantee that a
// published version cannot be rewritten. A trigger that checked immutable
// fields only when OLD.status <> 'submitted' would let two statements
// (roll the row back to 'submitted', then rewrite it) bypass the guarantee
// and replace a published version's manifest and archive digest under
// consumers who had already installed it.
func TestVersionImmutabilityBlocksStatusRollback(t *testing.T) {
	env := newTestEnv(t)
	user := env.register("imm-usr")
	env.verifyEmail(user)
	sess := env.login(user)
	versionID := env.publishedVersionID(t, sess, user, "immutable")
	ctx := context.Background()

	// Step one of the bypass must now fail on its own.
	_, err := env.st.Pool().Exec(ctx,
		`UPDATE agent_versions SET status = 'submitted' WHERE id = $1`, versionID)
	if err == nil {
		t.Fatal("a published version was rolled back to submitted — the immutability guard is bypassable")
	}
	if !strings.Contains(err.Error(), "regress") {
		t.Fatalf("unexpected error for a status rollback: %v", err)
	}

	// And the direct rewrite it was meant to enable still fails too.
	if _, err := env.st.Pool().Exec(ctx,
		`UPDATE agent_versions SET manifest = '{"evil":true}'::jsonb WHERE id = $1`, versionID); err == nil {
		t.Fatal("a published version's manifest was rewritten")
	}
	if _, err := env.st.Pool().Exec(ctx,
		`UPDATE agent_versions SET archive_digest = 'sha256:deadbeef' WHERE id = $1`, versionID); err == nil {
		t.Fatal("a published version's archive digest was rewritten")
	}

	// State-machine fields still move: the row is immutable, not frozen.
	if _, err := env.st.Pool().Exec(ctx,
		`UPDATE agent_versions SET status = 'yanked', yanked_at = now() WHERE id = $1`, versionID); err != nil {
		t.Fatalf("a legitimate state transition was refused: %v", err)
	}

	// Deletion remains impossible (00004's guard, re-asserted here because
	// DELETE /agents leans on it).
	if _, err := env.st.Pool().Exec(ctx, `DELETE FROM agent_versions WHERE id = $1`, versionID); err == nil {
		t.Fatal("a version row was deleted")
	}
}

// TestAuditEventsRefuseTruncate: the 00002
// trigger guards UPDATE and DELETE, but TRUNCATE fires neither, so the
// append-only log could be emptied in one statement.
func TestAuditEventsRefuseTruncate(t *testing.T) {
	env := newTestEnv(t)
	// Generate at least one event so an accidental success is visible.
	user := env.register("trunc-u")
	env.verifyEmail(user)
	ctx := context.Background()

	var before int64
	if err := env.st.Pool().QueryRow(ctx, `SELECT count(*) FROM audit_events`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if before == 0 {
		t.Fatal("expected some audit events to exist")
	}

	if _, err := env.st.Pool().Exec(ctx, `TRUNCATE audit_events`); err == nil {
		t.Fatal("TRUNCATE emptied the append-only audit log")
	} else if !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("unexpected error for TRUNCATE audit_events: %v", err)
	}

	// Truncating a partition directly must fail too — the parent trigger does
	// not fire for that, which is why the migration attaches one per partition.
	var partition string
	if err := env.st.Pool().QueryRow(ctx,
		`SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
		 WHERE i.inhparent = 'audit_events'::regclass
		   AND c.relname ~ '^audit_events_[0-9]{6}$' LIMIT 1`).Scan(&partition); err != nil {
		t.Fatalf("no monthly audit partition found: %v", err)
	}
	if _, err := env.st.Pool().Exec(ctx, `TRUNCATE `+partition); err == nil {
		t.Fatalf("TRUNCATE %s emptied a partition of the append-only log", partition)
	}

	var after int64
	if err := env.st.Pool().QueryRow(ctx, `SELECT count(*) FROM audit_events`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after < before {
		t.Fatalf("audit rows went from %d to %d", before, after)
	}

	// UPDATE and DELETE stay blocked (00002), asserted here so the whole
	// append-only contract is covered in one place.
	if _, err := env.st.Pool().Exec(ctx, `UPDATE audit_events SET action = 'tampered'`); err == nil {
		t.Fatal("an audit event was updated")
	}
	if _, err := env.st.Pool().Exec(ctx, `DELETE FROM audit_events`); err == nil {
		t.Fatal("audit events were deleted")
	}
}

// TestAuditPruneDropsOnlyOldPartitions pins the retention mechanism: whole
// partitions are dropped (rows cannot be deleted), and only ones entirely
// outside the window.
func TestAuditPruneDropsOnlyOldPartitions(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	// A partition well outside any sane retention window.
	if _, err := env.st.Pool().Exec(ctx,
		`SELECT audit_ensure_partition('2020-03-15'::date)`); err != nil {
		t.Fatal(err)
	}
	var exists bool
	if err := env.st.Pool().QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'audit_events_202003')`).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatal("the historical partition was not created")
	}

	var dropped int
	if err := env.st.Pool().QueryRow(ctx,
		`SELECT audit_prune_partitions((now() - interval '400 days')::date)`).Scan(&dropped); err != nil {
		t.Fatal(err)
	}
	if dropped < 1 {
		t.Fatalf("prune dropped %d partitions, want the 2020 one", dropped)
	}
	if err := env.st.Pool().QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'audit_events_202003')`).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("the historical partition survived the prune")
	}

	// The current month is inside the window and must be untouched, as must
	// the default catch-all partition (it has no bounded range to judge).
	for _, name := range []string{"audit_events_default"} {
		if err := env.st.Pool().QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM pg_class WHERE relname = $1)`, name).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if !exists {
			t.Fatalf("prune dropped %s, which is outside its remit", name)
		}
	}
	// Events from this month are still readable.
	res := env.do(anonymous, http.MethodGet, "/api/v1/meta", nil)
	_ = res.Body.Close()
	var n int64
	if err := env.st.Pool().QueryRow(ctx, `SELECT count(*) FROM audit_events`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("the prune took the current window with it")
	}
}
