package api_test

import (
	"context"
	"testing"

	"github.com/blaktron/agentry/internal/knowledge"
	"github.com/blaktron/agentry/internal/queue"
)

// rescueAtLastAttempt makes the matching job what River's rescuer leaves
// when the worker that held its last attempt died: discarded at
// max_attempts, with the rescuer's error, and its handler never called.
func rescueAtLastAttempt(t *testing.T, env *testEnv, where string, args ...any) {
	t.Helper()
	tag, err := env.st.Pool().Exec(context.Background(), `
		UPDATE river_job SET state = 'discarded', attempt = max_attempts, finalized_at = now(),
		  errors = coalesce(errors, '{}') || jsonb_build_object('at', now(), 'attempt', max_attempts,
		    'error', 'Stuck job rescued by JobRescuer', 'trace', '')
		WHERE `+where, args...)
	if err != nil {
		t.Fatal(err)
	}
	if tag.RowsAffected() != 1 {
		t.Fatalf("rescued %d jobs, want 1", tag.RowsAffected())
	}
}

// A knowledge scan whose last attempt died with its worker still fails the
// pack: the rescued job is given its last attempt, whose failure fails the
// pack rather than leave it scanning, and it is given it once.
func TestARescuedLastScanFailsThePack(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	svc := env.srvObj.Knowledge()
	owner := ownerOf(t, env, newKnowledgeOwner(env, "kn-rescue"))
	p, err := svc.CreateSealed(ctx, owner, "rescued")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.Replace(ctx, owner, p.ID, "", knowledgeFiles()); err != nil {
		t.Fatal(err)
	}
	// The tree can no longer be read, so the last attempt fails.
	var key string
	if err := env.st.Pool().QueryRow(ctx, `SELECT object_key FROM knowledge_packs WHERE id = $1`, p.ID).Scan(&key); err != nil {
		t.Fatal(err)
	}
	if err := env.srvObj.Blobs().Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
	rescueAtLastAttempt(t, env, `kind = $1 AND args->>'pack' = $2`, knowledge.JobScan, p.ID.String())

	rc := queue.NewRiverClient(env.st, nil)
	if n, err := rc.SettleRescued(ctx); err != nil || n != 1 {
		t.Fatalf("SettleRescued = %d, %v", n, err)
	}
	drainKnowledgeScans(t, env)
	got, err := svc.Info(ctx, owner, p.ID)
	if err != nil || got.State != knowledge.StateFailed {
		t.Fatalf("the pack after its rescued last scan: %+v (%v), want failed", got, err)
	}
	var finals int
	if err := env.st.Pool().QueryRow(ctx, `SELECT count(*) FROM river_job WHERE kind = $1 AND args->>'pack' = $2 AND metadata ? 'final'`,
		knowledge.JobScan, p.ID.String()).Scan(&finals); err != nil {
		t.Fatal(err)
	}
	if finals != 1 {
		t.Fatalf("final attempts queued: %d, want 1", finals)
	}
}

// A last attempt that is itself rescued is not given another: the job ends
// there, so a handler that hangs every time is not run for ever.
func TestARescuedFinalAttemptIsNotQueuedAgain(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	svc := env.srvObj.Knowledge()
	owner := ownerOf(t, env, newKnowledgeOwner(env, "kn-rescue2"))
	p, err := svc.CreateSealed(ctx, owner, "twice")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.Replace(ctx, owner, p.ID, "", knowledgeFiles()); err != nil {
		t.Fatal(err)
	}
	rescueAtLastAttempt(t, env, `kind = $1 AND args->>'pack' = $2`, knowledge.JobScan, p.ID.String())
	rc := queue.NewRiverClient(env.st, nil)
	if n, err := rc.SettleRescued(ctx); err != nil || n != 1 {
		t.Fatalf("SettleRescued = %d, %v", n, err)
	}
	rescueAtLastAttempt(t, env, `kind = $1 AND args->>'pack' = $2 AND metadata ? 'final'`, knowledge.JobScan, p.ID.String())
	if _, err := rc.SettleRescued(ctx); err != nil {
		t.Fatal(err)
	}
	var jobs int
	if err := env.st.Pool().QueryRow(ctx, `SELECT count(*) FROM river_job WHERE kind = $1 AND args->>'pack' = $2`,
		knowledge.JobScan, p.ID.String()).Scan(&jobs); err != nil {
		t.Fatal(err)
	}
	if jobs != 2 {
		t.Fatalf("scan jobs for the pack: %d, want the original and one final attempt", jobs)
	}
}
