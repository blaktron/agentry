package api_test

import (
	"context"
	"testing"
	"time"

	"github.com/blaktron/agentry/internal/knowledge"
	"github.com/blaktron/agentry/internal/queue"
	"github.com/blaktron/agentry/internal/scan"
	"github.com/blaktron/agentry/pkg/ruleset"
)

// A pack's scan is queued only once its tree has committed, so a worker
// that takes the job the moment it is queued, on another connection,
// finds the tree and the pack ends ready.
func TestAScanTakenAtOnceFindsItsTree(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	bundle, err := ruleset.Load()
	if err != nil {
		t.Fatal(err)
	}
	q := &eagerQueue{handlers: map[string]queue.Handler{}}
	svc := knowledge.NewService(knowledge.Deps{
		Store: env.st, Blobs: env.srvObj.Blobs(), Wrapper: env.srvObj.Knowledge().Wrapper(),
		Scanner: scan.NewOrchestrator(bundle, scan.StaticProvider{}, nil), Jobs: q,
	})
	svc.RegisterHandlers(q)
	owner := ownerOf(t, env, newKnowledgeOwner(env, "kn-eager"))
	p, err := svc.CreateSealed(ctx, owner, "eager")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.Replace(ctx, owner, p.ID, "", knowledgeFiles()); err != nil {
		t.Fatal(err)
	}
	if q.ran != 1 {
		t.Fatalf("the scan ran %d times", q.ran)
	}
	got, err := svc.Info(ctx, owner, p.ID)
	if err != nil || got.State != knowledge.StateReady {
		t.Fatalf("a scan taken at once left the pack %+v (%v), want ready", got, err)
	}
}

// A pack whose scan job was lost stays scanning only until the sweep: one
// left past the stall period has its scan queued again, once, and ends
// ready; a pack scanning more recently is left to its own job.
func TestTheSweepQueuesALostScanAgain(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	svc := env.srvObj.Knowledge()
	owner := ownerOf(t, env, newKnowledgeOwner(env, "kn-sweep"))
	p, err := svc.CreateSealed(ctx, owner, "lost")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.Replace(ctx, owner, p.ID, "", knowledgeFiles()); err != nil {
		t.Fatal(err)
	}
	// The job is lost.
	if _, err := env.st.Pool().Exec(ctx, `DELETE FROM river_job WHERE kind = $1 AND args->>'pack' = $2`, knowledge.JobScan, p.ID.String()); err != nil {
		t.Fatal(err)
	}
	cutoff := time.Now().Add(-knowledge.ScanStallAfter)
	if n, err := svc.SweepScans(ctx, cutoff); err != nil || n != 0 {
		t.Fatalf("a scan stored just now was queued again: %d %v", n, err)
	}
	if _, err := env.st.Pool().Exec(ctx, `UPDATE knowledge_packs SET updated_at = now() - interval '3 hours' WHERE id = $1`, p.ID); err != nil {
		t.Fatal(err)
	}
	if n, err := svc.SweepScans(ctx, cutoff); err != nil || n < 1 {
		t.Fatalf("the lost scan was not queued again: %d %v", n, err)
	}
	if n, err := svc.SweepScans(ctx, cutoff); err != nil || n != 0 {
		t.Fatalf("a scan the sweep queued was queued again before it ran: %d %v", n, err)
	}
	drainKnowledgeScans(t, env)
	got, err := svc.Info(ctx, owner, p.ID)
	if err != nil || got.State != knowledge.StateReady {
		t.Fatalf("after the sweep the pack is %+v (%v), want ready", got, err)
	}
}
