package api_test

import (
	"context"
	"encoding/json"
	"errors"
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
	offline := knowledge.NewService(knowledge.Deps{
		Store: env.st, Blobs: env.srvObj.Blobs(), Wrapper: env.srvObj.Knowledge().Wrapper(),
		Scanner: scan.NewOrchestrator(bundle, scan.StaticProvider{}, nil),
	})
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
	// A tree is stored only where its scan can be queued: with no queue the
	// pack would stay scanning for good, so nothing is stored.
	idle, err := offline.CreateSealed(ctx, owner, "unqueued")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := offline.Replace(ctx, owner, idle.ID, "", knowledgeFiles()); err == nil {
		t.Fatal("a tree was stored with no queue to scan it on")
	}
	if got, err := offline.Info(ctx, owner, idle.ID); err != nil || got.State != knowledge.StateEmpty || got.Digest != "" {
		t.Fatalf("a replace with no queue left the pack %+v (%v), want it empty", got, err)
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
	scansOf := func() int {
		var n int
		if err := env.st.Pool().QueryRow(ctx, `SELECT count(*) FROM river_job WHERE kind = $1 AND args->>'pack' = $2`, knowledge.JobScan, p.ID.String()).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	cutoff := time.Now().Add(-knowledge.ScanStallAfter)
	if n, err := svc.SweepScans(ctx, cutoff); err != nil || n != 0 {
		t.Fatalf("a scan stored just now was queued again: %d %v", n, err)
	}
	// A scan still inside its retry budget (about 75 minutes) is its own
	// job's to finish.
	if _, err := env.st.Pool().Exec(ctx, `UPDATE knowledge_packs SET updated_at = now() - interval '90 minutes' WHERE id = $1`, p.ID); err != nil {
		t.Fatal(err)
	}
	if n, err := svc.SweepScans(ctx, cutoff); err != nil || n != 0 || scansOf() != 0 {
		t.Fatalf("a scan stored 90 minutes ago was queued again: %d %v (%d jobs)", n, err, scansOf())
	}
	if _, err := env.st.Pool().Exec(ctx, `UPDATE knowledge_packs SET updated_at = now() - interval '3 hours' WHERE id = $1`, p.ID); err != nil {
		t.Fatal(err)
	}
	if n, err := svc.SweepScans(ctx, cutoff); err != nil || n < 1 || scansOf() != 1 {
		t.Fatalf("the lost scan was not queued again: %d %v (%d jobs)", n, err, scansOf())
	}
	if n, err := svc.SweepScans(ctx, cutoff); err != nil || n != 0 || scansOf() != 1 {
		t.Fatalf("a scan the sweep queued was queued again before it ran: %d %v (%d jobs)", n, err, scansOf())
	}
	drainKnowledgeScans(t, env)
	got, err := svc.Info(ctx, owner, p.ID)
	if err != nil || got.State != knowledge.StateReady {
		t.Fatalf("after the sweep the pack is %+v (%v), want ready", got, err)
	}

	// A pack whose scan ended is not scanned again, however long ago it
	// ended.
	jobsBefore := scansOf()
	if _, err := env.st.Pool().Exec(ctx, `UPDATE knowledge_packs SET updated_at = now() - interval '3 hours' WHERE id = $1`, p.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SweepScans(ctx, cutoff); err != nil || scansOf() != jobsBefore {
		t.Fatalf("the sweep queued a ready pack's scan again: %d jobs, was %d (%v)", scansOf(), jobsBefore, err)
	}

	// The scan job itself leaves a tree since replaced, and a pack no longer
	// scanning, to their own jobs: it ends cleanly and reads nothing.
	jobs := &handlerQueue{h: map[string]queue.Handler{}}
	svc.RegisterHandlers(jobs)
	var object string
	if err := env.st.Pool().QueryRow(ctx, `SELECT object_key FROM knowledge_packs WHERE id = $1`, p.ID).Scan(&object); err != nil {
		t.Fatal(err)
	}
	run := func(object string, attempt int) error {
		args, _ := json.Marshal(knowledge.ScanArgs{Pack: p.ID, Object: object})
		return jobs.h[knowledge.JobScan](ctx, queue.Job{Kind: knowledge.JobScan, Args: args, Attempt: attempt})
	}
	if err := run("knowledge/user/replaced.sealed", 3); err != nil {
		t.Fatalf("the scan of a tree since replaced: %v", err)
	}
	if err := env.srvObj.Blobs().Delete(ctx, object); err != nil {
		t.Fatal(err)
	}
	if err := run(object, 3); err != nil {
		t.Fatalf("the scan of a pack that is no longer scanning read its tree: %v", err)
	}
	if got, err := svc.Info(ctx, owner, p.ID); err != nil || got.State != knowledge.StateReady {
		t.Fatalf("a scan job over a ready pack left it %+v (%v)", got, err)
	}
	// A tree that is not the digest the pack holds is not scanned, and the
	// attempt fails to be tried again.
	other, err := svc.CreateSealed(ctx, owner, "mismatched")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.Replace(ctx, owner, other.ID, "", knowledgeFiles()); err != nil {
		t.Fatal(err)
	}
	if _, err := env.st.Pool().Exec(ctx, `UPDATE knowledge_packs SET digest = 'sha256:' || repeat('0', 64) WHERE id = $1`, other.ID); err != nil {
		t.Fatal(err)
	}
	var otherObject string
	if err := env.st.Pool().QueryRow(ctx, `SELECT object_key FROM knowledge_packs WHERE id = $1`, other.ID).Scan(&otherObject); err != nil {
		t.Fatal(err)
	}
	// The sweep job asks the same of a scan: one stored 90 minutes ago is its
	// own job's to finish.
	if _, err := env.st.Pool().Exec(ctx, `UPDATE knowledge_packs SET updated_at = now() - interval '90 minutes' WHERE id = $1`, other.ID); err != nil {
		t.Fatal(err)
	}
	queuedFor := func() int {
		var n int
		if err := env.st.Pool().QueryRow(ctx, `SELECT count(*) FROM river_job WHERE kind = $1 AND args->>'pack' = $2`, knowledge.JobScan, other.ID.String()).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	queuedBefore := queuedFor()
	if err := jobs.h[knowledge.JobScanSweep](ctx, queue.Job{Kind: knowledge.JobScanSweep}); err != nil || queuedFor() != queuedBefore {
		t.Fatalf("the sweep job queued a scan of 90 minutes again: %v (%d jobs, was %d)", err, queuedFor(), queuedBefore)
	}
	mismatch, _ := json.Marshal(knowledge.ScanArgs{Pack: other.ID, Object: otherObject})
	if err := jobs.h[knowledge.JobScan](ctx, queue.Job{Kind: knowledge.JobScan, Args: mismatch, Attempt: 1}); !errors.Is(err, knowledge.ErrDigest) {
		t.Fatalf("the scan of a tree that is not the pack's digest: %v, want ErrDigest", err)
	}
	if got, err := svc.Info(ctx, owner, other.ID); err != nil || got.State != knowledge.StateScanning {
		t.Fatalf("a tree that is not the pack's digest left the pack %+v (%v), want still scanning", got, err)
	}
}
