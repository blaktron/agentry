package queue

// The queue's failure paths are the ones that matter: a handler that errors
// must come back with backoff, a handler that keeps erroring must stop and be
// marked failed, a handler that panics must not take the worker with it, a
// job with no registered handler must not spin forever, and a job orphaned by
// a dead worker must be reclaimed. None of that was covered.

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/store"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

func newQueueTestClient(t *testing.T) (*PGClient, *store.Store) {
	t.Helper()
	url := os.Getenv("AGENTRY_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("AGENTRY_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	if err := store.Migrate(ctx, url); err != nil {
		t.Fatal(err)
	}
	st, err := store.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	return NewPGClient(st, nil), st
}

func jobRow(t *testing.T, st *store.Store, id uuid.UUID) storegen.Job {
	t.Helper()
	var j storegen.Job
	err := st.Pool().QueryRow(context.Background(),
		`SELECT id, kind, queue, args, state, attempt, max_attempts, run_at, locked_at,
		        last_error, created_at, finished_at FROM jobs WHERE id = $1`, id).
		Scan(&j.ID, &j.Kind, &j.Queue, &j.Args, &j.State, &j.Attempt, &j.MaxAttempts,
			&j.RunAt, &j.LockedAt, &j.LastError, &j.CreatedAt, &j.FinishedAt)
	if err != nil {
		t.Fatalf("load job: %v", err)
	}
	return j
}

// TestQueueRetriesWithBackoff pins that a failing handler reschedules the job
// into the future rather than hot-looping on it.
func TestQueueRetriesWithBackoff(t *testing.T) {
	c, st := newQueueTestClient(t)
	ctx := context.Background()
	qName := "test-retry-" + uuid.NewString()

	c.Register("boom", func(context.Context, Job) error { return errors.New("nope") })
	id, err := c.Enqueue(ctx, "boom", qName, map[string]string{"x": "1"})
	if err != nil {
		t.Fatal(err)
	}

	before := time.Now()
	if !c.RunOnce(ctx, qName) {
		t.Fatal("expected the job to be claimed")
	}
	j := jobRow(t, st, id)
	if j.State != "available" {
		t.Fatalf("state after a failed attempt = %s, want available (retry)", j.State)
	}
	if j.Attempt != 1 {
		t.Fatalf("attempt = %d, want 1", j.Attempt)
	}
	if j.LastError == nil || *j.LastError != "nope" {
		t.Fatalf("last_error = %v, want the handler error", j.LastError)
	}
	// Backoff is 2^attempt seconds; the point is that it is in the future, so
	// a permanently broken handler cannot saturate the worker.
	if !j.RunAt.After(before) {
		t.Fatalf("run_at = %v, want a future retry time (backoff)", j.RunAt)
	}
	// And the retry is not immediately claimable again.
	if c.RunOnce(ctx, qName) {
		t.Fatal("a backed-off job was claimed again in the same tick")
	}
}

// TestQueueFailsAfterMaxAttempts pins the terminal path: the job stops
// retrying and lands in `failed` with the last error recorded.
func TestQueueFailsAfterMaxAttempts(t *testing.T) {
	c, st := newQueueTestClient(t)
	ctx := context.Background()
	qName := "test-fail-" + uuid.NewString()

	calls := 0
	c.Register("always-bad", func(context.Context, Job) error {
		calls++
		return errors.New("still broken")
	})
	id, err := c.Enqueue(ctx, "always-bad", qName, nil, WithMaxAttempts(2))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if !c.RunOnce(ctx, qName) {
			t.Fatalf("attempt %d: job not claimed", i+1)
		}
		// Undo the backoff so the next attempt is claimable in-test.
		if _, err := st.Pool().Exec(ctx, `UPDATE jobs SET run_at = now() WHERE id = $1`, id); err != nil {
			t.Fatal(err)
		}
	}
	j := jobRow(t, st, id)
	if j.State != "failed" {
		t.Fatalf("state = %s, want failed after max attempts", j.State)
	}
	if j.LastError == nil || *j.LastError != "still broken" {
		t.Fatalf("last_error = %v", j.LastError)
	}
	if calls != 2 {
		t.Fatalf("handler ran %d times, want 2 (max attempts)", calls)
	}
	if c.RunOnce(ctx, qName) {
		t.Fatal("a failed job was claimed again")
	}
}

// TestQueueRecoversFromHandlerPanic pins that a panicking handler is treated
// as an ordinary error: the worker survives and the job retries.
func TestQueueRecoversFromHandlerPanic(t *testing.T) {
	c, st := newQueueTestClient(t)
	ctx := context.Background()
	qName := "test-panic-" + uuid.NewString()

	c.Register("panics", func(context.Context, Job) error { panic("stage exploded") })
	id, err := c.Enqueue(ctx, "panics", qName, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !c.RunOnce(ctx, qName) {
		t.Fatal("job not claimed")
	}
	j := jobRow(t, st, id)
	if j.State != "available" {
		t.Fatalf("state = %s, want available (panic retried like an error)", j.State)
	}
	if j.LastError == nil || *j.LastError == "" {
		t.Fatal("panic was not recorded on the job")
	}
	// The panic value must reach the operator, not be flattened to "panic".
	if got := *j.LastError; got != "queue: handler panic: stage exploded" {
		t.Fatalf("last_error = %q, want the panic value", got)
	}
}

// TestQueueNoHandlerFailsJob pins that an unroutable job is failed once
// rather than reclaimed on every tick forever.
func TestQueueNoHandlerFailsJob(t *testing.T) {
	c, st := newQueueTestClient(t)
	ctx := context.Background()
	qName := "test-nohandler-" + uuid.NewString()

	id, err := c.Enqueue(ctx, "kind-nobody-registered", qName, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !c.RunOnce(ctx, qName) {
		t.Fatal("job not claimed")
	}
	j := jobRow(t, st, id)
	if j.State != "failed" {
		t.Fatalf("state = %s, want failed", j.State)
	}
	if j.LastError == nil || *j.LastError != "no handler registered" {
		t.Fatalf("last_error = %v", j.LastError)
	}
	if c.RunOnce(ctx, qName) {
		t.Fatal("unroutable job was claimed twice")
	}
}

// TestQueueReclaimsOrphanedJobs pins the crash-recovery path: a job left
// `running` by a worker that died is returned to the pool. Previously this
// ran only at Work() start, so a long-lived worker never noticed.
func TestQueueReclaimsOrphanedJobs(t *testing.T) {
	c, st := newQueueTestClient(t)
	ctx := context.Background()
	qName := "test-orphan-" + uuid.NewString()

	ran := 0
	c.Register("orphan", func(context.Context, Job) error { ran++; return nil })
	id, err := c.Enqueue(ctx, "orphan", qName, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a worker that claimed the job and then died.
	if _, err := st.Pool().Exec(ctx,
		`UPDATE jobs SET state = 'running', locked_at = now() - interval '2 hours' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	if c.RunOnce(ctx, qName) {
		t.Fatal("a job locked by another worker must not be claimable")
	}

	c.ReclaimOrphanedJobs(ctx)
	if j := jobRow(t, st, id); j.State != "available" {
		t.Fatalf("state after reclaim = %s, want available", j.State)
	}
	if !c.RunOnce(ctx, qName) {
		t.Fatal("reclaimed job was not re-claimed")
	}
	if ran != 1 {
		t.Fatalf("handler ran %d times, want 1", ran)
	}
	if j := jobRow(t, st, id); j.State != "completed" {
		t.Fatalf("state = %s, want completed", j.State)
	}
}

// TestQueueReclaimRespectsCutoff guards the other direction: a job a healthy
// worker is holding right now must not be yanked out from under it.
func TestQueueReclaimRespectsCutoff(t *testing.T) {
	c, st := newQueueTestClient(t)
	ctx := context.Background()
	qName := "test-cutoff-" + uuid.NewString()

	id, err := c.Enqueue(ctx, "held", qName, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool().Exec(ctx,
		`UPDATE jobs SET state = 'running', locked_at = now() WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	c.ReclaimOrphanedJobs(ctx)
	if j := jobRow(t, st, id); j.State != "running" {
		t.Fatalf("state = %s, want running (in-flight job must not be reclaimed)", j.State)
	}
}

// TestQueueDelayedJobIsNotClaimableEarly pins WithDelay: a job scheduled for
// the future must not be claimable before its time. Everything that defers
// work — retry backoff, the rescan sweep, the audit retention job — rests on
// this, and a claim that ignored run_at would turn every delay into "now".
func TestQueueDelayedJobIsNotClaimableEarly(t *testing.T) {
	c, st := newQueueTestClient(t)
	ctx := context.Background()
	qName := "test-delay-" + uuid.NewString()

	ran := 0
	c.Register("later", func(context.Context, Job) error { ran++; return nil })
	id, err := c.Enqueue(ctx, "later", qName, nil, WithDelay(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if j := jobRow(t, st, id); !j.RunAt.After(time.Now().Add(30 * time.Minute)) {
		t.Fatalf("run_at = %v, want roughly an hour out", j.RunAt)
	}
	if c.RunOnce(ctx, qName) {
		t.Fatal("a job scheduled an hour out was claimed now")
	}
	if ran != 0 {
		t.Fatalf("handler ran %d times before the job was due", ran)
	}

	// Once due, the same job runs — the delay defers work, it does not lose it.
	if _, err := st.Pool().Exec(ctx, `UPDATE jobs SET run_at = now() - interval '1 second' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	if !c.RunOnce(ctx, qName) {
		t.Fatal("a due job was not claimed")
	}
	if ran != 1 {
		t.Fatalf("handler ran %d times, want 1", ran)
	}
	if j := jobRow(t, st, id); j.State != "completed" {
		t.Fatalf("state = %s, want completed", j.State)
	}
}

// TestQueueDrainEmptiesTheQueue pins Drain: it keeps going until nothing is
// claimable, rather than running one job per queue like RunOnce.
func TestQueueDrainEmptiesTheQueue(t *testing.T) {
	c, st := newQueueTestClient(t)
	ctx := context.Background()
	qName := "test-drain-" + uuid.NewString()

	ran := 0
	c.Register("bulk", func(context.Context, Job) error { ran++; return nil })
	var ids []uuid.UUID
	for i := 0; i < 5; i++ {
		id, err := c.Enqueue(ctx, "bulk", qName, map[string]int{"i": i})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	c.Drain(ctx, qName)
	if ran != 5 {
		t.Fatalf("handler ran %d times, want 5", ran)
	}
	for _, id := range ids {
		if j := jobRow(t, st, id); j.State != "completed" {
			t.Fatalf("job %s state = %s, want completed", id, j.State)
		}
	}
}

// TestQueueWorkLoopProcessesAndStops pins Work: it processes what arrives and
// returns the context's error when cancelled, rather than hanging or leaking
// the loop. A worker that cannot be shut down cleanly is a deploy that hangs.
func TestQueueWorkLoopProcessesAndStops(t *testing.T) {
	c, st := newQueueTestClient(t)
	qName := "test-work-" + uuid.NewString()
	c.pollInterval = 20 * time.Millisecond

	done := make(chan struct{})
	c.Register("looped", func(context.Context, Job) error { close(done); return nil })
	id, err := c.Enqueue(context.Background(), "looped", qName, nil)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- c.Work(ctx, qName) }()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("the work loop never ran the enqueued job")
	}
	// Wait for the completion WRITE, not just the handler return: cancelling
	// between the two would cancel the update's own context, and the job would
	// (correctly, at-least-once) be redelivered later. That is the queue
	// behaving properly, and racing it here would only make the test flaky.
	deadline := time.Now().Add(5 * time.Second)
	for jobRow(t, st, id).State != "completed" {
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("job never reached completed (state = %s)", jobRow(t, st, id).State)
		}
		time.Sleep(20 * time.Millisecond)
	}

	cancel()
	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Work returned %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Work did not return after its context was cancelled")
	}
}
