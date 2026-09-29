package queue

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/store"
)

func newRiverTestClient(t *testing.T) (*RiverClient, *store.Store) {
	t.Helper()
	url := os.Getenv("AGENTRY_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("AGENTRY_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	if err := store.Migrate(ctx, url); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	st, err := store.Connect(ctx, url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(st.Close)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if os.Getenv("AGENTRY_TEST_QUEUE_DEBUG") != "" {
		log = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	c := NewRiverClient(st, log)
	c.SetTestOnly(true)
	return c, st
}

// newIsolatedRiverTestClient is newRiverTestClient on a database of its own,
// made for the test and dropped after it. River runs its rescuer and its
// scheduler on the one client elected leader per database, and the other
// packages' tests start River clients against the shared test database at
// the same time, so a test that needs those services to run on time cannot
// share it.
func newIsolatedRiverTestClient(t *testing.T) (*RiverClient, *store.Store) {
	t.Helper()
	shared := os.Getenv("AGENTRY_TEST_DATABASE_URL")
	if shared == "" {
		t.Skip("AGENTRY_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	admin, err := store.Connect(ctx, shared)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(admin.Close)
	name := "agentry_rq_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	if _, err := admin.Pool().Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	t.Cleanup(func() {
		_, _ = admin.Pool().Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
	})
	u, err := url.Parse(shared)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	if err := store.Migrate(ctx, u.String()); err != nil {
		t.Fatalf("migrate %s: %v", name, err)
	}
	st, err := store.Connect(ctx, u.String())
	if err != nil {
		t.Fatalf("connect %s: %v", name, err)
	}
	t.Cleanup(st.Close)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if os.Getenv("AGENTRY_TEST_QUEUE_DEBUG") != "" {
		log = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	c := NewRiverClient(st, log)
	c.SetTestOnly(true)
	return c, st
}

type riverRow struct {
	State       string
	Attempt     int
	ScheduledAt time.Time
	Errors      int
	LastError   string
	// LastErrorAt is the start of the attempt that failed last, as River
	// recorded it in errors[].at.
	LastErrorAt time.Time
}

func riverJob(t *testing.T, st *store.Store, queue string) riverRow {
	t.Helper()
	var r riverRow
	var errs string
	err := st.Pool().QueryRow(context.Background(),
		// errors is a jsonb[] column; fold it into one JSON array to scan.
		`SELECT state, attempt, scheduled_at, COALESCE(array_to_json(errors)::text, '[]')
		 FROM river_job WHERE queue = $1 ORDER BY id DESC LIMIT 1`, queue).
		Scan(&r.State, &r.Attempt, &r.ScheduledAt, &errs)
	if err != nil {
		t.Fatalf("river_job row for %s: %v", queue, err)
	}
	var list []struct {
		At    time.Time `json:"at"`
		Error string    `json:"error"`
	}
	_ = json.Unmarshal([]byte(errs), &list)
	r.Errors = len(list)
	if len(list) > 0 {
		r.LastError = list[len(list)-1].Error
		r.LastErrorAt = list[len(list)-1].At
	}
	return r
}

// testQueueName gives each test its own queue and empties it first, so a
// re-run against a database that kept the last run's rows starts clean.
func testQueueName(t *testing.T, st *store.Store) string {
	t.Helper()
	q := "rq-" + strings.ToLower(strings.ReplaceAll(t.Name(), "/", "-"))
	if _, err := st.Pool().Exec(context.Background(), `DELETE FROM river_job WHERE queue = $1`, q); err != nil {
		t.Fatalf("clear queue %s: %v", q, err)
	}
	return q
}

func TestRiverRunsJobAndCompletes(t *testing.T) {
	c, st := newRiverTestClient(t)
	q := testQueueName(t, st)
	ctx := context.Background()
	var got atomic.Value
	c.Register("river.echo", func(_ context.Context, job Job) error {
		got.Store(job)
		return nil
	})
	id, err := c.Enqueue(ctx, "river.echo", q, map[string]int{"n": 7})
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	c.Drain(ctx, q)
	job, _ := got.Load().(Job)
	if job.ID != id || job.Kind != "river.echo" || job.Queue != q || job.Attempt != 1 {
		t.Fatalf("handler saw %+v, want id %s", job, id)
	}
	// River stores args as jsonb, so the bytes come back canonicalised;
	// the value is what a handler decodes.
	var args struct{ N int }
	if err := json.Unmarshal(job.Args, &args); err != nil || args.N != 7 {
		t.Fatalf("args passed through as %s (%v)", job.Args, err)
	}
	if r := riverJob(t, st, q); r.State != "completed" {
		t.Fatalf("row after drain: %+v", r)
	}
}

func TestRiverRetriesWithBackoffThenFails(t *testing.T) {
	c, st := newRiverTestClient(t)
	q := testQueueName(t, st)
	ctx := context.Background()
	var calls atomic.Int32
	c.Register("river.flaky", func(context.Context, Job) error {
		calls.Add(1)
		return errors.New("boom")
	})
	if _, err := c.Enqueue(ctx, "river.flaky", q, struct{}{}, WithMaxAttempts(2)); err != nil {
		t.Fatal(err)
	}
	c.Drain(ctx, q)
	r := riverJob(t, st, q)
	// A retry due within River's scheduler interval is written back as
	// available with a future scheduled_at (the fetch honours the time)
	// rather than taking the retryable→available hop; either is a retry.
	if (r.State != "retryable" && r.State != "available") || r.Attempt != 1 || calls.Load() != 1 {
		t.Fatalf("after first attempt: %+v calls=%d", r, calls.Load())
	}
	// Measure the backoff River recorded, not the distance from now: the
	// attempt's error is stamped with its start time and NextRetry adds 2^1 s
	// after the handler returns, so the gap is 2 s plus the handler's own
	// (instant) run however late this read lands on a loaded runner
	// (agentry#394). The millisecond of slack covers scheduled_at's
	// microsecond storage.
	if backoff := r.ScheduledAt.Sub(r.LastErrorAt); backoff < 2*time.Second-time.Millisecond || backoff > 3*time.Second {
		t.Fatalf("retry backoff %v (scheduled %v, attempt started %v), want 2s", backoff, r.ScheduledAt, r.LastErrorAt)
	}
	// Bring the retry forward rather than sleeping through the backoff.
	if _, err := st.Pool().Exec(ctx, `UPDATE river_job SET scheduled_at = now() WHERE queue = $1`, q); err != nil {
		t.Fatal(err)
	}
	c.Drain(ctx, q)
	r = riverJob(t, st, q)
	if r.State != "discarded" || r.Attempt != 2 || r.Errors != 2 || !strings.Contains(r.LastError, "boom") || calls.Load() != 2 {
		t.Fatalf("after last attempt: %+v calls=%d", r, calls.Load())
	}
}

func TestRiverRecoversFromHandlerPanic(t *testing.T) {
	c, st := newRiverTestClient(t)
	q := testQueueName(t, st)
	ctx := context.Background()
	c.Register("river.panic", func(context.Context, Job) error { panic("kaboom") })
	if _, err := c.Enqueue(ctx, "river.panic", q, struct{}{}, WithMaxAttempts(1)); err != nil {
		t.Fatal(err)
	}
	c.Drain(ctx, q)
	r := riverJob(t, st, q)
	if r.State != "discarded" || !strings.Contains(r.LastError, "handler panic: kaboom") {
		t.Fatalf("panicking job: %+v", r)
	}
}

func TestRiverUnknownKindIsCancelled(t *testing.T) {
	c, st := newRiverTestClient(t)
	q := testQueueName(t, st)
	ctx := context.Background()
	c.Register("river.known", func(context.Context, Job) error { return nil })
	if _, err := c.Enqueue(ctx, "river.unknown", q, struct{}{}); err != nil {
		t.Fatal(err)
	}
	c.Drain(ctx, q)
	if r := riverJob(t, st, q); r.State != "cancelled" {
		t.Fatalf("job of an unregistered kind: %+v", r)
	}
}

func TestRiverDelayedJobWaits(t *testing.T) {
	c, st := newRiverTestClient(t)
	q := testQueueName(t, st)
	ctx := context.Background()
	var ran atomic.Bool
	c.Register("river.later", func(context.Context, Job) error { ran.Store(true); return nil })
	if _, err := c.Enqueue(ctx, "river.later", q, struct{}{}, WithDelay(time.Hour)); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	c.Drain(ctx, q)
	if ran.Load() {
		t.Fatal("a job scheduled an hour out ran")
	}
	if time.Since(started) > 20*time.Second {
		t.Fatal("drain waited on a deliberately delayed job")
	}
	if r := riverJob(t, st, q); r.State != "scheduled" {
		t.Fatalf("delayed job: %+v", r)
	}
}

// TestRiverRescuesAJobItsWorkerLeftRunning pins crash recovery under River,
// production's driver (agentry#750): a job left running by a worker that died
// (an evicted pod, a node gone) is rescued once it has been running longer
// than the reclaim cutoff, and runs again on a live worker, while a job a
// healthy worker holds right now is left alone. It is the River half of
// TestQueueReclaimsOrphanedJobs and TestQueueReclaimRespectsCutoff: without
// it a scan whose worker died stays in scanning.
func TestRiverRescuesAJobItsWorkerLeftRunning(t *testing.T) {
	// The cutoff this relies on: a job running for longer is presumed
	// orphaned. A change to it moves both rows below.
	if defaultReclaimAfter != 30*time.Minute {
		t.Fatalf("defaultReclaimAfter = %s: re-check the rows' ages below", defaultReclaimAfter)
	}
	// Its own database: the rescue runs only on River's elected leader.
	c, st := newIsolatedRiverTestClient(t)
	q := testQueueName(t, st)
	ctx := context.Background()
	var orphanRuns, heldRuns atomic.Int32
	c.Register("river.orphan", func(context.Context, Job) error { orphanRuns.Add(1); return nil })
	c.Register("river.held", func(context.Context, Job) error { heldRuns.Add(1); return nil })
	for _, kind := range []string{"river.orphan", "river.held"} {
		if _, err := c.Enqueue(ctx, kind, q, struct{}{}); err != nil {
			t.Fatal(err)
		}
	}
	// A worker claimed both and died: the orphan two hours ago, past the
	// cutoff; the held job a moment ago, well inside it.
	for kind, age := range map[string]string{"river.orphan": "2 hours", "river.held": "0 seconds"} {
		if _, err := st.Pool().Exec(ctx, `
			UPDATE river_job SET state = 'running', attempt = 1,
			       attempted_at = now() - $3::interval, attempted_by = ARRAY['a-dead-worker']
			WHERE queue = $1 AND kind = $2`, q, kind, age); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = st.Pool().Exec(context.Background(), `DELETE FROM river_job WHERE queue = $1`, q)
	})

	workCtx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); _ = c.Work(workCtx, q) }()
	deadline := time.Now().Add(45 * time.Second)
	for orphanRuns.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	stop()
	<-done

	if n := orphanRuns.Load(); n != 1 {
		t.Fatalf("the orphaned job ran %d times, want 1: River never rescued it", n)
	}
	var state string
	var errs int
	if err := st.Pool().QueryRow(ctx, `
		SELECT state, coalesce(array_length(errors, 1), 0) FROM river_job
		WHERE queue = $1 AND kind = 'river.orphan'`, q).Scan(&state, &errs); err != nil {
		t.Fatal(err)
	}
	if state != "completed" || errs != 1 {
		t.Fatalf("orphaned job: state %s with %d recorded errors, want completed after one rescue", state, errs)
	}
	// The held job is inside the cutoff, so the pass that took the orphan
	// left it alone.
	if err := st.Pool().QueryRow(ctx, `
		SELECT state FROM river_job WHERE queue = $1 AND kind = 'river.held'`, q).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "running" || heldRuns.Load() != 0 {
		t.Fatalf("held job: state %s, ran %d times; a job inside the cutoff must be left to its worker", state, heldRuns.Load())
	}
}

// TestRiverJobTimeoutLeavesRoomForTheRescue guards the configuration the
// rescue depends on (agentry#750). River refuses a timeout past the rescue
// cutoff but accepts the two that break it: -1, with which no job is ever
// rescued, and a timeout equal to the cutoff, which would rescue a job its
// worker still runs. TestRiverRescuesAJobItsWorkerLeftRunning pins that the
// value reaches River.
func TestRiverJobTimeoutLeavesRoomForTheRescue(t *testing.T) {
	c := NewRiverClient(nil, nil)
	if c.jobTimeout <= 0 {
		t.Fatalf("jobTimeout = %s: River never rescues a job without a timeout", c.jobTimeout)
	}
	if c.jobTimeout >= c.reclaimAfter {
		t.Fatalf("jobTimeout %s must be under the rescue cutoff %s", c.jobTimeout, c.reclaimAfter)
	}
}

func TestOpenSelectsDriver(t *testing.T) {
	if _, ok := must(Open("", 3, nil, nil)).(*RiverClient); !ok {
		t.Error("empty driver should be river")
	}
	if c := must(Open("river", 3, nil, nil)).(*RiverClient); c.maxWorkers != 3 {
		t.Errorf("maxWorkers = %d, want 3", c.maxWorkers)
	}
	if _, ok := must(Open("pg", 3, nil, nil)).(*PGClient); !ok {
		t.Error("pg driver should be the SKIP LOCKED client")
	}
	if _, err := Open("bogus", 1, nil, nil); err == nil {
		t.Error("unknown driver accepted")
	}
	if _, err := uuid.Parse(uuid.Nil.String()); err != nil {
		t.Fatal(err)
	}
}

func must(w Worker, err error) Worker {
	if err != nil {
		panic(err)
	}
	return w
}
