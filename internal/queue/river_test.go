package queue

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
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

type riverRow struct {
	State       string
	Attempt     int
	ScheduledAt time.Time
	Errors      int
	LastError   string
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
		Error string `json:"error"`
	}
	_ = json.Unmarshal([]byte(errs), &list)
	r.Errors = len(list)
	if len(list) > 0 {
		r.LastError = list[len(list)-1].Error
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
	if wait := time.Until(r.ScheduledAt); wait < 500*time.Millisecond || wait > 5*time.Second {
		t.Fatalf("retry backoff %v, want about 2s", wait)
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
