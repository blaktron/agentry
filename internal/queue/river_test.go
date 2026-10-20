package queue

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/blaktron/agentry/internal/metrics"
	"github.com/blaktron/agentry/internal/store"
)

// closeStore closes the store, giving up on a pool in which a failing test
// left a transaction or a running worker open: its Close never returns.
func closeStore(st *store.Store) {
	closed := make(chan struct{})
	go func() { st.Close(); close(closed) }()
	limit, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	select {
	case <-closed:
	case <-limit.Done():
	}
}

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
	t.Cleanup(func() { closeStore(st) })
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
	t.Cleanup(func() { closeStore(st) })
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
	if len(q) > 64 {
		// River's limit on a queue name; a subtest's name can pass it.
		sum := sha256.Sum256([]byte(q))
		q = strings.TrimRight(q[:40], "-_") + "-" + hex.EncodeToString(sum[:4])
	}
	if _, err := st.Pool().Exec(context.Background(), `DELETE FROM river_job WHERE queue = $1`, q); err != nil {
		t.Fatalf("clear queue %s: %v", q, err)
	}
	return q
}

// newQueueMetrics is the instrument set a client under test reports to; its
// exposition is read back with metricValue.
func newQueueMetrics(t *testing.T) *metrics.Metrics {
	t.Helper()
	m, err := metrics.New(context.Background(), metrics.Config{ServiceName: "agentryd", Role: "all", Env: "dev"})
	if err != nil {
		t.Fatalf("metrics: %v", err)
	}
	t.Cleanup(func() { _ = m.Shutdown(context.Background()) })
	return m
}

// metricValue is the exposition value of the series of name that carries
// every label pair given (`queue="x"`), and whether there is one.
func metricValue(t *testing.T, m *metrics.Metrics, name string, labels ...string) (string, bool) {
	t.Helper()
	body, err := m.Gather(context.Background())
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, line := range strings.Split(string(body), "\n") {
		if !strings.HasPrefix(line, name+"{") {
			continue
		}
		match := true
		for _, l := range labels {
			match = match && strings.Contains(line, l)
		}
		if match {
			f := strings.Fields(line)
			return f[len(f)-1], true
		}
	}
	return "", false
}

// wantJobOutcomes checks the QueueJobs counter of one queue and kind: every
// outcome named has exactly its count and no other outcome was recorded.
func wantJobOutcomes(t *testing.T, m *metrics.Metrics, queue, kind string, want map[string]string) {
	t.Helper()
	for _, outcome := range []string{"ok", "retry", "failed", "no_handler"} {
		got, found := metricValue(t, m, "QueueJobs", `queue="`+queue+`"`, `kind="`+kind+`"`, `outcome="`+outcome+`"`)
		switch w, expected := want[outcome], want[outcome] != ""; {
		case expected && (!found || got != w):
			t.Errorf("QueueJobs outcome %s for %s = %q (recorded %v), want %s", outcome, kind, got, found, w)
		case !expected && found:
			t.Errorf("QueueJobs outcome %s for %s = %s, want none recorded", outcome, kind, got)
		}
	}
}

func TestRiverRunsJobAndCompletes(t *testing.T) {
	c, st := newRiverTestClient(t)
	q := testQueueName(t, st)
	ctx := context.Background()
	mx := newQueueMetrics(t)
	c.SetMetrics(mx, 0)
	var got atomic.Value
	var deadline atomic.Value
	c.Register("river.echo", func(ctx context.Context, job Job) error {
		got.Store(job)
		if d, ok := ctx.Deadline(); ok {
			deadline.Store(d)
		}
		return nil
	})
	enqueued := time.Now()
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
	// Every attempt runs under River's job timeout of 25 minutes: the
	// deadline the handler's context carries is that long after the
	// attempt began, which is after the enqueue and before this read.
	d, _ := deadline.Load().(time.Time)
	if d.Before(enqueued.Add(25*time.Minute)) || d.After(time.Now().Add(25*time.Minute)) {
		t.Fatalf("the handler's deadline is %v, want 25 minutes after the attempt began (between %v and %v)",
			d, enqueued.Add(25*time.Minute), time.Now().Add(25*time.Minute))
	}
	wantJobOutcomes(t, mx, q, "river.echo", map[string]string{"ok": "1"})

	// The retry budget is 5 attempts unless the caller sets one, and the
	// River row carries the agentry id the caller was handed.
	t.Run("the attempt budget", func(t *testing.T) {
		q := testQueueName(t, st)
		attempts := func(id uuid.UUID) int {
			t.Helper()
			var n int
			if err := st.Pool().QueryRow(ctx, `SELECT max_attempts FROM river_job WHERE queue = $1 AND metadata->>'id' = $2`, q, id.String()).Scan(&n); err != nil {
				t.Fatalf("river_job row of %s: %v", id, err)
			}
			return n
		}
		def, err := c.Enqueue(ctx, "river.budget", q, struct{}{})
		if err != nil {
			t.Fatal(err)
		}
		seven, err := c.Enqueue(ctx, "river.budget", q, struct{}{}, WithMaxAttempts(7))
		if err != nil {
			t.Fatal(err)
		}
		if n := attempts(def); n != 5 {
			t.Errorf("max attempts by default = %d, want 5", n)
		}
		if n := attempts(seven); n != 7 {
			t.Errorf("max attempts with WithMaxAttempts(7) = %d, want 7", n)
		}
	})

	// A job that cannot be stored is refused with its reason and nothing
	// is left in the table.
	t.Run("what enqueue refuses", func(t *testing.T) {
		q := testQueueName(t, st)
		kind := "river.refused"
		count := func() int {
			t.Helper()
			var n int
			if err := st.Pool().QueryRow(ctx, `SELECT count(*) FROM river_job WHERE kind = $1`, kind).Scan(&n); err != nil {
				t.Fatal(err)
			}
			return n
		}
		before := count()
		if id, err := c.Enqueue(ctx, kind, q, make(chan int)); err == nil || !strings.Contains(err.Error(), "marshal args") || id != uuid.Nil {
			t.Errorf("args that are not JSON: id %s, err %v, want a marshal error and no id", id, err)
		}
		if id, err := c.Enqueue(ctx, kind, "Not A Queue", struct{}{}); err == nil || !strings.Contains(err.Error(), "queue: enqueue") || id != uuid.Nil {
			t.Errorf("queue name River refuses: id %s, err %v, want an enqueue error and no id", id, err)
		}
		if id, err := c.Enqueue(ctx, kind, q, struct{}{}, WithMaxAttempts(-1)); err == nil || !strings.Contains(err.Error(), "queue: enqueue") || id != uuid.Nil {
			t.Errorf("a negative attempt budget: id %s, err %v, want the table's refusal as an enqueue error and no id", id, err)
		}
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		if id, err := c.Enqueue(cancelled, kind, q, struct{}{}); err == nil || id != uuid.Nil {
			t.Errorf("enqueue under a cancelled context: id %s, err %v, want an error and no id", id, err)
		}
		if n := count(); n != before {
			t.Errorf("%d job(s) of the refused kind were stored", n-before)
		}
	})

	// A kind registered twice runs the second handler only.
	t.Run("registering a kind twice replaces the handler", func(t *testing.T) {
		q := testQueueName(t, st)
		var first, second atomic.Int32
		c.Register("river.twice", func(context.Context, Job) error { first.Add(1); return nil })
		c.Register("river.twice", func(context.Context, Job) error { second.Add(1); return nil })
		if _, err := c.Enqueue(ctx, "river.twice", q, struct{}{}); err != nil {
			t.Fatal(err)
		}
		c.Drain(ctx, q)
		if first.Load() != 0 || second.Load() != 1 {
			t.Fatalf("handlers ran first=%d second=%d, want the second one only", first.Load(), second.Load())
		}
	})

	// A job enqueued with no queue name goes to "core", and a worker or a
	// drain given no queues works "core". River's rescuer and scheduler run
	// on one elected client per database, so this is a database of its own.
	t.Run("no queue named means core", func(t *testing.T) {
		c, st := newIsolatedRiverTestClient(t)
		ran := make(chan Job, 4)
		c.Register("river.core", func(_ context.Context, job Job) error { ran <- job; return nil })
		stateAndQueue := func(id uuid.UUID) (state, queue string) {
			t.Helper()
			if err := st.Pool().QueryRow(ctx, `SELECT state, queue FROM river_job WHERE metadata->>'id' = $1`, id.String()).Scan(&state, &queue); err != nil {
				t.Fatalf("river_job row of %s: %v", id, err)
			}
			return state, queue
		}

		drained, err := c.Enqueue(ctx, "river.core", "", struct{}{})
		if err != nil {
			t.Fatal(err)
		}
		if _, queue := stateAndQueue(drained); queue != "core" {
			t.Fatalf("a job enqueued with no queue name is in queue %q, want core", queue)
		}
		c.Drain(ctx)
		if state, _ := stateAndQueue(drained); state != "completed" {
			t.Fatalf("job in core after Drain with no queues: state %s, want completed", state)
		}
		if job := <-ran; job.ID != drained || job.Queue != "core" {
			t.Fatalf("handler saw %+v, want job %s in core", job, drained)
		}

		worked, err := c.Enqueue(ctx, "river.core", "", struct{}{})
		if err != nil {
			t.Fatal(err)
		}
		waitCtx, giveUp := context.WithTimeout(ctx, 60*time.Second)
		defer giveUp()
		workCtx, stop := context.WithCancel(ctx)
		t.Cleanup(stop)
		done := make(chan error, 1)
		go func() { done <- c.Work(workCtx) }()
		select {
		case job := <-ran:
			if job.ID != worked || job.Queue != "core" {
				t.Errorf("handler saw %+v, want job %s in core", job, worked)
			}
		case <-waitCtx.Done():
			t.Error("Work with no queues never ran the job in core")
		}
		stop()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Errorf("Work returned %v after its context was cancelled, want context.Canceled", err)
		}
	})

	// Stopping a worker lets a running job finish; only after the grace
	// period are the jobs still running cancelled.
	stopping := func(t *testing.T, grace time.Duration, release bool) (cancelled bool, state string) {
		t.Helper()
		c, st := newRiverTestClient(t)
		q := testQueueName(t, st)
		if grace > 0 {
			c.stopGrace = grace
		}
		started := make(chan struct{})
		letGo := make(chan struct{})
		var sawCancel atomic.Bool
		c.Register("river.slow", func(ctx context.Context, _ Job) error {
			close(started)
			select {
			case <-ctx.Done():
				sawCancel.Store(true)
				return ctx.Err()
			case <-letGo:
				return nil
			}
		})
		if _, err := c.Enqueue(ctx, "river.slow", q, struct{}{}); err != nil {
			t.Fatal(err)
		}
		waitCtx, giveUp := context.WithTimeout(ctx, 60*time.Second)
		defer giveUp()
		workCtx, stop := context.WithCancel(ctx)
		t.Cleanup(stop)
		done := make(chan error, 1)
		go func() { done <- c.Work(workCtx, q) }()
		select {
		case <-started:
		case <-waitCtx.Done():
			stop()
			t.Fatal("the job never started")
		}
		stop()
		if release {
			close(letGo)
		}
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Errorf("Work returned %v, want context.Canceled", err)
		}
		return sawCancel.Load(), riverJob(t, st, q).State
	}
	t.Run("a worker that stops lets a running job finish", func(t *testing.T) {
		if cancelled, state := stopping(t, 0, true); cancelled || state != "completed" {
			t.Fatalf("job running when the worker stopped: cancelled=%v state=%s, want it left to finish and completed", cancelled, state)
		}
	})
	t.Run("a worker that stops cancels what outlives the grace period", func(t *testing.T) {
		cancelled, state := stopping(t, 50*time.Millisecond, false)
		if !cancelled || state == "completed" {
			t.Fatalf("job outliving the grace period: cancelled=%v state=%s, want it cancelled and not completed", cancelled, state)
		}
	})

	// A job put into the table without anyone announcing it (a row written
	// by SQL does not notify) is found by the worker's own polling, every
	// poll interval it was given. The worker is idle and started when the
	// row is written: its first sample is published after it started, and no
	// job is finishing, so only the poll can find the row.
	t.Run("a worker polls for jobs nobody announced", func(t *testing.T) {
		c, st := newRiverTestClient(t)
		q := testQueueName(t, st)
		mx := newQueueMetrics(t)
		c.SetMetrics(mx, time.Hour)
		c.pollInterval = 20 * time.Millisecond
		ran := make(chan struct{}, 1)
		c.Register("river.unannounced", func(context.Context, Job) error { ran <- struct{}{}; return nil })
		waitCtx, giveUp := context.WithTimeout(ctx, 30*time.Second)
		defer giveUp()
		workCtx, stop := context.WithCancel(ctx)
		t.Cleanup(stop)
		done := make(chan error, 1)
		go func() { done <- c.Work(workCtx, q) }()
		for {
			if _, up := metricValue(t, mx, "QueueDepth", `queue="`+q+`"`); up {
				break
			}
			if waitCtx.Err() != nil {
				stop()
				t.Fatal("the worker never started")
			}
			runtime.Gosched()
		}
		if _, err := st.Pool().Exec(ctx, `INSERT INTO river_job (kind, queue, args, max_attempts) VALUES ('river.unannounced', $1, '{}', 3)`, q); err != nil {
			stop()
			t.Fatal(err)
		}
		select {
		case <-ran:
		case <-waitCtx.Done():
			t.Error("a job inserted without a notification was never picked up by polling")
		}
		stop()
		if err := <-done; err != nil {
			t.Logf("worker stopped: %v", err)
		}
	})

	// The envelope is River's job args: an empty one marshals as JSON null,
	// the handler's own JSON passes through untouched.
	t.Run("the envelope", func(t *testing.T) {
		if b, err := json.Marshal(envelope{kind: "k"}); err != nil || string(b) != "null" {
			t.Errorf("empty envelope marshals as %s (%v), want null", b, err)
		}
		if b, err := json.Marshal(envelope{kind: "k", raw: json.RawMessage(`{"a":1}`)}); err != nil || string(b) != `{"a":1}` {
			t.Errorf("envelope marshals as %s (%v), want its payload", b, err)
		}
		var e envelope
		if err := json.Unmarshal([]byte(`{"b":2}`), &e); err != nil || string(e.raw) != `{"b":2}` {
			t.Errorf("envelope decoded %s (%v), want the payload kept", e.raw, err)
		}
	})
}

func TestRiverRetriesWithBackoffThenFails(t *testing.T) {
	c, st := newRiverTestClient(t)
	q := testQueueName(t, st)
	ctx := context.Background()
	mx := newQueueMetrics(t)
	c.SetMetrics(mx, 0)
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
	// (instant) run however late this read lands on a loaded runner. The
	// millisecond of slack covers scheduled_at's microsecond storage.
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
	// The first failure is counted as a retry, the one that used the last
	// attempt as the failure.
	wantJobOutcomes(t, mx, q, "river.flaky", map[string]string{"retry": "1", "failed": "1"})

	// The delay is 2^attempt seconds: 2, 4, 8 after the first three
	// attempts. Attempt one alone cannot tell it from 2*attempt.
	t.Run("the delay doubles with each attempt", func(t *testing.T) {
		q := testQueueName(t, st)
		c.Register("river.doubling", func(context.Context, Job) error { return errors.New("again") })
		if _, err := c.Enqueue(ctx, "river.doubling", q, struct{}{}, WithMaxAttempts(4)); err != nil {
			t.Fatal(err)
		}
		for attempt := 1; attempt <= 3; attempt++ {
			c.Drain(ctx, q)
			r := riverJob(t, st, q)
			want := time.Duration(1<<attempt) * time.Second
			backoff := r.ScheduledAt.Sub(r.LastErrorAt)
			if r.Attempt != attempt || backoff < want-time.Millisecond || backoff > want+time.Second {
				t.Fatalf("after attempt %d: %+v, retry backoff %v, want %v", attempt, r, backoff, want)
			}
			if _, err := st.Pool().Exec(ctx, `UPDATE river_job SET scheduled_at = now() WHERE queue = $1`, q); err != nil {
				t.Fatal(err)
			}
		}
		c.Drain(ctx, q)
		if r := riverJob(t, st, q); r.State != "discarded" || r.Attempt != 4 || r.Errors != 4 {
			t.Fatalf("after the fourth attempt: %+v, want discarded after 4 attempts", r)
		}
	})
}

func TestRiverRecoversFromHandlerPanic(t *testing.T) {
	c, st := newRiverTestClient(t)
	q := testQueueName(t, st)
	ctx := context.Background()
	mx := newQueueMetrics(t)
	c.SetMetrics(mx, 0)
	c.Register("river.panic", func(context.Context, Job) error { panic("kaboom") })
	var after atomic.Int32
	c.Register("river.after-panic", func(context.Context, Job) error { after.Add(1); return nil })
	if _, err := c.Enqueue(ctx, "river.panic", q, struct{}{}, WithMaxAttempts(1)); err != nil {
		t.Fatal(err)
	}
	c.Drain(ctx, q)
	r := riverJob(t, st, q)
	if r.State != "discarded" || !strings.Contains(r.LastError, "handler panic: kaboom") {
		t.Fatalf("panicking job: %+v", r)
	}
	// The stack goes to the log; the error River records is the message alone.
	if r.LastError != "queue: handler panic: kaboom" {
		t.Fatalf("recorded error %q, want exactly %q (no stack)", r.LastError, "queue: handler panic: kaboom")
	}
	wantJobOutcomes(t, mx, q, "river.panic", map[string]string{"failed": "1"})
	// One bad job never kills the worker: the next job runs.
	if _, err := c.Enqueue(ctx, "river.after-panic", q, struct{}{}); err != nil {
		t.Fatal(err)
	}
	c.Drain(ctx, q)
	if after.Load() != 1 {
		t.Fatalf("the job after the panic ran %d times, want 1", after.Load())
	}
}

func TestRiverUnknownKindIsCancelled(t *testing.T) {
	c, st := newRiverTestClient(t)
	q := testQueueName(t, st)
	ctx := context.Background()
	mx := newQueueMetrics(t)
	c.SetMetrics(mx, 0)
	c.Register("river.known", func(context.Context, Job) error { return nil })
	if _, err := c.Enqueue(ctx, "river.unknown", q, struct{}{}); err != nil {
		t.Fatal(err)
	}
	c.Drain(ctx, q)
	if r := riverJob(t, st, q); r.State != "cancelled" {
		t.Fatalf("job of an unregistered kind: %+v", r)
	}
	// It is counted as a wiring fault, not as a failure or a retry.
	wantJobOutcomes(t, mx, q, "river.unknown", map[string]string{"no_handler": "1"})

	// The paths River cannot reach on its own: a worker whose handler is
	// gone cancels the job at once, and a panic that gets past the
	// handler's recovery is logged and left to River's retry.
	t.Run("a worker without a handler", func(t *testing.T) {
		job := &river.Job[envelope]{JobRow: &rivertype.JobRow{ID: 7, Kind: "river.nobody", Queue: q}}
		err := (&riverWorker{c: c}).Work(ctx, job)
		var cancelled *rivertype.JobCancelError
		if !errors.As(err, &cancelled) {
			t.Fatalf("worker without a handler returned %v, want a cancellation", err)
		}
		wantJobOutcomes(t, mx, q, "river.nobody", map[string]string{"no_handler": "1"})
	})
	t.Run("a panic past the recovery", func(t *testing.T) {
		var logged bytes.Buffer
		c := NewRiverClient(nil, slog.New(slog.NewTextHandler(&logged, nil)))
		row := &rivertype.JobRow{ID: 9, Kind: "river.escaped", Queue: q}
		if res := (&riverErrors{c: c}).HandlePanic(ctx, row, "escaped", "trace-text"); res != nil {
			t.Errorf("HandlePanic = %+v, want River's own retry (nil)", res)
		}
		if out := logged.String(); !strings.Contains(out, "queue: handler panic") || !strings.Contains(out, "escaped") || !strings.Contains(out, "trace-text") {
			t.Errorf("panic log %q lacks the message, the value or the stack", out)
		}
	})
}

func TestRiverDelayedJobWaits(t *testing.T) {
	c, st := newRiverTestClient(t)
	q := testQueueName(t, st)
	ctx := context.Background()
	var ran atomic.Bool
	c.Register("river.later", func(context.Context, Job) error { ran.Store(true); return nil })
	enqueued := time.Now()
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
	r := riverJob(t, st, q)
	if r.State != "scheduled" {
		t.Fatalf("delayed job: %+v", r)
	}
	// It is due an hour after it was enqueued, not at some other time in
	// the future. (The database keeps microseconds.)
	if r.ScheduledAt.Before(enqueued.Add(time.Hour-time.Millisecond)) || r.ScheduledAt.After(started.Add(time.Hour)) {
		t.Fatalf("delayed job is scheduled for %v, want an hour after it was enqueued (%v to %v)", r.ScheduledAt, enqueued.Add(time.Hour), started.Add(time.Hour))
	}

	// A drain works the queues it is given and waits on nothing else: a
	// job ready in another queue is neither run nor waited for.
	other := q + "-other"
	if _, err := st.Pool().Exec(ctx, `DELETE FROM river_job WHERE queue = $1`, other); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = st.Pool().Exec(context.Background(), `DELETE FROM river_job WHERE queue = $1`, other)
	})
	var elsewhere atomic.Bool
	c.Register("river.elsewhere", func(context.Context, Job) error { elsewhere.Store(true); return nil })
	if _, err := c.Enqueue(ctx, "river.elsewhere", other, struct{}{}); err != nil {
		t.Fatal(err)
	}
	started = time.Now()
	c.Drain(ctx, q)
	if time.Since(started) > 20*time.Second {
		t.Fatal("drain waited on a job in a queue it was not given")
	}
	if elsewhere.Load() {
		t.Fatal("drain ran a job from a queue it was not given")
	}
	if r := riverJob(t, st, other); r.State != "available" {
		t.Fatalf("job in the other queue: %+v, want it left available", r)
	}
}

// TestRiverRescuesAJobItsWorkerLeftRunning pins crash recovery under River,
// production's driver: a job left running by a worker that died
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
	var orphanRuns, heldRuns, lateRuns, nearRuns, lastRuns atomic.Int32
	var lastJob atomic.Value
	c.Register("river.orphan", func(context.Context, Job) error { orphanRuns.Add(1); return nil })
	c.Register("river.held", func(context.Context, Job) error { heldRuns.Add(1); return nil })
	c.Register("river.late", func(context.Context, Job) error { lateRuns.Add(1); return nil })
	c.Register("river.near", func(context.Context, Job) error { nearRuns.Add(1); return nil })
	c.Register("river.last", func(_ context.Context, job Job) error { lastRuns.Add(1); lastJob.Store(job); return nil })
	for _, kind := range []string{"river.orphan", "river.held", "river.late", "river.near"} {
		if _, err := c.Enqueue(ctx, kind, q, struct{}{}); err != nil {
			t.Fatal(err)
		}
	}
	// A job on its last attempt that its worker took with it: River's
	// rescuer discards it without calling the handler again.
	lastID, err := c.Enqueue(ctx, "river.last", q, map[string]string{"pack": "p-1"}, WithMaxAttempts(1))
	if err != nil {
		t.Fatal(err)
	}
	// A worker claimed all of them and died: the orphan two hours ago, past
	// the cutoff; the held job a moment ago, well inside it; and, either
	// side of the cutoff itself, one claimed 31 minutes ago (rescued) and
	// one 29 minutes ago (left alone).
	for kind, age := range map[string]string{"river.orphan": "2 hours", "river.held": "0 seconds", "river.late": "31 minutes", "river.near": "29 minutes", "river.last": "2 hours"} {
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
	t.Cleanup(stop)
	done := make(chan struct{})
	go func() { defer close(done); _ = c.Work(workCtx, q) }()
	deadline := time.Now().Add(45 * time.Second)
	for (orphanRuns.Load() == 0 || lateRuns.Load() == 0) && time.Now().Before(deadline) {
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
	// The cutoff is 30 minutes: past it the job is rescued, a minute short
	// of it the job is its worker's.
	if err := st.Pool().QueryRow(ctx, `
		SELECT state, coalesce(array_length(errors, 1), 0) FROM river_job
		WHERE queue = $1 AND kind = 'river.late'`, q).Scan(&state, &errs); err != nil {
		t.Fatal(err)
	}
	if lateRuns.Load() != 1 || state != "completed" || errs != 1 {
		t.Fatalf("job claimed 31 minutes ago: ran %d times, state %s, %d recorded errors; want one rescue and a completed run", lateRuns.Load(), state, errs)
	}
	if err := st.Pool().QueryRow(ctx, `
		SELECT state FROM river_job WHERE queue = $1 AND kind = 'river.near'`, q).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "running" || nearRuns.Load() != 0 {
		t.Fatalf("job claimed 29 minutes ago: state %s, ran %d times; inside the cutoff it is left to its worker", state, nearRuns.Load())
	}

	// A job rescued on its last attempt is discarded with River's own
	// message and its handler never runs; SettleRescued recognises that
	// message and gives it the last attempt it lost.
	var lastState string
	if err := st.Pool().QueryRow(ctx, `
		SELECT state FROM river_job WHERE queue = $1 AND kind = 'river.last'`, q).Scan(&lastState); err != nil {
		t.Fatal(err)
	}
	if lastState != "discarded" || lastRuns.Load() != 0 {
		t.Fatalf("job rescued on its last attempt: state %s, ran %d times, want discarded with no run", lastState, lastRuns.Load())
	}
	if n, err := c.SettleRescued(ctx); err != nil || n != 1 {
		t.Fatalf("SettleRescued after River's rescue = %d, %v, want the one discarded job settled", n, err)
	}
	// The two jobs the dead worker still "holds" would keep the drain
	// waiting; they have been checked, so end them.
	if _, err := st.Pool().Exec(ctx, `
		UPDATE river_job SET state = 'cancelled', finalized_at = now()
		WHERE queue = $1 AND kind IN ('river.held', 'river.near')`, q); err != nil {
		t.Fatal(err)
	}
	c.Drain(ctx, q)
	job, _ := lastJob.Load().(Job)
	if lastRuns.Load() != 1 || job.Attempt != 1 || job.Kind != "river.last" || job.ID == lastID {
		t.Fatalf("last attempt of the rescued job: ran %d times, saw %+v, want one run as attempt 1 under a new id", lastRuns.Load(), job)
	}
}

// TestRiverJobTimeoutLeavesRoomForTheRescue guards the configuration the
// rescue depends on. River refuses a timeout past the rescue
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
	// What a new client starts with: the cutoff the rescue test relies on,
	// the 25-minute attempt limit, one worker per queue, a 30-second grace
	// period for running jobs to finish on a stop, and a backlog sample far
	// more often than the 15-minute queue-age alarm looks.
	if c.reclaimAfter != 30*time.Minute || c.jobTimeout != 25*time.Minute {
		t.Errorf("rescue cutoff %s and job timeout %s, want 30m and 25m", c.reclaimAfter, c.jobTimeout)
	}
	if c.maxWorkers != 1 || c.stopGrace != 30*time.Second || c.pollInterval != time.Second {
		t.Errorf("workers %d, stop grace %s, poll %s, want 1, 30s, 1s", c.maxWorkers, c.stopGrace, c.pollInterval)
	}
	if c.sampleEvery != defaultSampleEvery || c.sampleEvery <= 0 || c.sampleEvery > time.Minute {
		t.Errorf("backlog sample every %s, want the default and no more than a minute", c.sampleEvery)
	}
	if c.log == nil {
		t.Error("a client built without a logger has none: its first log line would panic")
	}
	// The test switch is passed on, not ignored.
	if c.testOnly {
		t.Error("a new client is in test-only mode")
	}
	c.SetTestOnly(true)
	if !c.testOnly {
		t.Error("SetTestOnly(true) left test-only mode off")
	}
	c.SetTestOnly(false)
	if c.testOnly {
		t.Error("SetTestOnly(false) left test-only mode on")
	}
	// SetMetrics keeps the default interval when none is given.
	c.SetMetrics(nil, 0)
	if c.sampleEvery != defaultSampleEvery {
		t.Errorf("SetMetrics with no interval left %s, want the default", c.sampleEvery)
	}
	c.SetMetrics(nil, 3*time.Second)
	if c.sampleEvery != 3*time.Second {
		t.Errorf("SetMetrics(3s) left %s", c.sampleEvery)
	}
}

func TestOpenSelectsDriver(t *testing.T) {
	if _, ok := must(Open("", 3, nil, nil)).(*RiverClient); !ok {
		t.Error("empty driver should be river")
	}
	if c := must(Open("river", 3, nil, nil)).(*RiverClient); c.maxWorkers != 3 {
		t.Errorf("maxWorkers = %d, want 3", c.maxWorkers)
	}
	// Without a positive count the client keeps its one worker per queue.
	for _, n := range []int{0, -1} {
		if c := must(Open("river", n, nil, nil)).(*RiverClient); c.maxWorkers != 1 {
			t.Errorf("Open(river, %d): maxWorkers = %d, want the default of 1", n, c.maxWorkers)
		}
	}
	// The pg driver name is refused.
	if _, err := Open("pg", 3, nil, nil); err == nil || !strings.Contains(err.Error(), "removed") || !strings.Contains(err.Error(), "use river") {
		t.Errorf("pg driver: %v, want a refusal that says it was removed and points at river", err)
	}
	if _, err := Open("bogus", 1, nil, nil); err == nil {
		t.Error("unknown driver accepted")
	} else if !strings.Contains(err.Error(), `"bogus"`) || !strings.Contains(err.Error(), "(river)") {
		t.Errorf("unknown driver: %v, want the name given and the one driver there is", err)
	}
	if _, err := uuid.Parse(uuid.Nil.String()); err != nil {
		t.Fatal(err)
	}

	// The count reaches River: a client opened with two workers runs two
	// jobs at once, one opened with one never runs two.
	t.Run("two workers run two jobs at once", func(t *testing.T) {
		_, st := newRiverTestClient(t)
		w, err := Open("river", 2, st, nil)
		if err != nil {
			t.Fatal(err)
		}
		c := w.(*RiverClient)
		c.SetTestOnly(true)
		q := testQueueName(t, st)
		ctx := context.Background()
		waitCtx, giveUp := context.WithTimeout(ctx, 20*time.Second)
		defer giveUp()
		both := make(chan struct{})
		var running atomic.Int32
		c.Register("river.pair", func(ctx context.Context, _ Job) error {
			if running.Add(1) == 2 {
				close(both)
			}
			defer running.Add(-1)
			select {
			case <-both:
				return nil
			case <-waitCtx.Done():
				return waitCtx.Err()
			case <-ctx.Done():
				return ctx.Err()
			}
		})
		for i := 0; i < 2; i++ {
			if _, err := c.Enqueue(ctx, "river.pair", q, struct{}{}); err != nil {
				t.Fatal(err)
			}
		}
		c.Drain(ctx, q)
		select {
		case <-both:
		default:
			t.Fatal("two jobs were never running at once with two workers")
		}
	})
	t.Run("one worker runs one job at a time", func(t *testing.T) {
		_, st := newRiverTestClient(t)
		w, err := Open("river", 1, st, nil)
		if err != nil {
			t.Fatal(err)
		}
		c := w.(*RiverClient)
		c.SetTestOnly(true)
		q := testQueueName(t, st)
		ctx := context.Background()
		var running atomic.Int32
		var overlapped atomic.Bool
		c.Register("river.single", func(ctx context.Context, _ Job) error {
			if running.Add(1) > 1 {
				overlapped.Store(true)
			}
			defer running.Add(-1)
			// Hold the worker long enough for a second one to start if
			// River would let it.
			hold, release := context.WithTimeout(ctx, 200*time.Millisecond)
			defer release()
			<-hold.Done()
			return nil
		})
		for i := 0; i < 3; i++ {
			if _, err := c.Enqueue(ctx, "river.single", q, struct{}{}); err != nil {
				t.Fatal(err)
			}
		}
		c.Drain(ctx, q)
		if overlapped.Load() {
			t.Fatal("two jobs ran at once with one worker")
		}
		var done int
		if err := st.Pool().QueryRow(ctx, `SELECT count(*) FROM river_job WHERE queue = $1 AND state = 'completed'`, q).Scan(&done); err != nil || done != 3 {
			t.Fatalf("completed jobs = %d (%v), want all 3 run one after the other", done, err)
		}
	})
}

func must(w Worker, err error) Worker {
	if err != nil {
		panic(err)
	}
	return w
}

// TestCountWaitingCountsJobsThatHaveNotStarted: the
// self-rescheduling jobs' seeds ask the driver how many of a kind wait, in
// River's own table: queued, scheduled and retrying jobs of the kind, never
// running or finished ones.
func TestCountWaitingCountsJobsThatHaveNotStarted(t *testing.T) {
	c, st := newRiverTestClient(t)
	ctx := context.Background()
	qname := testQueueName(t, st)
	kind := "test.count-waiting-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:8]

	if n, err := c.CountWaiting(ctx, kind); err != nil || n != 0 {
		t.Fatalf("River counted %d (err %v) with nothing enqueued, want 0", n, err)
	}

	// Scheduled for later and due now both wait.
	if _, err := c.Enqueue(ctx, kind, qname, struct{}{}, WithDelay(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Enqueue(ctx, kind, qname, struct{}{}); err != nil {
		t.Fatal(err)
	}
	if n, err := c.CountWaiting(ctx, kind); err != nil || n != 2 {
		t.Fatalf("River counted %d (err %v), want 2 (one scheduled, one available)", n, err)
	}

	// A finished run no longer waits.
	c.Register(kind, func(context.Context, Job) error { return nil })
	c.Drain(ctx, qname)
	if n, err := c.CountWaiting(ctx, kind); err != nil || n != 1 {
		t.Fatalf("River counted %d (err %v) after the due job ran, want 1 (the scheduled one)", n, err)
	}

	// Every state: a job waits while it is available, scheduled, retrying
	// or pending, and not once it is running or finished, and only jobs of
	// the kind asked about count.
	t.Run("each state", func(t *testing.T) {
		kind := "test.count-states-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:8]
		other := kind + "-other"
		var ids []uuid.UUID
		enqueue := func(kind string) uuid.UUID {
			t.Helper()
			id, err := c.Enqueue(ctx, kind, qname, struct{}{})
			if err != nil {
				t.Fatal(err)
			}
			ids = append(ids, id)
			return id
		}
		t.Cleanup(func() {
			for _, id := range ids {
				_, _ = st.Pool().Exec(context.Background(), `DELETE FROM river_job WHERE metadata->>'id' = $1`, id.String())
			}
		})
		set := func(id uuid.UUID, state string) {
			t.Helper()
			if _, err := st.Pool().Exec(ctx, `
				UPDATE river_job SET state = $2::river_job_state,
				       finalized_at = CASE WHEN $2 IN ('completed', 'cancelled', 'discarded') THEN now() END
				WHERE metadata->>'id' = $1`, id.String(), state); err != nil {
				t.Fatalf("set %s: %v", state, err)
			}
		}
		waiting := []string{"available", "scheduled", "retryable", "pending"}
		for _, state := range waiting {
			set(enqueue(kind), state)
		}
		for _, state := range []string{"running", "completed", "cancelled", "discarded"} {
			set(enqueue(kind), state)
		}
		set(enqueue(other), "available")
		if n, err := c.CountWaiting(ctx, kind); err != nil || n != int64(len(waiting)) {
			t.Fatalf("River counted %d (err %v), want %d: available, scheduled, retryable and pending, not running or finished or another kind", n, err, len(waiting))
		}
	})
}

// syncBuffer is a log sink that River's goroutines and the test can share.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// TestRiverSamplesTheBacklogPerQueue: the gauges the queue-age alarm reads
// count, per queue, the jobs that could be picked up this moment and the age
// of the oldest of them; delayed, running, finished and other queues' jobs
// are not in them, and an empty queue reads zero. A worker publishes them as
// it starts and again on every interval.
func TestRiverSamplesTheBacklogPerQueue(t *testing.T) {
	c, st := newRiverTestClient(t)
	ctx := context.Background()
	qa := testQueueName(t, st)
	qb, qc := qa+"-b", qa+"-c"
	for _, q := range []string{qb, qc} {
		if _, err := st.Pool().Exec(ctx, `DELETE FROM river_job WHERE queue = $1`, q); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, q := range []string{qa, qb, qc} {
			_, _ = st.Pool().Exec(context.Background(), `DELETE FROM river_job WHERE queue = $1`, q)
		}
	})
	// A job that has waited for the given age is one scheduled that long ago;
	// a negative age is a job that is not due yet.
	insert := func(queue, state, age string) {
		t.Helper()
		if _, err := st.Pool().Exec(ctx, `
			INSERT INTO river_job (state, kind, queue, args, scheduled_at, finalized_at)
			VALUES ($1::river_job_state, 'river.sampled', $2, '{}', now() - $3::interval,
			        CASE WHEN $1 IN ('completed') THEN now() END)`, state, queue, age); err != nil {
			t.Fatalf("insert %s job: %v", state, err)
		}
	}
	insert(qa, "available", "90 seconds")
	insert(qa, "available", "30 seconds")
	insert(qa, "retryable", "10 seconds")
	insert(qa, "scheduled", "-1 hour")
	insert(qa, "available", "-1 hour")
	insert(qa, "running", "5 minutes")
	insert(qa, "completed", "10 minutes")
	insert(qa, "pending", "2 minutes")
	insert(qb, "available", "5 seconds")

	number := func(mx *metrics.Metrics, name, queue string) float64 {
		t.Helper()
		v, ok := metricValue(t, mx, name, `queue="`+queue+`"`)
		if !ok {
			t.Fatalf("no %s series for queue %s", name, queue)
		}
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			t.Fatalf("%s for %s = %q: %v", name, queue, v, err)
		}
		return f
	}
	mx := newQueueMetrics(t)
	c.SetMetrics(mx, 0)
	c.sampleBacklog(ctx, []string{qa, qb, qc})
	if d := number(mx, "QueueDepth", qa); d != 3 {
		t.Errorf("depth of %s = %v, want 3 (two available and one retrying, all due)", qa, d)
	}
	// The oldest waited 90 seconds when it was inserted; a sample taken a
	// little later reads a little more, and in seconds.
	if a := number(mx, "QueueAgeSeconds", qa); a < 90 || a > 150 {
		t.Errorf("age of %s = %vs, want the oldest job's 90s", qa, a)
	}
	if d, a := number(mx, "QueueDepth", qb), number(mx, "QueueAgeSeconds", qb); d != 1 || a < 5 || a > 65 {
		t.Errorf("queue %s: depth %v, age %vs, want 1 job about 5s old", qb, d, a)
	}
	if d, a := number(mx, "QueueDepth", qc), number(mx, "QueueAgeSeconds", qc); d != 0 || a != 0 {
		t.Errorf("empty queue %s: depth %v, age %vs, want 0 and 0", qc, d, a)
	}
	// Without metrics a sample does nothing: it does not even ask the
	// database (a client whose pool is gone has nothing to log), and with
	// them a failed sample is logged unless the worker is stopping.
	bare, bareStore := newRiverTestClient(t)
	bareStore.Close()
	bareLog := &syncBuffer{}
	bare.log = slog.New(slog.NewTextHandler(bareLog, nil))
	bare.sampleBacklog(ctx, []string{qa})
	if out := bareLog.String(); out != "" {
		t.Errorf("a client without metrics sampled the backlog anyway: %s", out)
	}
	broken, brokenStore := newRiverTestClient(t)
	brokenStore.Close()
	brokenLog := &syncBuffer{}
	broken.log = slog.New(slog.NewTextHandler(brokenLog, nil))
	broken.SetMetrics(newQueueMetrics(t), 0)
	stopped, stopSampling := context.WithCancel(ctx)
	stopSampling()
	broken.sampleBacklog(stopped, []string{qa})
	if out := brokenLog.String(); out != "" {
		t.Errorf("a sample that failed because the worker was stopping was logged: %s", out)
	}
	broken.sampleBacklog(ctx, []string{qa})
	if out := brokenLog.String(); !strings.Contains(out, "queue: backlog sample") || !strings.Contains(out, "queue="+qa) {
		t.Errorf("a sample that failed was not logged with its queue: %q", out)
	}

	// Work samples when it starts and on every interval after that.
	waitCtx, giveUp := context.WithTimeout(ctx, 30*time.Second)
	defer giveUp()
	waitFor := func(what string, ok func() bool) {
		t.Helper()
		for !ok() {
			if waitCtx.Err() != nil {
				t.Fatalf("timed out waiting for %s", what)
			}
			runtime.Gosched()
		}
	}
	t.Run("a worker samples as it starts", func(t *testing.T) {
		c, st := newRiverTestClient(t)
		q := testQueueName(t, st)
		mx := newQueueMetrics(t)
		// An hour between samples: only the first one can show. (River
		// starts only with a worker registered.)
		c.SetMetrics(mx, time.Hour)
		c.Register("river.idle", func(context.Context, Job) error { return nil })
		workCtx, stop := context.WithCancel(ctx)
		t.Cleanup(stop)
		done := make(chan error, 1)
		go func() { done <- c.Work(workCtx, q) }()
		waitFor("the first sample", func() bool { _, ok := metricValue(t, mx, "QueueDepth", `queue="`+q+`"`); return ok })
		stop()
		if err := <-done; err != nil {
			t.Logf("worker stopped: %v", err)
		}
		if v, _ := metricValue(t, mx, "QueueDepth", `queue="`+q+`"`); v != "0" {
			t.Errorf("depth of the empty queue %s = %s, want 0", q, v)
		}
	})
	t.Run("a worker samples on every interval", func(t *testing.T) {
		c, st := newRiverTestClient(t)
		q := testQueueName(t, st)
		mx := newQueueMetrics(t)
		c.SetMetrics(mx, 5*time.Millisecond)
		letGo := make(chan struct{})
		c.Register("river.held-open", func(ctx context.Context, _ Job) error {
			select {
			case <-letGo:
			case <-ctx.Done():
			}
			return nil
		})
		workCtx, stop := context.WithCancel(ctx)
		t.Cleanup(stop)
		done := make(chan error, 1)
		go func() { done <- c.Work(workCtx, q) }()
		depth := func() string { v, _ := metricValue(t, mx, "QueueDepth", `queue="`+q+`"`); return v }
		waitFor("an empty queue to be sampled", func() bool { return depth() == "0" })
		// One worker runs the first job and holds it; the other two wait.
		for i := 0; i < 3; i++ {
			if _, err := c.Enqueue(ctx, "river.held-open", q, struct{}{}); err != nil {
				t.Fatal(err)
			}
		}
		waitFor("the two waiting jobs to be sampled", func() bool { return depth() == "2" })
		close(letGo)
		stop()
		if err := <-done; err != nil {
			t.Logf("worker stopped: %v", err)
		}
	})
}

// TestSettleRescuedGivesEachRescuedJobItsLastAttempt: River's rescuer discards
// a stuck job that is already on its last attempt without calling its
// handler. SettleRescued finds exactly those jobs, in River's table, and
// queues each once more as a single attempt that its handler sees as the
// job's last, then marks the job settled in the same transaction. The sweep
// reads every discarded job in the database, so it has one of its own.
func TestSettleRescuedGivesEachRescuedJobItsLastAttempt(t *testing.T) {
	c, st := newIsolatedRiverTestClient(t)
	ctx := context.Background()
	logged := &syncBuffer{}
	c.log = slog.New(slog.NewTextHandler(logged, nil))
	// River's own message on a job it rescued; the rescue test above shows
	// the client's rescuer writes this one.
	const marker = "Stuck job rescued by JobRescuer"

	var mu sync.Mutex
	ran := map[string][]Job{}
	register := func(kind string) {
		c.Register(kind, func(_ context.Context, job Job) error {
			mu.Lock()
			defer mu.Unlock()
			ran[kind] = append(ran[kind], job)
			return nil
		})
	}
	// rescued enqueues a job and puts it where River's rescuer leaves one:
	// in the given state, on its last attempt, with the errors given as the
	// attempts' recorded errors, oldest first.
	rescued := func(kind, queue string, maxAttempts int, state string, errs ...string) uuid.UUID {
		t.Helper()
		register(kind)
		id, err := c.Enqueue(ctx, kind, queue, map[string]string{"pack": kind}, WithMaxAttempts(maxAttempts))
		if err != nil {
			t.Fatal(err)
		}
		if errs == nil {
			errs = []string{}
		}
		if _, err := st.Pool().Exec(ctx, `
			UPDATE river_job SET state = $2::river_job_state, attempt = max_attempts,
			       finalized_at = CASE WHEN $2 IN ('discarded', 'cancelled', 'completed') THEN now() END,
			       errors = ARRAY(SELECT jsonb_build_object('at', now(), 'attempt', 1, 'error', e, 'trace', '')
			                      FROM unnest($3::text[]) WITH ORDINALITY AS u(e, n) ORDER BY n)
			WHERE metadata->>'id' = $1`, id.String(), state, errs); err != nil {
			t.Fatal(err)
		}
		return id
	}
	annotate := func(id uuid.UUID, jsonb string) {
		t.Helper()
		if _, err := st.Pool().Exec(ctx, `UPDATE river_job SET metadata = metadata || $2::jsonb WHERE metadata->>'id' = $1`, id.String(), jsonb); err != nil {
			t.Fatal(err)
		}
	}
	settled := func(id uuid.UUID) bool {
		t.Helper()
		var n int
		if err := st.Pool().QueryRow(ctx, `SELECT count(*) FROM river_job WHERE metadata->>'id' = $1 AND metadata ? 'rescueSettled'`, id.String()).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n == 1
	}
	jobCount := func() int {
		t.Helper()
		var n int
		if err := st.Pool().QueryRow(ctx, `SELECT count(*) FROM river_job`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	type last struct {
		id, queue, kind, state string
		maxAttempts, offset    int
		final                  bool
		sameArgs               bool
	}
	lastOf := func(orig uuid.UUID) []last {
		t.Helper()
		rows, err := st.Pool().Query(ctx, `
			SELECT coalesce(l.metadata->>'id', ''), l.queue, l.kind, l.state::text, l.max_attempts,
			       coalesce((l.metadata->>'attemptOffset')::int, 0), coalesce((l.metadata->>'final')::bool, false),
			       l.args = o.args
			FROM river_job l JOIN river_job o ON o.metadata->>'id' = $1
			WHERE l.metadata->>'finalOf' = $1`, orig.String())
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []last
		for rows.Next() {
			var l last
			if err := rows.Scan(&l.id, &l.queue, &l.kind, &l.state, &l.maxAttempts, &l.offset, &l.final, &l.sameArgs); err != nil {
				t.Fatal(err)
			}
			out = append(out, l)
		}
		return out
	}

	if n, err := c.SettleRescued(ctx); err != nil || n != 0 {
		t.Fatalf("SettleRescued with nothing rescued = %d, %v, want 0", n, err)
	}

	// Rescued on the last attempt, whatever the earlier attempts did.
	plain := rescued("settle.plain", "settle-plain", 5, "discarded", marker)
	earlier := rescued("settle.earlier", "settle-earlier", 3, "discarded", "boom", marker)
	single := rescued("settle.single", "settle-single", 1, "discarded", marker)
	// Not to be settled: rescued and then retried, so the handler's own error
	// is the last; not discarded; no errors at all; already settled; and a
	// final attempt that was itself rescued.
	retried := rescued("settle.retried", "settle-retried", 4, "discarded", marker, "the handler failed")
	cancelled := rescued("settle.cancelled", "settle-cancelled", 4, "cancelled", marker)
	bare := rescued("settle.bare", "settle-bare", 4, "discarded")
	done := rescued("settle.done", "settle-done", 4, "discarded", marker)
	annotate(done, `{"rescueSettled": true}`)
	twice := rescued("settle.twice", "settle-twice", 4, "discarded", marker)
	annotate(twice, `{"final": true, "finalOf": "an-earlier-job"}`)
	before := jobCount()

	if n, err := c.SettleRescued(ctx); err != nil || n != 3 {
		t.Fatalf("SettleRescued = %d, %v, want 3: the plain, earlier-failed and single-attempt jobs", n, err)
	}
	if after := jobCount(); after != before+3 {
		t.Fatalf("river_job holds %d rows after the sweep, want %d (one new attempt for each of 3 jobs)", after, before+3)
	}
	wantOffset := map[uuid.UUID]int{plain: 4, earlier: 2, single: 0}
	wantKind := map[uuid.UUID]string{plain: "settle.plain", earlier: "settle.earlier", single: "settle.single"}
	finals := map[uuid.UUID]last{}
	for orig, offset := range wantOffset {
		ls := lastOf(orig)
		if len(ls) != 1 {
			t.Fatalf("%s: %d last attempts queued, want 1", wantKind[orig], len(ls))
		}
		l := ls[0]
		if l.queue != strings.Replace(wantKind[orig], "settle.", "settle-", 1) || l.kind != wantKind[orig] || l.maxAttempts != 1 || l.state != "available" || !l.final || l.offset != offset || !l.sameArgs || l.id == "" || l.id == orig.String() {
			t.Errorf("%s: last attempt %+v, want its queue and kind, one attempt, available, marked final, offset %d, the same args and an id of its own", wantKind[orig], l, offset)
		}
		finals[orig] = l
		if !settled(orig) {
			t.Errorf("%s was not marked settled", wantKind[orig])
		}
	}
	for name, id := range map[string]uuid.UUID{"retried": retried, "cancelled": cancelled, "bare": bare} {
		if settled(id) || len(lastOf(id)) != 0 {
			t.Errorf("the %s job was settled or given a last attempt", name)
		}
	}
	if len(lastOf(done)) != 0 {
		t.Errorf("the already settled job was queued again")
	}
	// A rescued final attempt ends there: marked, not queued, and logged.
	if !settled(twice) || len(lastOf(twice)) != 0 {
		t.Errorf("a rescued final attempt: settled=%v, last attempts %d, want settled and none queued", settled(twice), len(lastOf(twice)))
	}
	out := logged.String()
	if !strings.Contains(out, `last attempt" count=3`) {
		t.Errorf("log lacks the count of settled jobs:\n%s", out)
	}
	endsHere := false
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "it ends here") {
			endsHere = strings.Contains(line, "level=ERROR") && strings.Contains(line, "kind=settle.twice") && strings.Contains(line, "job=an-earlier-job")
		}
	}
	if !endsHere {
		t.Errorf("log lacks the error naming the rescued final attempt:\n%s", out)
	}

	// The handler sees each as the job's last attempt: the attempt number
	// River's retry budget ended on, the args, and the new attempt's own id.
	for _, q := range []string{"settle-plain", "settle-earlier", "settle-single"} {
		c.Drain(ctx, q)
	}
	for orig, kind := range wantKind {
		mu.Lock()
		jobs := ran[kind]
		mu.Unlock()
		wantAttempt := map[uuid.UUID]int{plain: 5, earlier: 3, single: 1}[orig]
		if len(jobs) != 1 || jobs[0].Attempt != wantAttempt || jobs[0].ID.String() != finals[orig].id || jobs[0].Kind != kind {
			t.Errorf("%s: handler ran %+v, want once as attempt %d under id %s", kind, jobs, wantAttempt, finals[orig].id)
			continue
		}
		var args map[string]string
		if err := json.Unmarshal(jobs[0].Args, &args); err != nil || args["pack"] != kind {
			t.Errorf("%s: handler args %s (%v), want the rescued job's", kind, jobs[0].Args, err)
		}
	}
	// Settled once is settled for good.
	if n, err := c.SettleRescued(ctx); err != nil || n != 0 {
		t.Fatalf("SettleRescued again = %d, %v, want 0", n, err)
	}

	// A row another transaction holds is skipped, not waited for: the sweep
	// settles the rest and the next one settles it.
	lockedID := rescued("settle.locked", "settle-locked", 2, "discarded", marker)
	freeID := rescued("settle.free", "settle-free", 2, "discarded", marker)
	holder, err := st.Pool().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := holder.Exec(ctx, `SELECT 1 FROM river_job WHERE metadata->>'id' = $1 FOR UPDATE`, lockedID.String()); err != nil {
		t.Fatal(err)
	}
	waitCtx, giveUp := context.WithTimeout(ctx, 20*time.Second)
	n, err := c.SettleRescued(waitCtx)
	giveUp()
	if err != nil || n != 1 || !settled(freeID) || settled(lockedID) {
		_ = holder.Rollback(ctx)
		t.Fatalf("SettleRescued with a row locked = %d, %v (free settled %v, locked settled %v), want it to skip the locked row and settle the other", n, err, settled(freeID), settled(lockedID))
	}
	if err := holder.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if n, err := c.SettleRescued(ctx); err != nil || n != 1 || !settled(lockedID) {
		t.Fatalf("SettleRescued once the row is free = %d, %v, settled=%v, want the locked job settled", n, err, settled(lockedID))
	}

	// A hundred a pass, oldest first.
	if _, err := st.Pool().Exec(ctx, `
		INSERT INTO river_job (state, kind, queue, args, max_attempts, attempt, finalized_at, errors)
		SELECT 'discarded', 'settle.many', 'settle-many', '{}', 2, 2, now(),
		       ARRAY[jsonb_build_object('at', now(), 'attempt', 2, 'error', $1::text, 'trace', '')]
		FROM generate_series(1, 101)`, marker); err != nil {
		t.Fatal(err)
	}
	if n, err := c.SettleRescued(ctx); err != nil || n != 100 {
		t.Fatalf("first sweep of 101 rescued jobs = %d, %v, want 100", n, err)
	}
	var leftID, newestID int64
	if err := st.Pool().QueryRow(ctx, `
		SELECT (SELECT id FROM river_job WHERE kind = 'settle.many' AND state = 'discarded' AND NOT metadata ? 'rescueSettled'),
		       (SELECT max(id) FROM river_job WHERE kind = 'settle.many' AND state = 'discarded')`).Scan(&leftID, &newestID); err != nil {
		t.Fatalf("the one job left: %v", err)
	}
	if leftID != newestID {
		t.Fatalf("the job left unsettled is %d, want the newest, %d", leftID, newestID)
	}
	if n, err := c.SettleRescued(ctx); err != nil || n != 1 {
		t.Fatalf("second sweep = %d, %v, want the last 1", n, err)
	}

	// All or nothing: a job whose last attempt cannot be queued fails the
	// sweep and leaves the others, and every row, as they were and unlocked.
	goodID := rescued("settle.good", "settle-good", 2, "discarded", marker)
	badID := rescued("settle.bad", "settle-bad", 2, "discarded", marker)
	if _, err := st.Pool().Exec(ctx, `UPDATE river_job SET queue = 'Not A Queue' WHERE metadata->>'id' = $1`, badID.String()); err != nil {
		t.Fatal(err)
	}
	if n, err := c.SettleRescued(ctx); err == nil || n != 0 || !strings.Contains(err.Error(), "queue a rescued job's last attempt") {
		t.Fatalf("SettleRescued with a job that cannot be queued = %d, %v, want an error and 0", n, err)
	}
	if settled(goodID) || len(lastOf(goodID)) != 0 {
		t.Fatalf("the sweep that failed left the job before the bad one settled or given an attempt")
	}
	probe, err := st.Pool().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := probe.Exec(ctx, `SELECT 1 FROM river_job WHERE metadata->>'id' = ANY($1) FOR UPDATE NOWAIT`, []string{goodID.String(), badID.String()}); err != nil {
		t.Errorf("rows are still locked after the sweep failed: %v", err)
	}
	_ = probe.Rollback(ctx)
	// (Bounded: were the rows still locked, these would wait for ever.)
	repair, cancelRepair := context.WithTimeout(ctx, 20*time.Second)
	defer cancelRepair()
	if _, err := st.Pool().Exec(repair, `DELETE FROM river_job WHERE metadata->>'id' = $1`, badID.String()); err != nil {
		t.Fatal(err)
	}
	if n, err := c.SettleRescued(repair); err != nil || n != 1 || !settled(goodID) {
		t.Fatalf("SettleRescued without the bad job = %d, %v, settled=%v, want the good one settled", n, err, settled(goodID))
	}

	// The periodic job that does all this is the one registered by name.
	if JobSettleRescued != "queue.settle_rescued" {
		t.Errorf("JobSettleRescued = %q: periodic jobs are stored under it", JobSettleRescued)
	}
	viaJobID := rescued("settle.via-job", "settle-via", 2, "discarded", marker)
	c.RegisterRescueSettling()
	if _, err := c.Enqueue(ctx, JobSettleRescued, "settle-via", struct{}{}); err != nil {
		t.Fatal(err)
	}
	c.Drain(ctx, "settle-via")
	mu.Lock()
	jobs := ran["settle.via-job"]
	mu.Unlock()
	if !settled(viaJobID) || len(lastOf(viaJobID)) != 1 || len(jobs) != 1 || jobs[0].Attempt != 2 {
		t.Fatalf("settling job: settled=%v, last attempts %d, handler ran %+v, want the rescued job settled and run once as attempt 2", settled(viaJobID), len(lastOf(viaJobID)), jobs)
	}
}
