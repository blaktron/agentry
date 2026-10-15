package queue

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivertype"

	"github.com/blaktron/agentry/internal/metrics"
	"github.com/blaktron/agentry/internal/store"
)

// DriverRiver is the driver name Open accepts (config queue.driver).
const DriverRiver = "river"

// Worker is a Client that also runs jobs: what the worker role and the
// tests hold. RiverClient implements it.
type Worker interface {
	Client
	SetMetrics(m *metrics.Metrics, sampleEvery time.Duration)
	Drain(ctx context.Context, queues ...string)
}

// Open returns the driver named by the configuration: River, the only
// one. The former "pg" driver name is refused with a pointer to river.
// maxWorkers is how many jobs
// one process runs at once per queue.
func Open(driver string, maxWorkers int, st *store.Store, log *slog.Logger) (Worker, error) {
	switch driver {
	case "", DriverRiver:
		c := NewRiverClient(st, log)
		if maxWorkers > 0 {
			c.maxWorkers = maxWorkers
		}
		return c, nil
	case "pg":
		return nil, fmt.Errorf("queue: the pg driver was removed; use river, the default")
	}
	return nil, fmt.Errorf("queue: unknown driver %q (river)", driver)
}

// RiverClient is the River-backed Client. River owns the job table
// (river_job), fetching, retries, the rescue of jobs a dead worker held and
// the per-queue concurrency; this type keeps the agentry contract on top of
// it: kind-string handlers, at-least-once delivery, the metrics and the
// backlog gauges the queue-age alarm reads.
type RiverClient struct {
	st  *store.Store
	log *slog.Logger

	mu       sync.Mutex
	handlers map[string]Handler
	workers  *river.Workers
	// inserter is the insert-only client every role uses to enqueue; it is
	// built on first use so an API replica never starts a worker.
	inserter    *river.Client[pgx.Tx]
	inserterErr error
	inserterMu  sync.Once

	maxWorkers   int
	pollInterval time.Duration
	reclaimAfter time.Duration
	jobTimeout   time.Duration
	stopGrace    time.Duration
	testOnly     bool

	mx          *metrics.Metrics
	sampleEvery time.Duration
}

// riverJobTimeout is how long one attempt of a job may run before River
// cancels its context and retries it. It exists for the rescue:
// River's rescuer skips a job with no timeout (JobTimeout -1) however long its
// worker has been gone, so a job whose worker died mid-run (an evicted pod, a
// lost node) stayed running, and a scan stayed in scanning, for good. River
// rescues a job only past both its timeout and RescueStuckJobsAfter, and needs
// the timeout under the rescue cutoff (defaultReclaimAfter, 30 minutes). Jobs
// in practice run for seconds.
const riverJobTimeout = 25 * time.Minute

// NewRiverClient builds the River queue client. Register handlers, then
// Work (worker role) or only Enqueue (API role).
func NewRiverClient(st *store.Store, log *slog.Logger) *RiverClient {
	if log == nil {
		log = slog.Default()
	}
	return &RiverClient{
		st: st, log: log,
		handlers:     map[string]Handler{},
		workers:      river.NewWorkers(),
		maxWorkers:   1,
		pollInterval: time.Second,
		reclaimAfter: defaultReclaimAfter,
		jobTimeout:   riverJobTimeout,
		stopGrace:    30 * time.Second,
		sampleEvery:  defaultSampleEvery,
	}
}

// SetMetrics wires the instrument set and the backlog sample interval.
func (c *RiverClient) SetMetrics(m *metrics.Metrics, sampleEvery time.Duration) {
	c.mx = m
	if sampleEvery > 0 {
		c.sampleEvery = sampleEvery
	}
}

// SetTestOnly turns off River's production-only staggering (jittered
// maintenance start-up) so a test's Drain starts and stops promptly.
func (c *RiverClient) SetTestOnly(on bool) { c.testOnly = on }

// envelope carries one agentry job through River. River keys workers by the
// kind a JobArgs value reports, and agentry's kinds are strings chosen at
// Register time (extensions add their own), so one Go type serves
// every kind: the kind is set per registration and per insert, and the args
// column holds the handler's own JSON untouched.
type envelope struct {
	kind string
	raw  json.RawMessage
}

func (e envelope) Kind() string { return e.kind }

func (e envelope) MarshalJSON() ([]byte, error) {
	if len(e.raw) == 0 {
		return []byte("null"), nil
	}
	return e.raw, nil
}

func (e *envelope) UnmarshalJSON(b []byte) error {
	e.raw = append(json.RawMessage(nil), b...)
	return nil
}

// jobMeta is what Enqueue records in river_job.metadata: the agentry job id
// handed back to the caller and to the handler as Job.ID.
type jobMeta struct {
	ID string `json:"id"`
}

// Enqueue durably records a job.
func (c *RiverClient) Enqueue(ctx context.Context, kind, queueName string, args any, opts ...EnqueueOption) (uuid.UUID, error) {
	cfg := enqueueConfig{maxAttempts: 5}
	for _, o := range opts {
		o(&cfg)
	}
	raw, err := json.Marshal(args)
	if err != nil {
		return uuid.Nil, fmt.Errorf("queue: marshal args: %w", err)
	}
	if queueName == "" {
		queueName = "core"
	}
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.Nil, err
	}
	meta, _ := json.Marshal(jobMeta{ID: id.String()})
	cl, err := c.insertClient()
	if err != nil {
		return uuid.Nil, err
	}
	iopts := &river.InsertOpts{Queue: queueName, MaxAttempts: cfg.maxAttempts, Metadata: meta}
	if cfg.runAt != nil {
		iopts.ScheduledAt = *cfg.runAt
	}
	if _, err := cl.Insert(ctx, envelope{kind: kind, raw: raw}, iopts); err != nil {
		return uuid.Nil, fmt.Errorf("queue: enqueue: %w", err)
	}
	return id, nil
}

func (c *RiverClient) insertClient() (*river.Client[pgx.Tx], error) {
	c.inserterMu.Do(func() {
		c.inserter, c.inserterErr = river.NewClient(riverpgxv5.New(c.st.Pool()), &river.Config{Logger: c.log})
		if c.inserterErr != nil {
			c.inserterErr = fmt.Errorf("queue: river client: %w", c.inserterErr)
		}
	})
	return c.inserter, c.inserterErr
}

// Register wires a handler for a job kind (before Work). Registering a kind
// twice replaces the handler.
func (c *RiverClient) Register(kind string, h Handler) {
	c.mu.Lock()
	_, known := c.handlers[kind]
	c.handlers[kind] = h
	c.mu.Unlock()
	if !known {
		// AddWorkerArgs takes the kind from the value rather than from the
		// type's zero value, which is what lets one type stand in for every
		// registered kind. River documents it as internal; it is the only
		// exported door to Workers.add and has been stable across releases.
		river.AddWorkerArgs(c.workers, envelope{kind: kind}, &riverWorker{c: c})
	}
}

// CountWaiting counts the kind's jobs in river_job not yet started. It
// reads only river_job.
func (c *RiverClient) CountWaiting(ctx context.Context, kind string) (int64, error) {
	var n int64
	err := c.st.Pool().QueryRow(ctx, `
		SELECT count(*) FROM river_job
		WHERE kind = $1 AND state IN ('available', 'scheduled', 'retryable', 'pending')`, kind).Scan(&n)
	return n, err
}

func (c *RiverClient) handler(kind string) Handler {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.handlers[kind]
}

// riverWorker adapts every registered kind to River's Worker: a backoff of
// 2^attempt seconds, riverJobTimeout as every job's limit, and the outcome
// metrics.
type riverWorker struct {
	river.WorkerDefaults[envelope]
	c *RiverClient
}

func (w *riverWorker) NextRetry(job *river.Job[envelope]) time.Time {
	return time.Now().Add(time.Duration(1<<uint(job.Attempt)) * time.Second)
}

func (w *riverWorker) Work(ctx context.Context, job *river.Job[envelope]) error {
	c := w.c
	h := c.handler(job.Kind)
	if h == nil {
		// River only dispatches registered kinds, so this is unreachable
		// short of a handler map edited after Work; the outcome is the same as
		// for an unknown kind.
		c.mx.RecordQueueJob(ctx, job.Queue, job.Kind, "no_handler", 0)
		c.log.Error("queue: no handler", "kind", job.Kind, "job", job.ID)
		return river.JobCancel(errors.New("no handler registered"))
	}
	var meta jobMeta
	_ = json.Unmarshal(job.Metadata, &meta)
	id, _ := uuid.Parse(meta.ID)
	started := time.Now()
	err := c.runHandler(ctx, h, Job{ID: id, Kind: job.Kind, Queue: job.Queue, Args: job.Args.raw, Attempt: job.Attempt})
	elapsed := time.Since(started)
	switch {
	case err == nil:
		c.mx.RecordQueueJob(ctx, job.Queue, job.Kind, "ok", elapsed)
	case job.Attempt >= job.MaxAttempts:
		c.mx.RecordQueueJob(ctx, job.Queue, job.Kind, "failed", elapsed)
		c.log.Error("queue: job failed permanently", "kind", job.Kind, "job", id,
			"attempt", job.Attempt, "err", err)
	default:
		c.mx.RecordQueueJob(ctx, job.Queue, job.Kind, "retry", elapsed)
	}
	return err
}

// runHandler isolates a handler panic so one bad job never kills the worker;
// the stack is logged here and dropped from the error River records.
func (c *RiverClient) runHandler(ctx context.Context, h Handler, job Job) (err error) {
	defer func() {
		if r := recover(); r != nil {
			c.log.Error("queue: handler panic", "kind", job.Kind, "job", job.ID,
				"panic", r, "stack", string(debug.Stack()))
			err = fmt.Errorf("queue: handler panic: %v", r)
		}
	}()
	return h(ctx, job)
}

// riverErrors is River's ErrorHandler: a job whose kind has no worker in
// this process is a wiring bug, not a job failure, so it is cancelled at once
// and counted as no_handler; every other error is
// River's retry path and is logged by the worker.
type riverErrors struct{ c *RiverClient }

func (e *riverErrors) HandleError(ctx context.Context, job *rivertype.JobRow, err error) *river.ErrorHandlerResult {
	var unknown *rivertype.UnknownJobKindError
	if errors.As(err, &unknown) {
		e.c.mx.RecordQueueJob(ctx, job.Queue, job.Kind, "no_handler", 0)
		e.c.log.Error("queue: no handler", "kind", job.Kind, "job", job.ID)
		return &river.ErrorHandlerResult{SetCancelled: true}
	}
	return nil
}

func (e *riverErrors) HandlePanic(ctx context.Context, job *rivertype.JobRow, panicVal any, trace string) *river.ErrorHandlerResult {
	e.c.log.Error("queue: handler panic", "kind", job.Kind, "job", job.ID, "panic", panicVal, "stack", trace)
	return nil
}

// workClient builds a River client that works the given queues.
func (c *RiverClient) workClient(queues []string, poll time.Duration) (*river.Client[pgx.Tx], error) {
	cfg := &river.Config{
		Logger:               c.log,
		Workers:              c.workers,
		Queues:               map[string]river.QueueConfig{},
		JobTimeout:           c.jobTimeout,
		RescueStuckJobsAfter: c.reclaimAfter,
		ErrorHandler:         &riverErrors{c: c},
		FetchPollInterval:    poll,
		FetchCooldown:        min(poll, river.FetchCooldownDefault),
		TestOnly:             c.testOnly,
	}
	for _, q := range queues {
		cfg.Queues[q] = river.QueueConfig{MaxWorkers: c.maxWorkers}
	}
	cl, err := river.NewClient(riverpgxv5.New(c.st.Pool()), cfg)
	if err != nil {
		return nil, fmt.Errorf("queue: river worker client: %w", err)
	}
	return cl, nil
}

// Work runs jobs from the queues until ctx is cancelled, then stops
// gracefully: no new fetches, running jobs finish within stopGrace, after
// which they are cancelled.
func (c *RiverClient) Work(ctx context.Context, queues ...string) error {
	if len(queues) == 0 {
		queues = []string{"core"}
	}
	cl, err := c.workClient(queues, c.pollInterval)
	if err != nil {
		return err
	}
	// River cancels every running job when the Start context ends; the
	// graceful stop below wants them to finish, so the client gets a context
	// that outlives ctx.
	runCtx, cancelRun := context.WithCancel(context.WithoutCancel(ctx))
	defer cancelRun()
	if err := cl.Start(runCtx); err != nil {
		return fmt.Errorf("queue: river start: %w", err)
	}
	sample := time.NewTicker(c.sampleEvery)
	defer sample.Stop()
	c.sampleBacklog(ctx, queues)
	for {
		select {
		case <-ctx.Done():
			stopCtx, cancel := context.WithTimeout(runCtx, c.stopGrace)
			defer cancel()
			if err := cl.Stop(stopCtx); err != nil {
				c.log.Warn("queue: river stop", "err", err)
				_ = cl.StopAndCancel(runCtx)
			}
			return ctx.Err()
		case <-sample.C:
			c.sampleBacklog(ctx, queues)
		}
	}
}

// Drain works the queues until nothing in them is ready or running, then
// stops (tests and one-shot drains). A retry scheduled for later is
// deliberately waiting and does not hold the drain.
func (c *RiverClient) Drain(ctx context.Context, queues ...string) {
	if len(queues) == 0 {
		queues = []string{"core"}
	}
	cl, err := c.workClient(queues, 50*time.Millisecond)
	if err != nil {
		c.log.Error("queue: drain", "err", err)
		return
	}
	runCtx, cancelRun := context.WithCancel(context.WithoutCancel(ctx))
	defer cancelRun()
	if err := cl.Start(runCtx); err != nil {
		c.log.Error("queue: drain start", "err", err)
		return
	}
	defer func() {
		stopCtx, cancel := context.WithTimeout(runCtx, c.stopGrace)
		defer cancel()
		if err := cl.Stop(stopCtx); err != nil {
			_ = cl.StopAndCancel(runCtx)
		}
	}()
	deadline := time.Now().Add(60 * time.Second)
	for ctx.Err() == nil && time.Now().Before(deadline) {
		n, err := c.pending(ctx, queues)
		if err != nil {
			c.log.Error("queue: drain count", "err", err)
			return
		}
		if n == 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// pending counts jobs that are running or ready to run now in the queues.
func (c *RiverClient) pending(ctx context.Context, queues []string) (int64, error) {
	var n int64
	err := c.st.Pool().QueryRow(ctx, `
		SELECT count(*) FROM river_job
		WHERE queue = ANY($1)
		  AND (state = 'running'
		       OR (state IN ('available', 'scheduled', 'retryable') AND scheduled_at <= now()))`, queues).Scan(&n)
	return n, err
}

// sampleBacklog publishes QueueDepth and QueueAgeSeconds per queue: jobs
// waiting to be picked up now, and the age of the oldest of them.
func (c *RiverClient) sampleBacklog(ctx context.Context, queues []string) {
	if c.mx == nil {
		return
	}
	for _, q := range queues {
		var depth int64
		var oldest float64
		err := c.st.Pool().QueryRow(ctx, `
			SELECT count(*), COALESCE(EXTRACT(EPOCH FROM (now() - min(scheduled_at))), 0)::float8
			FROM river_job
			WHERE queue = $1 AND state IN ('available', 'scheduled', 'retryable') AND scheduled_at <= now()`, q).Scan(&depth, &oldest)
		if err != nil {
			if ctx.Err() == nil {
				c.log.Error("queue: backlog sample", "queue", q, "err", err)
			}
			continue
		}
		c.mx.RecordQueueStats(ctx, q, depth, time.Duration(oldest*float64(time.Second)))
	}
}
