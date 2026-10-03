// Package queue is the async job abstraction (D-05). The interface is the
// commitment; the default backend is River (river.go, Postgres-backed; the
// config's default queue.driver, DEV-095), and the Postgres SELECT … FOR
// UPDATE SKIP LOCKED implementation in this file remains selectable as the
// "pg" driver. Either sits behind Client without changing enqueue sites or
// handlers — see DEVIATIONS DEV-005.
package queue

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/blaktron/agentry/internal/metrics"
	"github.com/blaktron/agentry/internal/store"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// Job is a claimed unit of work handed to a Handler.
type Job struct {
	ID      uuid.UUID
	Kind    string
	Queue   string
	Args    json.RawMessage
	Attempt int
}

// Handler processes one job kind. Returning an error retries (with backoff)
// up to the job's max attempts, then the job is marked failed. Handlers MUST
// be idempotent: at-least-once delivery is the contract.
type Handler func(ctx context.Context, job Job) error

// Client enqueues and (as a worker) runs jobs.
type Client interface {
	Enqueue(ctx context.Context, kind, queueName string, args any, opts ...EnqueueOption) (uuid.UUID, error)
	Register(kind string, h Handler)
	Work(ctx context.Context, queues ...string) error
	// CountWaiting counts the jobs of a kind that have not started: queued,
	// scheduled for later, or waiting out a retry, in this driver's own
	// table. A self-rescheduling job keeps one successor waiting and asks
	// this before it enqueues another, so a restart or a stacked chain never
	// adds one (agentry#853).
	CountWaiting(ctx context.Context, kind string) (int64, error)
}

// EnqueueOption customizes enqueue.
type EnqueueOption func(*enqueueConfig)

type enqueueConfig struct {
	runAt       *time.Time
	maxAttempts int
}

// WithDelay schedules the job to run after d.
func WithDelay(d time.Duration) EnqueueOption {
	return func(c *enqueueConfig) { t := time.Now().Add(d); c.runAt = &t }
}

// WithMaxAttempts overrides the retry budget.
func WithMaxAttempts(n int) EnqueueOption {
	return func(c *enqueueConfig) { c.maxAttempts = n }
}

// Orphan recovery: a worker that dies mid-job leaves the row `running` with
// no owner. reclaimAfter is how long a claimed job may stay locked before
// another worker may take it; reclaimEvery is how often we look. Both run on
// the ticker loop, not only at Work() start — a long-lived worker used to
// never notice a peer crashing after it booted.
const (
	defaultReclaimAfter = 30 * time.Minute
	defaultReclaimEvery = 5 * time.Minute
	// defaultSampleEvery refreshes the backlog gauges. Well under the §16.3
	// 15-minute queue-age alarm threshold, so the alarm never fires — or
	// clears — on a stale sample.
	defaultSampleEvery = 15 * time.Second
)

// PGClient is the Postgres-backed Client.
type PGClient struct {
	st       *store.Store
	log      *slog.Logger
	handlers map[string]Handler
	// pollInterval bounds latency when no NOTIFY wakeup fires.
	pollInterval time.Duration
	// reclaimAfter / reclaimEvery drive orphaned-job recovery.
	reclaimAfter time.Duration
	reclaimEvery time.Duration
	// mx records §16.2 job outcomes and the queue depth/age gauges the §16.3
	// page alarm reads. nil is a working no-op.
	mx *metrics.Metrics
	// sampleEvery is how often the backlog gauges are refreshed.
	sampleEvery time.Duration
}

// SetMetrics wires the §16.2 instrument set and the backlog sample interval.
func (c *PGClient) SetMetrics(m *metrics.Metrics, sampleEvery time.Duration) {
	c.mx = m
	if sampleEvery > 0 {
		c.sampleEvery = sampleEvery
	}
}

// NewPGClient builds the Postgres queue client.
func NewPGClient(st *store.Store, log *slog.Logger) *PGClient {
	if log == nil {
		log = slog.Default()
	}
	return &PGClient{
		st: st, log: log, handlers: map[string]Handler{},
		pollInterval: time.Second,
		reclaimAfter: defaultReclaimAfter,
		reclaimEvery: defaultReclaimEvery,
		sampleEvery:  defaultSampleEvery,
	}
}

// Enqueue durably records a job.
func (c *PGClient) Enqueue(ctx context.Context, kind, queueName string, args any, opts ...EnqueueOption) (uuid.UUID, error) {
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
	params := storegen.EnqueueJobParams{
		ID: id, Kind: kind, Queue: queueName, Args: raw,
		MaxAttempts: int32(cfg.maxAttempts),
	}
	if cfg.runAt != nil {
		params.RunAt = cfg.runAt
	}
	if _, err := c.st.Queries().EnqueueJob(ctx, params); err != nil {
		return uuid.Nil, fmt.Errorf("queue: enqueue: %w", err)
	}
	return id, nil
}

// Register wires a handler for a job kind (before Work).
func (c *PGClient) Register(kind string, h Handler) { c.handlers[kind] = h }

// CountWaiting counts the kind's jobs in the jobs table not yet started.
func (c *PGClient) CountWaiting(ctx context.Context, kind string) (int64, error) {
	return c.st.Queries().CountWaitingJobsOfKind(ctx, kind)
}

// Work runs the claim/execute loop until ctx is cancelled.
func (c *PGClient) Work(ctx context.Context, queues ...string) error {
	if len(queues) == 0 {
		queues = []string{"core"}
	}
	// Recover jobs orphaned by a crashed worker, at boot and then on a timer:
	// a worker that has been up for days must still notice a peer dying.
	c.ReclaimOrphanedJobs(ctx)
	ticker := time.NewTicker(c.pollInterval)
	defer ticker.Stop()
	reclaim := time.NewTicker(c.reclaimEvery)
	defer reclaim.Stop()
	// The backlog gauges are sampled on their OWN ticker, not inside the claim
	// loop: that loop drains each queue every tick, so a reading taken there
	// would see zero on an idle worker and miss the very backlog the §16.3
	// alarm exists to catch.
	sample := time.NewTicker(c.sampleEvery)
	defer sample.Stop()
	c.sampleBacklog(ctx, queues)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-reclaim.C:
			c.ReclaimOrphanedJobs(ctx)
		case <-sample.C:
			c.sampleBacklog(ctx, queues)
		case <-ticker.C:
			for _, q := range queues {
				for c.claimOne(ctx, q) { //nolint:revive // drain the queue each tick
				}
			}
		}
	}
}

// sampleBacklog publishes QueueDepth and QueueAgeSeconds per queue.
func (c *PGClient) sampleBacklog(ctx context.Context, queues []string) {
	if c.mx == nil {
		return
	}
	for _, q := range queues {
		row, err := c.st.Queries().QueueBacklog(ctx, q)
		if err != nil {
			if ctx.Err() == nil {
				c.log.Error("queue: backlog sample", "queue", q, "err", err)
			}
			continue
		}
		c.mx.RecordQueueStats(ctx, q, row.Depth,
			time.Duration(row.OldestSeconds*float64(time.Second)))
	}
}

// ReclaimOrphanedJobs returns jobs locked by a dead worker to `available`.
// Exported so the worker role (and tests) can run it out of band; the Work
// loop calls it at boot and every reclaimEvery.
func (c *PGClient) ReclaimOrphanedJobs(ctx context.Context) {
	cutoff := time.Now().Add(-c.reclaimAfter)
	n, err := c.st.Queries().ResetStuckJobs(ctx, &cutoff)
	if err != nil {
		c.log.Warn("queue: reset stuck jobs", "err", err)
		return
	}
	if n > 0 {
		// Not routine: every row here is a job a worker died holding.
		c.log.Warn("queue: reclaimed orphaned jobs", "count", n, "locked_before", cutoff)
	}
}

// RunOnce claims and runs at most one job from each queue (tests, drains).
func (c *PGClient) RunOnce(ctx context.Context, queues ...string) bool {
	if len(queues) == 0 {
		queues = []string{"core"}
	}
	any := false
	for _, q := range queues {
		if c.claimOne(ctx, q) {
			any = true
		}
	}
	return any
}

// Drain runs jobs until every queue is empty (tests).
func (c *PGClient) Drain(ctx context.Context, queues ...string) {
	for c.RunOnce(ctx, queues...) {
	}
}

func (c *PGClient) claimOne(ctx context.Context, queueName string) bool {
	job, err := c.st.Queries().ClaimJob(ctx, queueName)
	if err != nil {
		// ErrNoRows is the empty queue — the normal case, every tick. Anything
		// else is a database problem, and a worker that goes quietly idle on a
		// broken pool is indistinguishable from one with nothing to do.
		if !errors.Is(err, pgx.ErrNoRows) && ctx.Err() == nil {
			c.log.Error("queue: claim job", "queue", queueName, "err", err)
		}
		return false
	}
	h, ok := c.handlers[job.Kind]
	if !ok {
		// Distinct from a job failure: nothing ran, and it is a wiring bug
		// rather than anything the job did.
		c.mx.RecordQueueJob(ctx, job.Queue, job.Kind, "no_handler", 0)
		c.log.Error("queue: no handler", "kind", job.Kind, "job", job.ID)
		if err := c.st.Queries().FailJob(ctx, storegen.FailJobParams{
			ID: job.ID, LastError: strptr("no handler registered"),
		}); err != nil {
			c.log.Error("queue: fail job", "job", job.ID, "err", err)
		}
		return true
	}
	started := time.Now()
	err = c.runHandler(ctx, h, Job{ID: job.ID, Kind: job.Kind, Queue: job.Queue, Args: job.Args, Attempt: int(job.Attempt)})
	elapsed := time.Since(started)
	if err == nil {
		c.mx.RecordQueueJob(ctx, job.Queue, job.Kind, "ok", elapsed)
		if err := c.st.Queries().CompleteJob(ctx, job.ID); err != nil {
			c.log.Error("queue: complete", "err", err)
		}
		return true
	}
	if int(job.Attempt) >= int(job.MaxAttempts) {
		c.mx.RecordQueueJob(ctx, job.Queue, job.Kind, "failed", elapsed)
		c.log.Error("queue: job failed permanently", "kind", job.Kind, "job", job.ID,
			"attempt", job.Attempt, "err", err)
		if ferr := c.st.Queries().FailJob(ctx, storegen.FailJobParams{
			ID: job.ID, LastError: strptr(err.Error()),
		}); ferr != nil {
			c.log.Error("queue: fail job", "job", job.ID, "err", ferr)
		}
		return true
	}
	c.mx.RecordQueueJob(ctx, job.Queue, job.Kind, "retry", elapsed)
	backoff := time.Duration(1<<uint(job.Attempt)) * time.Second
	if err := c.st.Queries().RetryJob(ctx, storegen.RetryJobParams{
		ID: job.ID, LastError: strptr(err.Error()), RunAt: time.Now().Add(backoff),
	}); err != nil {
		c.log.Error("queue: retry", "err", err)
	}
	return true
}

// runHandler isolates a handler panic so one bad job never kills the worker.
// The stack is logged here and dropped from the returned error: last_error
// is surfaced in operator tooling, and a full stack does not belong there.
func (c *PGClient) runHandler(ctx context.Context, h Handler, job Job) (err error) {
	defer func() {
		if r := recover(); r != nil {
			c.log.Error("queue: handler panic", "kind", job.Kind, "job", job.ID,
				"panic", r, "stack", string(debug.Stack()))
			err = fmt.Errorf("queue: handler panic: %v", r)
		}
	}()
	return h(ctx, job)
}

func strptr(s string) *string { return &s }
