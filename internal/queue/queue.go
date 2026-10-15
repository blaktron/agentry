// Package queue is the async job abstraction. The interface is the
// commitment; the backend is River (river.go, Postgres-backed), behind
// Client without changing enqueue sites or handlers.
package queue

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
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
	// adds one.
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

// Orphan recovery: a worker that dies mid-job leaves the job running with
// no owner. defaultReclaimAfter is how long a job may stay running before
// River rescues it for another worker (river.go keeps its job timeout under
// it).
const (
	defaultReclaimAfter = 30 * time.Minute
	// defaultSampleEvery refreshes the backlog gauges. Well under the
	// 15-minute queue-age alarm threshold, so the alarm never fires — or
	// clears — on a stale sample.
	defaultSampleEvery = 15 * time.Second
)
