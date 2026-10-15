package api

import (
	"context"
	"fmt"

	"github.com/blaktron/agentry/internal/queue"
)

// keepOneWaiting enqueues the next run of a self-rescheduling job (the
// red team, audit retention, the staff mirror) unless one is already
// waiting in the queue driver's own table. It is both the seed at start-up
// and each run's reschedule, so a restart never adds a run, and a chain
// that two seeds doubled folds back to one when its runs come round: the
// run that finds its twin waiting enqueues nothing.
//
// The count is the driver's (queue.Client.CountWaiting). Counting another
// driver's jobs table would, on a database where that driver had left a
// run waiting, never seed River, and on one where it had not, seed another
// chain on every start.
//
// The count and the enqueue are not one statement: two processes starting
// together can each add a run, and the next turn folds them.
func keepOneWaiting(ctx context.Context, q queue.Client, kind string, args any, opts ...queue.EnqueueOption) (bool, error) {
	n, err := q.CountWaiting(ctx, kind)
	if err != nil {
		return false, fmt.Errorf("count waiting %s: %w", kind, err)
	}
	if n > 0 {
		return false, nil
	}
	if _, err := q.Enqueue(ctx, kind, "core", args, opts...); err != nil {
		return false, err
	}
	return true, nil
}
