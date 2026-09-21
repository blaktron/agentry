package saml

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// The shared implementations (agentry#414, DEV-119): the replay cache and
// the request tracker in the registry's own database, so an assertion
// consumed by one API replica is a replay at every other, and a login
// started on one can be completed on another. A database that cannot be
// reached fails closed — an assertion is treated as a replay, a request
// as unknown — because the alternative is a session minted on a guess.
// Expired rows are swept by the writers every so often; the sets stay
// the size of what is live.

// sweepEvery is how many writes pass between one sweep of expired rows
// and the next.
const sweepEvery = 64

// storeCallTimeout bounds one round trip to the database from a path
// that has no context of its own to carry.
const storeCallTimeout = 5 * time.Second

// StoreReplayCache is the replay cache in the database.
type StoreReplayCache struct {
	q     *storegen.Queries
	log   *slog.Logger
	calls atomic.Uint64
}

// NewStoreReplayCache builds a replay cache over the registry's store.
func NewStoreReplayCache(q *storegen.Queries, log *slog.Logger) *StoreReplayCache {
	if log == nil {
		log = slog.Default()
	}
	return &StoreReplayCache{q: q, log: log}
}

// SeenBefore implements ReplayCache.
func (c *StoreReplayCache) SeenBefore(id string, exp time.Time) bool {
	if id == "" {
		return true // an assertion with no id cannot be replay-protected: fail closed
	}
	now := time.Now()
	if !exp.After(now) {
		exp = now.Add(10 * time.Minute) // the floor the in-memory cache keeps
	}
	ctx, cancel := context.WithTimeout(context.Background(), storeCallTimeout)
	defer cancel()
	n, err := c.q.ConsumeSAMLAssertion(ctx, storegen.ConsumeSAMLAssertionParams{ID: id, ExpiresAt: exp})
	if err != nil {
		c.log.Error("saml: replay cache", "err", err)
		return true
	}
	if c.calls.Add(1)%sweepEvery == 0 {
		if _, err := c.q.SweepSAMLAssertions(ctx); err != nil {
			c.log.Warn("saml: replay cache sweep", "err", err)
		}
	}
	return n == 0
}

// StoreRequestTracker is the request tracker in the database.
type StoreRequestTracker struct {
	q     *storegen.Queries
	log   *slog.Logger
	calls atomic.Uint64
}

// NewStoreRequestTracker builds a request tracker over the registry's
// store.
func NewStoreRequestTracker(q *storegen.Queries, log *slog.Logger) *StoreRequestTracker {
	if log == nil {
		log = slog.Default()
	}
	return &StoreRequestTracker{q: q, log: log}
}

// Track implements RequestTracker.
func (t *StoreRequestTracker) Track(id string, exp time.Time) {
	if id == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), storeCallTimeout)
	defer cancel()
	if err := t.q.TrackSAMLRequest(ctx, storegen.TrackSAMLRequestParams{ID: id, ExpiresAt: exp}); err != nil {
		t.log.Error("saml: request tracker", "err", err)
	}
	if t.calls.Add(1)%sweepEvery == 0 {
		if _, err := t.q.SweepSAMLRequests(ctx); err != nil {
			t.log.Warn("saml: request tracker sweep", "err", err)
		}
	}
}

// Consume implements RequestTracker.
func (t *StoreRequestTracker) Consume(id string) bool {
	if id == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), storeCallTimeout)
	defer cancel()
	n, err := t.q.ConsumeSAMLRequest(ctx, id)
	if err != nil {
		t.log.Error("saml: request tracker", "err", err)
		return false
	}
	return n == 1
}
