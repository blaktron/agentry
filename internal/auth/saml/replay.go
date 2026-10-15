package saml

import (
	"context"
	"sync"
	"time"
)

// ReplayCache records assertion IDs that have been consumed so a captured
// assertion cannot be replayed within its validity window. The
// SP records each accepted assertion's ID until at least its NotOnOrAfter
// (replayFloor is the least time either implementation keeps one); a second
// presentation of the same ID is rejected.
//
// The interface is the commitment. A server with a database keeps the set
// there (StoreReplayCache), shared by every API replica; the
// in-memory implementation below serves a server without one. A single
// replica losing its cache (restart) is bounded by the short assertion
// lifetime, so the exposure window is minutes, not the session lifetime.
type ReplayCache interface {
	// SeenBefore atomically reports whether id was already recorded and, if
	// not, records it until exp. It returns true when id is a replay. The
	// context is the request's, for an implementation that asks a store.
	SeenBefore(ctx context.Context, id string, exp time.Time) bool
}

// replayFloor is the least time a consumed assertion's id is kept, in both
// implementations. The validator goes on accepting an assertion for its
// clock skew past the expiry the assertion carries — and crewjam's
// MaxIssueDelay bounds how long after issue that can be — so a record that
// lapsed at that expiry would leave the tail of the window unprotected.
// Ten minutes outlives both by a wide margin; the store-backed cache
// applies it on the database's clock.
const replayFloor = 10 * time.Minute

// MemoryReplayCache is an in-process TTL set of assertion IDs.
type MemoryReplayCache struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

// NewMemoryReplayCache builds an empty in-memory replay cache.
func NewMemoryReplayCache() *MemoryReplayCache {
	return &MemoryReplayCache{seen: map[string]time.Time{}}
}

// SeenBefore implements ReplayCache.
func (c *MemoryReplayCache) SeenBefore(_ context.Context, id string, exp time.Time) bool {
	if id == "" {
		// An assertion with no ID cannot be replay-protected; treat as replay
		// to fail closed rather than silently accept.
		return true
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gcLocked(now)
	if until, ok := c.seen[id]; ok && until.After(now) {
		return true
	}
	// The record outlives the window the validator still accepts this
	// assertion in, which runs past the expiry the assertion carries.
	if floor := now.Add(replayFloor); exp.Before(floor) {
		exp = floor
	}
	c.seen[id] = exp
	return false
}

// gcLocked drops expired entries; cheap because the set stays small (only
// live assertions, which expire in minutes).
func (c *MemoryReplayCache) gcLocked(now time.Time) {
	for id, until := range c.seen {
		if !until.After(now) {
			delete(c.seen, id)
		}
	}
}
