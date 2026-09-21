package saml

import (
	"sync"
	"time"
)

// ReplayCache records assertion IDs that have been consumed so a captured
// assertion cannot be replayed within its validity window (§12.4, T-12). The
// SP records each accepted assertion's ID keyed until its NotOnOrAfter; a
// second presentation of the same ID is rejected.
//
// The interface is the commitment. A server with a database keeps the set
// there (StoreReplayCache, agentry#414), shared by every API replica; the
// in-memory implementation below serves a server without one. A single
// replica losing its cache (restart) is bounded by the short assertion
// lifetime, so the exposure window is minutes, not the session lifetime.
type ReplayCache interface {
	// SeenBefore atomically reports whether id was already recorded and, if
	// not, records it until exp. It returns true when id is a replay.
	SeenBefore(id string, exp time.Time) bool
}

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
func (c *MemoryReplayCache) SeenBefore(id string, exp time.Time) bool {
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
	if !exp.After(now) {
		exp = now.Add(10 * time.Minute) // floor for assertions with no/old expiry
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
