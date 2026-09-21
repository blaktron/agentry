package saml

import (
	"sync"
	"time"
)

// RequestTracker remembers the AuthnRequest ids this SP has issued, so an
// assertion that names one (`InResponseTo`) can be matched to a login THIS
// server actually started (§12.4 SP-initiated).
//
// It is the mirror image of ReplayCache: the replay cache remembers what has
// been consumed, the tracker remembers what is outstanding. Both are TTL sets
// with the same deployment story — in the database when there is one
// (StoreRequestTracker, agentry#414), so any API replica can complete a
// login the user started on another; in memory for a server without one,
// where a lost entry costs the user one retry of a login that never
// completed.
type RequestTracker interface {
	// Track records id as an outstanding AuthnRequest until exp.
	Track(id string, exp time.Time)
	// Consume reports whether id is outstanding and, if so, removes it.
	// Single use: an assertion answers exactly one request.
	Consume(id string) bool
}

// MemoryRequestTracker is an in-process TTL set of outstanding request ids.
type MemoryRequestTracker struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

// NewMemoryRequestTracker builds an empty tracker.
func NewMemoryRequestTracker() *MemoryRequestTracker {
	return &MemoryRequestTracker{seen: map[string]time.Time{}}
}

// Track implements RequestTracker.
func (t *MemoryRequestTracker) Track(id string, exp time.Time) {
	if id == "" {
		return
	}
	now := time.Now()
	if exp.IsZero() {
		exp = now.Add(defaultRequestTTL)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.gcLocked(now)
	t.seen[id] = exp
}

// Consume implements RequestTracker.
func (t *MemoryRequestTracker) Consume(id string) bool {
	if id == "" {
		return false
	}
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	t.gcLocked(now)
	exp, ok := t.seen[id]
	if !ok || !exp.After(now) {
		return false
	}
	delete(t.seen, id)
	return true
}

// defaultRequestTTL bounds how long a started login may take to come back.
// Generous enough for a password + MFA prompt at the IdP, short enough that
// a captured SAMLRequest is not useful an hour later.
const defaultRequestTTL = 15 * time.Minute

func (t *MemoryRequestTracker) gcLocked(now time.Time) {
	for id, until := range t.seen {
		if !until.After(now) {
			delete(t.seen, id)
		}
	}
}
