package saml

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/blaktron/agentry/internal/logevent"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// The shared implementations (agentry#414, DEV-119): the replay cache and
// the request tracker in the registry's own database, so an assertion
// consumed by one API replica is a replay at every other, and a login
// started on one can be completed on another. A database that cannot be
// reached fails closed — an assertion is treated as a replay, a request
// as unknown — because the alternative is a session minted on a guess;
// each refusal is a catalogued signal, so an operator can tell that apart
// from a replay that was really presented. Expired rows are swept by the
// writers every so often; the sets stay the size of what is live.

// sweepEvery is how many writes pass between one sweep of expired rows
// and the next.
const sweepEvery = 64

// storeCallTimeout bounds one round trip to the database; the deletions
// that sweep expired rows share it with the consume they ride on. A login
// whose database has gone slow is refused after this, not held open.
const storeCallTimeout = 5 * time.Second

// maxIDLen is the longest id the tables take (their CHECK); an identity
// provider's ids are a few dozen characters, and a longer one is refused
// here rather than at the database.
const maxIDLen = 1024

// storeSet is what the two sets share: the queries, the log, and the write
// count that paces the sweep. What each does when the database cannot be
// reached is its own, because the two fail closed in opposite directions.
type storeSet struct {
	q     *storegen.Queries
	log   *slog.Logger
	calls atomic.Uint64
}

func newStoreSet(q *storegen.Queries, log *slog.Logger) *storeSet {
	if log == nil {
		log = slog.Default()
	}
	return &storeSet{q: q, log: log}
}

// sweepDue counts one write and reports whether it is the sweep's turn.
func (s *storeSet) sweepDue() bool { return s.calls.Add(1)%sweepEvery == 0 }

// StoreReplayCache is the replay cache in the database.
type StoreReplayCache struct{ *storeSet }

// NewStoreReplayCache builds a replay cache over the registry's store.
func NewStoreReplayCache(q *storegen.Queries, log *slog.Logger) *StoreReplayCache {
	return &StoreReplayCache{storeSet: newStoreSet(q, log)}
}

// SeenBefore implements ReplayCache.
func (c *StoreReplayCache) SeenBefore(reqCtx context.Context, id string, exp time.Time) bool {
	if id == "" || len(id) > maxIDLen {
		return true // an assertion with no id, or one no table takes, cannot be replay-protected: fail closed
	}
	ctx, cancel := context.WithTimeout(reqCtx, storeCallTimeout)
	defer cancel()
	// replayFloor is the query's floor as well as the in-memory cache's, so
	// both keep a consumed id for the same least time.
	n, err := c.q.ConsumeSAMLAssertion(ctx, storegen.ConsumeSAMLAssertionParams{
		ID: id, ExpiresAt: exp, FloorSeconds: replayFloor.Seconds(),
	})
	if err != nil {
		c.log.ErrorContext(ctx, "saml: recording the consumed assertion",
			logevent.SAMLStateUnavailable.Attr(), "set", "assertions", "err", err)
		return true
	}
	if c.sweepDue() {
		if _, err := c.q.DeleteExpiredSAMLAssertions(ctx); err != nil {
			c.log.WarnContext(ctx, "saml: dropping expired assertions", "err", err)
		}
	}
	return n == 0
}

// StoreRequestTracker is the request tracker in the database.
type StoreRequestTracker struct{ *storeSet }

// NewStoreRequestTracker builds a request tracker over the registry's
// store.
func NewStoreRequestTracker(q *storegen.Queries, log *slog.Logger) *StoreRequestTracker {
	return &StoreRequestTracker{storeSet: newStoreSet(q, log)}
}

// Track implements RequestTracker.
func (t *StoreRequestTracker) Track(reqCtx context.Context, id string, exp time.Time) {
	if id == "" || len(id) > maxIDLen {
		return
	}
	ctx, cancel := context.WithTimeout(reqCtx, storeCallTimeout)
	defer cancel()
	if err := t.q.TrackSAMLRequest(ctx, storegen.TrackSAMLRequestParams{ID: id, ExpiresAt: exp}); err != nil {
		// The request goes out untracked; the assertion that answers it
		// finds no outstanding id and is refused, so the person retries a
		// login that could not complete rather than one that should not.
		t.log.ErrorContext(ctx, "saml: recording the login request",
			logevent.SAMLStateUnavailable.Attr(), "set", "requests", "err", err)
	}
	if t.sweepDue() {
		if _, err := t.q.DeleteExpiredSAMLRequests(ctx); err != nil {
			t.log.WarnContext(ctx, "saml: dropping expired login requests", "err", err)
		}
	}
}

// Consume implements RequestTracker.
func (t *StoreRequestTracker) Consume(reqCtx context.Context, id string) bool {
	if id == "" || len(id) > maxIDLen {
		return false
	}
	ctx, cancel := context.WithTimeout(reqCtx, storeCallTimeout)
	defer cancel()
	n, err := t.q.ConsumeSAMLRequest(ctx, id)
	if err != nil {
		t.log.ErrorContext(ctx, "saml: consuming the login request",
			logevent.SAMLStateUnavailable.Attr(), "set", "requests", "err", err)
		return false
	}
	return n == 1
}
