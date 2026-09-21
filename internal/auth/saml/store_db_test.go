package saml

// The store-backed sets against a real database (agentry#414). What makes
// them one set across API replicas is where they live, and what makes them
// safe is the direction they fail in when that database cannot be reached;
// both are about what the queries return rather than about a decision the
// SP makes, so they are tested here, beside the code, rather than through
// the API's fixtures (as internal/notify's database tests are).

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/blaktron/agentry/internal/store"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// testStore opens the test database, migrated, and closes it with the test.
func testStore(t *testing.T) (*store.Store, *storegen.Queries) {
	t.Helper()
	url := os.Getenv("AGENTRY_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("AGENTRY_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	if err := store.Migrate(ctx, url); err != nil {
		t.Fatal(err)
	}
	st, err := store.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	return st, st.Queries()
}

// TestSAMLStoreSetsAreSharedAndExpire: two instances over one database see
// one set, which is what makes the sets one across replicas; an id seen
// once is a replay and an expired record is not; a request is consumed
// once; and a database that cannot be reached fails closed in both
// directions.
func TestSAMLStoreSetsAreSharedAndExpire(t *testing.T) {
	st, q := testStore(t)
	ctx := context.Background()
	sfx := uuid.NewString()[:8]

	cacheA, cacheB := NewStoreReplayCache(q, nil), NewStoreReplayCache(q, nil)
	id := "_assertion-" + sfx
	if cacheA.SeenBefore(ctx, id, time.Now().Add(5*time.Minute)) {
		t.Fatal("a fresh assertion id was called a replay")
	}
	if !cacheB.SeenBefore(ctx, id, time.Now().Add(5*time.Minute)) {
		t.Fatal("the other instance did not see the consumed assertion")
	}
	if !cacheA.SeenBefore(ctx, "", time.Now().Add(5*time.Minute)) {
		t.Fatal("an assertion with no id must fail closed")
	}
	tooLong := strings.Repeat("x", maxIDLen+1)
	if !cacheA.SeenBefore(ctx, tooLong, time.Now().Add(5*time.Minute)) {
		t.Fatal("an assertion id longer than the table takes must fail closed")
	}

	// A record is kept for the floor even when the assertion's own expiry
	// has already passed, on the database's clock and by the same constant
	// the in-memory cache uses: the validator goes on accepting an
	// assertion past the expiry it carries, and a record that lapsed with
	// it would leave that tail of the window unprotected.
	edge := "_edge-" + sfx
	if cacheA.SeenBefore(ctx, edge, time.Now().Add(-time.Second)) {
		t.Fatal("a fresh id at the edge of its window was called a replay")
	}
	var kept bool
	if err := st.Pool().QueryRow(ctx,
		`SELECT expires_at > now() + make_interval(secs => $2) FROM saml_consumed_assertions WHERE id = $1`,
		edge, (replayFloor - time.Minute).Seconds()).Scan(&kept); err != nil {
		t.Fatal(err)
	}
	if !kept {
		t.Fatalf("the record of a consumed assertion is kept for less than %s", replayFloor)
	}

	// An expired record does not stand in the way of a fresh id.
	if _, err := st.Pool().Exec(ctx,
		`UPDATE saml_consumed_assertions SET expires_at = now() - interval '1 minute' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	if cacheB.SeenBefore(ctx, id, time.Now().Add(5*time.Minute)) {
		t.Fatal("an expired record was still counted as a replay")
	}

	trackerA, trackerB := NewStoreRequestTracker(q, nil), NewStoreRequestTracker(q, nil)
	req := "_request-" + sfx
	trackerA.Track(ctx, req, time.Now().Add(15*time.Minute))
	if !trackerB.Consume(ctx, req) {
		t.Fatal("the other instance could not consume the tracked request")
	}
	if trackerA.Consume(ctx, req) {
		t.Fatal("a request was consumed twice")
	}
	trackerA.Track(ctx, req+"-old", time.Now().Add(-time.Minute))
	if trackerB.Consume(ctx, req+"-old") {
		t.Fatal("an expired request was consumed")
	}
	trackerA.Track(ctx, "", time.Now().Add(time.Minute))
	if trackerB.Consume(ctx, "") {
		t.Fatal("an empty request id was consumed")
	}
	trackerA.Track(ctx, tooLong, time.Now().Add(time.Minute))
	if trackerB.Consume(ctx, tooLong) {
		t.Fatal("a request id longer than the table takes was consumed")
	}

	// A database that cannot be reached fails closed: every assertion is a
	// replay, no request is outstanding.
	gone := storegen.New(deadDB{})
	if !NewStoreReplayCache(gone, nil).SeenBefore(ctx, "_x", time.Now().Add(time.Minute)) {
		t.Fatal("a replay cache with no database accepted an assertion")
	}
	if NewStoreRequestTracker(gone, nil).Consume(ctx, "_x") {
		t.Fatal("a request tracker with no database answered a request as outstanding")
	}
}

// TestSAMLReplayRefusalHoldsUnderConcurrentPresentations: the same
// assertion presented at once to as many instances as a deployment has
// replicas is admitted exactly once, and the same request is consumed
// exactly once. Both are one statement over one row — the loser of the
// insert waits on the winner's row and re-reads it against the WHERE, the
// loser of the DELETE finds nothing — so single use is the database's
// property, not the callers'.
func TestSAMLReplayRefusalHoldsUnderConcurrentPresentations(t *testing.T) {
	_, q := testStore(t)
	ctx := context.Background()
	sfx := uuid.NewString()[:8]
	const presenters = 8

	race := func(what string, act func() bool) {
		t.Helper()
		start := make(chan struct{})
		won := make([]bool, presenters)
		var wg sync.WaitGroup
		for i := range presenters {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				won[i] = act()
			}(i)
		}
		close(start)
		wg.Wait()
		n := 0
		for _, ok := range won {
			if ok {
				n++
			}
		}
		if n != 1 {
			t.Fatalf("%s: %d of %d concurrent presentations were admitted, want exactly 1 (%v)", what, n, presenters, won)
		}
	}

	assertion := "_race-assertion-" + sfx
	exp := time.Now().Add(5 * time.Minute)
	race("a captured assertion", func() bool {
		// Its own instance, as its own replica would have.
		cache := NewStoreReplayCache(q, nil)
		return !cache.SeenBefore(ctx, assertion, exp)
	})

	request := "_race-request-" + sfx
	NewStoreRequestTracker(q, nil).Track(ctx, request, exp)
	race("an answered login request", func() bool {
		tracker := NewStoreRequestTracker(q, nil)
		return tracker.Consume(ctx, request)
	})
}

// deadDB is a database that answers nothing.
type deadDB struct{}

func (deadDB) Exec(context.Context, string, ...interface{}) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, errors.New("the database is gone")
}
func (deadDB) Query(context.Context, string, ...interface{}) (pgx.Rows, error) {
	return nil, errors.New("the database is gone")
}
func (deadDB) QueryRow(context.Context, string, ...interface{}) pgx.Row { return deadRow{} }

type deadRow struct{}

func (deadRow) Scan(...interface{}) error { return errors.New("the database is gone") }
