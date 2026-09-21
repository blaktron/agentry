package api_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	samlsp "github.com/blaktron/agentry/internal/auth/saml"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// TestSAMLStoreSetsAreSharedAndExpire (agentry#414): the replay cache and
// the request tracker in the database behave as the in-memory ones do —
// an id seen once is a replay, an expired one is not; a request tracked
// is consumed once — and two instances over one database see the same
// sets, which is what makes them one across replicas.
func TestSAMLStoreSetsAreSharedAndExpire(t *testing.T) {
	env := newTestEnv(t)
	q := env.st.Queries()
	cacheA, cacheB := samlsp.NewStoreReplayCache(q, nil), samlsp.NewStoreReplayCache(q, nil)
	id := "_assertion-" + env.sfx
	if cacheA.SeenBefore(id, time.Now().Add(5*time.Minute)) {
		t.Fatal("a fresh assertion id was called a replay")
	}
	if !cacheB.SeenBefore(id, time.Now().Add(5*time.Minute)) {
		t.Fatal("the other instance did not see the consumed assertion")
	}
	if !cacheA.SeenBefore("", time.Now().Add(5*time.Minute)) {
		t.Fatal("an assertion with no id must fail closed")
	}
	// An expired record does not stand in the way of a fresh id.
	if _, err := env.st.Pool().Exec(context.Background(), `UPDATE saml_consumed_assertions SET expires_at = now() - interval '1 minute' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	if cacheB.SeenBefore(id, time.Now().Add(5*time.Minute)) {
		t.Fatal("an expired record was still counted as a replay")
	}

	trackerA, trackerB := samlsp.NewStoreRequestTracker(q, nil), samlsp.NewStoreRequestTracker(q, nil)
	req := "_request-" + env.sfx
	trackerA.Track(req, time.Now().Add(15*time.Minute))
	if !trackerB.Consume(req) {
		t.Fatal("the other instance could not consume the tracked request")
	}
	if trackerA.Consume(req) {
		t.Fatal("a request was consumed twice")
	}
	trackerA.Track(req+"-old", time.Now().Add(-time.Minute))
	if trackerB.Consume(req + "-old") {
		t.Fatal("an expired request was consumed")
	}
	trackerA.Track("", time.Now().Add(time.Minute))
	if trackerB.Consume("") {
		t.Fatal("an empty request id was consumed")
	}

	// A database that cannot be reached fails closed: every assertion is
	// a replay, no request is outstanding.
	gone := storegen.New(deadDB{})
	if !samlsp.NewStoreReplayCache(gone, nil).SeenBefore("_x", time.Now().Add(time.Minute)) {
		t.Fatal("a replay cache with no database accepted an assertion")
	}
	if samlsp.NewStoreRequestTracker(gone, nil).Consume("_x") {
		t.Fatal("a request tracker with no database answered a request as outstanding")
	}
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
