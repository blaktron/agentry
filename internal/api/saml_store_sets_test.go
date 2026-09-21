package api_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	samlsp "github.com/blaktron/agentry/internal/auth/saml"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// The store-backed sets (agentry#414): what makes them one set across API
// replicas is where they live, and what makes them safe is the direction
// they fail in when that database cannot be reached.
//
// They belong to internal/auth/saml and are tested here, against this
// fixture's database, on purpose: the fixture migrates one database and
// every test in this package shares its pool, while a test in the owning
// package would make it one more package migrating and querying beside
// this suite, and four others already do. On the self-hosted runner
// internal/api runs close to go test's default ten-minute package timeout
// (agentry#137 is the same contention), so the margin is worth more than
// the placement.

// TestSAMLStoreSetsAreSharedAndExpire: two instances over one database see
// one set, which is what makes the sets one across replicas; an id seen
// once is a replay and an expired record is not; a request is consumed
// once; and a database that cannot be reached fails closed in both
// directions.
func TestSAMLStoreSetsAreSharedAndExpire(t *testing.T) {
	env := newTestEnv(t)
	q := env.st.Queries()
	ctx := context.Background()
	cacheA, cacheB := samlsp.NewStoreReplayCache(q, nil), samlsp.NewStoreReplayCache(q, nil)
	id := "_assertion-" + env.sfx
	if cacheA.SeenBefore(ctx, id, time.Now().Add(5*time.Minute)) {
		t.Fatal("a fresh assertion id was called a replay")
	}
	if !cacheB.SeenBefore(ctx, id, time.Now().Add(5*time.Minute)) {
		t.Fatal("the other instance did not see the consumed assertion")
	}
	if !cacheA.SeenBefore(ctx, "", time.Now().Add(5*time.Minute)) {
		t.Fatal("an assertion with no id must fail closed")
	}
	tooLong := strings.Repeat("x", 1025) // the tables' CHECK is 1024
	if !cacheA.SeenBefore(ctx, tooLong, time.Now().Add(5*time.Minute)) {
		t.Fatal("an assertion id longer than the table takes must fail closed")
	}

	// A record is kept for the floor even when the assertion's own expiry
	// has already passed, on the database's clock: the validator goes on
	// accepting an assertion for its clock skew past the expiry it carries,
	// and a record that lapsed with it would leave that tail unprotected.
	// The floor is saml's unexported replayFloor, ten minutes, pinned here
	// by value so that changing it fails this test deliberately.
	edge := "_edge-" + env.sfx
	if cacheA.SeenBefore(ctx, edge, time.Now().Add(-time.Second)) {
		t.Fatal("a fresh id at the edge of its window was called a replay")
	}
	var kept bool
	if err := env.st.Pool().QueryRow(ctx,
		`SELECT expires_at > now() + interval '9 minutes' FROM saml_consumed_assertions WHERE id = $1`, edge).Scan(&kept); err != nil {
		t.Fatal(err)
	}
	if !kept {
		t.Fatal("the record of a consumed assertion is kept for less than the floor")
	}

	// An expired record does not stand in the way of a fresh id.
	if _, err := env.st.Pool().Exec(ctx,
		`UPDATE saml_consumed_assertions SET expires_at = now() - interval '1 minute' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	if cacheB.SeenBefore(ctx, id, time.Now().Add(5*time.Minute)) {
		t.Fatal("an expired record was still counted as a replay")
	}

	trackerA, trackerB := samlsp.NewStoreRequestTracker(q, nil), samlsp.NewStoreRequestTracker(q, nil)
	req := "_request-" + env.sfx
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
	if !samlsp.NewStoreReplayCache(gone, nil).SeenBefore(ctx, "_x", time.Now().Add(time.Minute)) {
		t.Fatal("a replay cache with no database accepted an assertion")
	}
	if samlsp.NewStoreRequestTracker(gone, nil).Consume(ctx, "_x") {
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
	env := newTestEnv(t)
	q := env.st.Queries()
	ctx := context.Background()
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

	exp := time.Now().Add(5 * time.Minute)
	assertion := "_race-assertion-" + env.sfx
	race("a captured assertion", func() bool {
		// Its own instance, as its own replica would have.
		cache := samlsp.NewStoreReplayCache(q, nil)
		return !cache.SeenBefore(ctx, assertion, exp)
	})

	request := "_race-request-" + env.sfx
	samlsp.NewStoreRequestTracker(q, nil).Track(ctx, request, exp)
	race("an answered login request", func() bool {
		tracker := samlsp.NewStoreRequestTracker(q, nil)
		return tracker.Consume(ctx, request)
	})
}

// TestSAMLLoginStartedOnOneReplicaCompletesOnAnother (agentry#414): the
// other half of the shared state. The AuthnRequest one replica's landing
// issues is recorded where every replica reads it, so the assertion
// answering it is accepted at a replica that never issued it — and, the
// request being single use, a second answer to it is refused there too.
func TestSAMLLoginStartedOnOneReplicaCompletesOnAnother(t *testing.T) {
	a := newTestEnv(t)
	b := newTestEnv(t)
	owner := a.register("saml-xrep-owner")
	a.verifyEmail(owner)
	sess := a.login(owner)
	orgH := "samlxrep" + a.sfx
	a.createOrg(sess, orgH)
	a.verifyOrgDomain(orgH, "acme.example")
	idp := newSAMLTestIdP(t)
	metadataXML, err := samlsp.BuildIDPMetadataXML(idp.entityID, "https://acs-idp.test/sso", idp.certPEM)
	if err != nil {
		t.Fatal(err)
	}
	a.doJSON(sess, http.MethodPut, "/api/v1/orgs/"+orgH+"/sso/connections/saml", map[string]any{
		"enabled": true,
		"config":  map[string]any{"idpMetadataXml": metadataXML, "emailAttribute": "email"},
	}, nil, http.StatusOK)
	nameID := "saml-xrep-" + a.sfx + "@acme.example"
	a.seedMembership(orgH, a.registerEmail("saml-xrep-member", nameID), "member", "active")

	// The login starts at the first replica, which records the request it
	// issued in the set both replicas read.
	started := a.getNoRedirect(t, "/sso/"+orgH)
	location := started.Header.Get("Location")
	_ = started.Body.Close()
	if started.StatusCode != http.StatusFound {
		t.Fatalf("/sso/%s at the first replica: got %d want 302", orgH, started.StatusCode)
	}
	requestID := authnRequestID(t, location)

	// The identity provider's answer arrives at the other replica, under
	// the public Host they share.
	metadataURL := a.srv.URL + "/api/v1/orgs/" + orgH + "/sso/saml/metadata"
	acsURL := a.srv.URL + "/api/v1/orgs/" + orgH + "/sso/saml/acs"
	publicHost := strings.TrimPrefix(a.srv.URL, "http://")
	postAtB := func(samlResponse string) (*http.Response, []byte) {
		res := b.postFormAs(t, b.srv.URL+"/api/v1/orgs/"+orgH+"/sso/saml/acs", url.Values{"SAMLResponse": {samlResponse}}, publicHost)
		body, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		return res, body
	}

	answer := idp.signedResponseFor(t, metadataURL, acsURL, nameID, requestID, false)
	completed, body := postAtB(answer)
	if completed.StatusCode != http.StatusOK {
		t.Fatalf("the assertion answering the other replica's request: %d %s, want 200", completed.StatusCode, body)
	}
	if !sessionCookie(completed) {
		t.Fatal("a login started at one replica and answered at another minted no session")
	}

	// The request is single use across replicas too, and one neither
	// replica issued was never outstanding.
	reused, body := postAtB(idp.signedResponseFor(t, metadataURL, acsURL, nameID, requestID, false))
	if reused.StatusCode != http.StatusUnauthorized {
		t.Fatalf("answering the other replica's request twice: %d %s, want 401", reused.StatusCode, body)
	}
	foreign, body := postAtB(idp.signedResponseFor(t, metadataURL, acsURL, nameID, "_id_neither_replica_issued", false))
	if foreign.StatusCode != http.StatusUnauthorized {
		t.Fatalf("an assertion naming a request no replica issued: %d %s, want 401", foreign.StatusCode, body)
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
