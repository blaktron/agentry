package saml

// SP-initiated SAML: the SP generates an AuthnRequest, tracks its id, and
// refuses an assertion whose InResponseTo names anything else. crewjam
// skips the InResponseTo check whenever AllowIDPInitiated is set, so these
// tests pin the check we added on top of it.

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"
)

// spWithTracker builds an SP for the in-test IdP with a request tracker.
func spWithTracker(t *testing.T, idp *testIdP) (*SP, *MemoryRequestTracker) {
	t.Helper()
	tracker := NewMemoryRequestTracker()
	return newSPForIdP(t, idp).WithRequestTracker(tracker), tracker
}

func TestSAML_AuthnRequestIsTracked(t *testing.T) {
	idp := newTestIdP(t)
	sp, tracker := spWithTracker(t, idp)

	redirect, err := sp.AuthnRequest(context.Background(), "acme")
	if err != nil {
		t.Fatalf("AuthnRequest: %v", err)
	}
	u, err := url.Parse(redirect)
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	if !strings.HasPrefix(redirect, "https://idp.test/sso") {
		t.Fatalf("redirect must target the IdP SSO endpoint, got %s", redirect)
	}
	if u.Query().Get("SAMLRequest") == "" {
		t.Fatal("redirect carries no SAMLRequest")
	}
	if u.Query().Get("RelayState") != "acme" {
		t.Fatalf("RelayState = %q, want acme", u.Query().Get("RelayState"))
	}
	// Exactly one id is outstanding, and it is single use.
	id := onlyTrackedID(t, tracker)
	if !tracker.Consume(context.Background(), id) {
		t.Fatal("the tracked request id must be consumable once")
	}
	if tracker.Consume(context.Background(), id) {
		t.Fatal("a request id must not be consumable twice")
	}
}

func TestSAML_SPInitiatedRoundTrip(t *testing.T) {
	idp := newTestIdP(t)
	sp, tracker := spWithTracker(t, idp)

	if _, err := sp.AuthnRequest(context.Background(), "acme"); err != nil {
		t.Fatalf("AuthnRequest: %v", err)
	}
	requestID := onlyTrackedID(t, tracker)

	o := goodOpts()
	o.inResponseTo = requestID
	res, err := sp.ParseAndValidate(context.Background(), idp.mintResponse(t, o))
	if err != nil {
		t.Fatalf("SP-initiated assertion must be accepted: %v", err)
	}
	if res.Subject != testSubject {
		t.Fatalf("subject = %q, want %q", res.Subject, testSubject)
	}

	// The request id is consumed: a second assertion naming it is refused
	// even though its own assertion id is fresh.
	o2 := goodOpts()
	o2.inResponseTo = requestID
	if _, err := sp.ParseAndValidate(context.Background(), idp.mintResponse(t, o2)); err == nil {
		t.Fatal("a second assertion for the same AuthnRequest must be rejected")
	}
}

func TestSAML_InResponseToMismatchRejected(t *testing.T) {
	idp := newTestIdP(t)
	sp, _ := spWithTracker(t, idp)

	// A perfectly signed, in-window, correctly addressed assertion that names
	// a request this SP never issued — the response-stealing case.
	o := goodOpts()
	o.inResponseTo = "_assert_never_issued"
	if _, err := sp.ParseAndValidate(context.Background(), idp.mintResponse(t, o)); err == nil {
		t.Fatal("assertion naming an unknown AuthnRequest must be rejected")
	}
}

func TestSAML_IDPInitiatedStillAllowed(t *testing.T) {
	idp := newTestIdP(t)
	sp, _ := spWithTracker(t, idp)

	// No InResponseTo at all: IdP-initiated, which stays supported.
	if _, err := sp.ParseAndValidate(context.Background(), idp.mintResponse(t, goodOpts())); err != nil {
		t.Fatalf("IdP-initiated assertion must still be accepted: %v", err)
	}
}

func TestSAML_InResponseToRejectedWithoutTracker(t *testing.T) {
	idp := newTestIdP(t)
	sp := newSPForIdP(t, idp) // no tracker attached

	o := goodOpts()
	o.inResponseTo = "_assert_something"
	if _, err := sp.ParseAndValidate(context.Background(), idp.mintResponse(t, o)); err == nil {
		t.Fatal("without a tracker an InResponseTo we cannot check must be refused, not ignored")
	}
}

func TestSAML_RequestTrackerExpires(t *testing.T) {
	tracker := NewMemoryRequestTracker()
	tracker.Track(context.Background(), "_expired", time.Now().Add(-time.Second))
	if tracker.Consume(context.Background(), "_expired") {
		t.Fatal("an expired request id must not be consumable")
	}
	if tracker.Consume(context.Background(), "") {
		t.Fatal("an empty request id must never be consumable")
	}
}

// onlyTrackedID returns the single outstanding request id, failing otherwise.
func onlyTrackedID(t *testing.T, tracker *MemoryRequestTracker) string {
	t.Helper()
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	if len(tracker.seen) != 1 {
		t.Fatalf("expected exactly one tracked request, got %d", len(tracker.seen))
	}
	for id := range tracker.seen {
		return id
	}
	return ""
}
