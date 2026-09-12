package notify

import (
	"testing"

	"github.com/google/uuid"
)

func TestEmailAllowedDefaultsAndKinds(t *testing.T) {
	row := Defaults(uuid.New())
	for _, k := range []Kind{KindDependencyAlert, KindQuarantine, KindReviewDecision, KindAdvisory, KindOrgInvite, Kind("something-new")} {
		if !EmailAllowed(row, k) {
			t.Fatalf("defaults must allow %s", k)
		}
	}
	row.EmailReviewDecisions = false
	row.EmailOrgInvites = false
	if EmailAllowed(row, KindReviewDecision) || EmailAllowed(row, KindOrgInvite) {
		t.Fatal("switched-off kinds must be refused")
	}
	if !EmailAllowed(row, KindQuarantine) || !EmailAllowed(row, KindDependencyAlert) {
		t.Fatal("other kinds stay on")
	}
}

func TestEmailPermittedRequiresVerifiedAddress(t *testing.T) {
	row := Defaults(uuid.New())
	for _, k := range []Kind{KindDependencyAlert, KindQuarantine, KindReviewDecision, KindAdvisory, KindOrgInvite, Kind("something-new")} {
		if EmailPermitted(false, row, k) {
			t.Fatalf("an unverified address must get no %s mail, whatever the settings say", k)
		}
		if !EmailPermitted(true, row, k) {
			t.Fatalf("a verified address with default settings must get %s mail", k)
		}
	}
	row.EmailQuarantine = false
	if EmailPermitted(true, row, KindQuarantine) {
		t.Fatal("verified but switched off must still be refused")
	}
}
