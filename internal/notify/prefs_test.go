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
