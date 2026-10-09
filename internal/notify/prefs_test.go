package notify

import (
	"testing"

	"github.com/google/uuid"
)

func TestEmailAllowedDefaultsAndKinds(t *testing.T) {
	row := Defaults(uuid.New())
	for _, k := range []Kind{KindDependencyAlert, KindQuarantine, KindReviewDecision, KindAdvisory, KindOrgInvite, KindBilling, KindSchedule, Kind("something-new")} {
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
	for _, k := range []Kind{KindDependencyAlert, KindQuarantine, KindReviewDecision, KindAdvisory, KindOrgInvite, KindBilling, KindSchedule, Kind("something-new")} {
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

// The schedules switch (agentry#1002) governs schedule mail and nothing
// else, and nothing else governs it: billing off leaves it on.
func TestScheduleSwitchIsItsOwn(t *testing.T) {
	row := Defaults(uuid.New())
	row.EmailSchedules = false
	if EmailAllowed(row, KindSchedule) || EmailPermitted(true, row, KindSchedule) {
		t.Fatal("schedules switched off, and schedule mail is still allowed")
	}
	if !EmailAllowed(row, KindBilling) || !EmailAllowed(row, KindDependencyAlert) {
		t.Fatal("schedules off switched another kind off")
	}
	row = Defaults(uuid.New())
	row.EmailBilling = false
	if !EmailAllowed(row, KindSchedule) {
		t.Fatal("billing off switched schedule mail off")
	}
}
