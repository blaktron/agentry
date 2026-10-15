package saml

import (
	"testing"

	"github.com/crewjam/saml"
)

// TestSAMLReplayFloorOutlivesTheAcceptanceWindow: the record of a
// consumed assertion is what refuses its replay, so it has to outlive the
// window in which the validator would still accept that assertion.
//
// That window ends at IssueInstant + MaxIssueDelay, and at the expiry the
// assertion carries plus MaxClockSkew; the first presentation that writes
// the record had itself to pass validation, so it is no earlier than
// IssueInstant - MaxClockSkew. The floor is applied at that first
// presentation, on the database's clock for the store-backed cache, so the
// margin is replayFloor less both knobs. Nothing else in the tree relates
// the three, and the floor is the only thing standing between a captured
// assertion and a session: widening a knob past it has to fail here rather
// than open the window silently.
func TestSAMLReplayFloorOutlivesTheAcceptanceWindow(t *testing.T) {
	budget := saml.MaxIssueDelay + saml.MaxClockSkew
	if replayFloor <= budget {
		t.Fatalf("replayFloor %s does not outlive the acceptance budget %s (MaxIssueDelay %s + MaxClockSkew %s): a replay could arrive after the record lapsed and still be accepted",
			replayFloor, budget, saml.MaxIssueDelay, saml.MaxClockSkew)
	}
}
