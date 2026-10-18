package scan

import (
	"context"
	"errors"
	"testing"

	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// publishUnderLock is the one place a scan's result becomes a publication,
// and it refuses a result whose verdict is not publish before it touches the
// store: a held, rejected or empty result cannot publish whatever route
// brought it here.
func TestPublishUnderLockRefusesAVerdictThatIsNotPublish(t *testing.T) {
	p := &Pipeline{}
	for _, o := range []Outcome{OutcomeNeedsReview, OutcomeRejected, ""} {
		err := p.publishUnderLock(context.Background(), storegen.GetAgentByIDRow{}, storegen.AgentVersion{Version: "1.0.0"},
			"quarantined", [16]byte{}, RunResult{Decision: GateDecision{Outcome: o}}, 1, "test", nil)
		if !errors.Is(err, errNotAPublishVerdict) {
			t.Errorf("verdict %q: err = %v, want errNotAPublishVerdict", o, err)
		}
	}
}
