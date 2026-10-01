package scan

import "testing"

func TestRulesetJobActionFor(t *testing.T) {
	for _, tc := range []struct {
		worker, job string
		want        rulesetJobAction
	}{
		{"0.2.3", "", rulesetJobRun},        // enqueued before jobs named their ruleset
		{"0.2.3", "0.2.3", rulesetJobRun},   // its own
		{"0.2.3", "0.3.0", rulesetJobDefer}, // the incoming build's: hand it back
		{"0.3.0", "0.2.3", rulesetJobSkip},  // superseded: 0.3.0 enqueued its own
		{"0.2.3", "0.2.10", rulesetJobDefer},
		{"0.2.3", "not-a-version", rulesetJobRun},
		{"9.99.1-redo1", "9.99.1-redo1", rulesetJobRun},
	} {
		if got := rulesetJobActionFor(tc.worker, tc.job); got != tc.want {
			t.Errorf("worker %q, job %q: %v, want %v", tc.worker, tc.job, got, tc.want)
		}
	}
}
