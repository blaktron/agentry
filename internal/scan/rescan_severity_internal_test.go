package scan

import "testing"

// TestRescanSeverityKeepsTheLowerBarForTheProbableFindings: the findings
// rated high on probable evidence hold a submission but weigh medium when
// a rescan decides whether to pull a published version. These are undeclared
// env reads and S5 scores of 2 for injection, undeclared capability and
// deceiving the user. Everything else weighs what it is.
func TestRescanSeverityKeepsTheOldBarForTheReratedFindings(t *testing.T) {
	cases := []struct {
		name string
		f    Finding
		want Severity
	}{
		{"undeclared env", Finding{Scanner: "S6/undeclared-env", Severity: SevHigh}, SevMedium},
		{"C3 at 2", Finding{Scanner: "S5/C3_undeclared_capability", Severity: SevHigh, Detail: map[string]any{"score": 2}}, SevMedium},
		{"C1 at 2, read back from JSON", Finding{Scanner: "S5/C1_injection", Severity: SevHigh, Detail: map[string]any{"score": 2.0}}, SevMedium},
		{"a shipped pack's C3 at 2", Finding{Scanner: "SK/S5/C3_undeclared_capability", Severity: SevHigh, Detail: map[string]any{"score": 2}}, SevMedium},
		{"C4 at 2", Finding{Scanner: "S5/C4_user_deception", Severity: SevHigh, Detail: map[string]any{"score": 2}}, SevMedium},
		{"C3 at 3", Finding{Scanner: "S5/C3_undeclared_capability", Severity: SevHigh, Detail: map[string]any{"score": 3}}, SevHigh},
		{"C3 with no score", Finding{Scanner: "S5/C3_undeclared_capability", Severity: SevHigh}, SevHigh},
		{"a manipulated judge", Finding{Scanner: "S5/manipulated-judge", Severity: SevHigh}, SevHigh},
		{"a pack's C1 at 3", Finding{Scanner: "SK/S5/C1_injection", Severity: SevHigh, Detail: map[string]any{"score": 3}}, SevHigh},
		{"C6 at 3", Finding{Scanner: "S5/C6_destructive_actions", Severity: SevHigh, Detail: map[string]any{"score": 3}}, SevHigh},
		{"another S6 high", Finding{Scanner: "S6/undeclared-exec", Severity: SevHigh}, SevHigh},
		{"a critical", Finding{Scanner: "S1/binary-executable", Severity: SevCritical}, SevCritical},
	}
	for _, tc := range cases {
		if got := rescanSeverity(tc.f); got != tc.want {
			t.Errorf("%s: rescanSeverity = %s, want %s", tc.name, got, tc.want)
		}
	}
}
