package scan

import "testing"

// TestRescanSeverityKeepsTheLowerBarForTheProbableFindings: the findings
// rated high on probable evidence hold a submission but weigh medium when
// a rescan decides whether to pull a published version. These are undeclared
// env reads and S5 scores of 2 for injection, undeclared capability and
// deceiving the user, and S6's ungranted tools, which say a run lacks a
// tool rather than that it does harm. Everything else weighs what it is.
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
		{"S6's ungranted tools", Finding{Scanner: "S6/ungranted-tool", Severity: SevHigh}, SevMedium},
		{"another S6 high", Finding{Scanner: "S6/undeclared-exec", Severity: SevHigh}, SevHigh},
		{"a critical", Finding{Scanner: "S1/binary-executable", Severity: SevCritical}, SevCritical},
		{"C1 at 3, read back from JSON", Finding{Scanner: "S5/C1_injection", Severity: SevHigh, Detail: map[string]any{"score": 3.0}}, SevHigh},
		{"C6 at 2 is not a probable high", Finding{Scanner: "S5/C6_destructive_actions", Severity: SevHigh, Detail: map[string]any{"score": 2}}, SevHigh},
		{"C2 at 2 is not a probable high", Finding{Scanner: "S5/C2_exfiltration", Severity: SevHigh, Detail: map[string]any{"score": 2}}, SevHigh},
		{"C5 at 2 is not a probable high", Finding{Scanner: "S5/C5_obfuscation", Severity: SevHigh, Detail: map[string]any{"score": 2}}, SevHigh},
		{"a pack's C6 at 2 is not a probable high", Finding{Scanner: "SK/S5/C6_destructive_actions", Severity: SevHigh, Detail: map[string]any{"score": 2}}, SevHigh},
		{"a category of another stage at 2", Finding{Scanner: "S4/C1_injection", Severity: SevHigh, Detail: map[string]any{"score": 2}}, SevHigh},
		{"a score that is not a number", Finding{Scanner: "S5/C1_injection", Severity: SevHigh, Detail: map[string]any{"score": "2"}}, SevHigh},
		{"a medium stays medium", Finding{Scanner: "S6/undeclared-env", Severity: SevMedium}, SevMedium},
		{"a low stays low", Finding{Scanner: "S6/ungranted-tool", Severity: SevLow}, SevLow},
	}
	for _, tc := range cases {
		if got := rescanSeverity(tc.f); got != tc.want {
			t.Errorf("%s: rescanSeverity = %s, want %s", tc.name, got, tc.want)
		}
	}
}
