package judge

import "testing"

// RubricSeverity is the gate's S5 rating and the draft check's: injection,
// an undeclared capability and deceiving the user are high from a probable
// score (agentry#771, agentry#773; deception since ruleset 0.4.0), and
// exfiltration and destructive actions are at most medium since ruleset
// 0.4.0 (agentry#893): a capability the manifest does not declare is C3's
// to hold.
func TestRubricSeverity(t *testing.T) {
	want := map[string][4]string{
		RubricIDInjection:            {"", "", "high", "high"},
		RubricIDUndeclaredCapability: {"", "", "high", "high"},
		RubricIDDeception:            {"", "", "high", "high"},
		RubricIDObfuscation:          {"", "", "medium", "high"},
		RubricIDExfiltration:         {"", "", "medium", "medium"},
		RubricIDDestructive:          {"", "", "medium", "medium"},
	}
	for _, q := range RubricQuestions() {
		w, ok := want[q.ID]
		if !ok {
			t.Fatalf("%s has no expected rating", q.ID)
		}
		for score := 0; score <= 3; score++ {
			if got := RubricSeverity(q.ID, score); got != w[score] {
				t.Errorf("RubricSeverity(%s, %d) = %q, want %q", q.ID, score, got, w[score])
			}
		}
	}
}
