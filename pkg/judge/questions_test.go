package judge

import "testing"

// RubricSeverity is the gate's S5 rating and the draft check's, D16's two
// classes high from a probable score (agentry#771, agentry#773).
func TestRubricSeverity(t *testing.T) {
	for _, q := range RubricQuestions() {
		want2 := "medium"
		if q.ID == RubricIDInjection || q.ID == RubricIDUndeclaredCapability {
			want2 = "high"
		}
		for score, want := range map[int]string{0: "", 1: "", 2: want2, 3: "high"} {
			if got := RubricSeverity(q.ID, score); got != want {
				t.Errorf("RubricSeverity(%s, %d) = %q, want %q", q.ID, score, got, want)
			}
		}
	}
}
