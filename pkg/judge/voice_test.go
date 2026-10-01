package judge

import (
	"context"
	"strings"
	"testing"
)

func TestAVoiceIsAskedTheVoiceSetOnceAsData(t *testing.T) {
	f := &fakeAsker{answer: quiet}
	s := NewVoiceScanner(f)
	voice := "# Writing Voice\n\nShort sentences.\n"
	res := s.Scan(context.Background(), voice)
	if res.Verdict != VerdictPass || res.Score != 0 || len(res.Flagged) != 0 || len(res.Scores) != len(VoiceQuestions()) || res.Usage.Requests != 1 {
		t.Fatalf("result: %+v", res)
	}
	if res.Model != DefaultModel || res.QuestionSet != s.QuestionSet() || !strings.HasPrefix(res.QuestionSet, "sha256:") {
		t.Fatalf("record: %q %q", res.Model, res.QuestionSet)
	}
	if state := f.asked[0]; len(state) != 1 || state["voice"] != voice {
		t.Fatalf("state: %+v", state)
	}
	want := VoiceQuestions()
	if len(f.qsets[0]) != len(want) {
		t.Fatalf("asked %d questions", len(f.qsets[0]))
	}
	for i, q := range f.qsets[0] {
		if q != want[i] || strings.Contains(q.Text, "Short sentences") {
			t.Fatalf("question %d: %+v", i, q)
		}
	}
}

func TestAVoiceQuestionAtTheLineFlagsTheVoice(t *testing.T) {
	f := &fakeAsker{answer: func(_ map[string]string, q Question, _ int) (float64, error) {
		if q.ID == VoiceIDInsertedContent {
			return 0.91, nil
		}
		return 0.1, nil
	}}
	res := NewVoiceScanner(f).Scan(context.Background(), "x")
	if res.Verdict != VerdictFlagged || res.Score != 3 || strings.Join(res.Flagged, ",") != VoiceIDInsertedContent {
		t.Fatalf("result: %+v", res)
	}
	// A first answer in the band is asked twice more and the highest kept;
	// 0.69 is not a flag, 0.71 is, and an answer out of the band is not
	// asked again.
	for _, c := range []struct {
		answers  []float64
		flagged  bool
		requests int
	}{{[]float64{0.55, 0.52, 0.69}, false, 3}, {[]float64{0.55, 0.71, 0.4}, true, 2}} {
		band := &fakeAsker{answer: func(_ map[string]string, q Question, n int) (float64, error) {
			if q.ID == VoiceIDOverride {
				return c.answers[n-1], nil
			}
			return 0, nil
		}}
		res := NewVoiceScanner(band).Scan(context.Background(), "x")
		if (res.Verdict == VerdictFlagged) != c.flagged || res.Usage.Requests != c.requests {
			t.Fatalf("banded %v: %+v", c.answers, res)
		}
	}
}

func TestAVoiceThatIsNotOneOrAFailedJudgeIsNotScanned(t *testing.T) {
	f := &fakeAsker{answer: quiet}
	s := NewVoiceScanner(f)
	for want, voice := range map[string]string{
		FailureTooLarge: strings.Repeat("v", VoiceMaxBytes+1),
		FailureInvalid:  string([]byte{0xff, 0xfe}),
		"":              "",
	} {
		res := s.Scan(context.Background(), voice)
		if want == "" {
			want = FailureInvalid
		}
		if res.Verdict != VerdictNotScanned || res.Failure != want || res.Scores != nil {
			t.Fatalf("%s: %+v", want, res)
		}
	}
	if len(f.asked) != 0 {
		t.Fatal("a text that is not a voice was asked")
	}
	if res := s.Scan(context.Background(), strings.Repeat("v", VoiceMaxBytes)); res.Verdict != VerdictPass {
		t.Fatalf("a voice at the bound: %+v", res)
	}
	broken := &fakeAsker{answer: func(map[string]string, Question, int) (float64, error) { return 0, context.DeadlineExceeded }}
	if res := NewVoiceScanner(broken).Scan(context.Background(), "x"); res.Verdict != VerdictNotScanned || res.Failure != FailureTimeout {
		t.Fatalf("a timeout: %+v", res)
	}
}
