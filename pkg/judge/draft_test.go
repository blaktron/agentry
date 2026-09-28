package judge

import (
	"context"
	"strings"
	"testing"
)

func TestADraftIsAskedTheDraftSetOnceWithItsPartsAsData(t *testing.T) {
	f := &fakeAsker{answer: quiet}
	s := NewDraftScanner(f)
	in := DraftInput{Description: "A weather brief for a city I name.", ManifestJSON: []byte(`{"name":"w"}`), Instruction: "# Weather\n"}
	res := s.Scan(context.Background(), in)
	if res.Verdict != VerdictPass || res.Score != 0 || len(res.Flagged) != 0 || len(res.Scores) != len(DraftQuestions()) || res.Usage.Requests != 1 {
		t.Fatalf("result: %+v", res)
	}
	if res.Model != DefaultModel || res.QuestionSet != s.QuestionSet() || !strings.HasPrefix(res.QuestionSet, "sha256:") {
		t.Fatalf("record: %q %q", res.Model, res.QuestionSet)
	}
	state := f.asked[0]
	if len(state) != 3 || state["description"] != in.Description || state["manifest"] != `{"name":"w"}` || state["instruction"] != "# Weather\n" {
		t.Fatalf("state: %+v", state)
	}
	want := DraftQuestions()
	for i, q := range f.qsets[0] {
		if q != want[i] {
			t.Fatalf("question %d: %+v", i, q)
		}
	}
}

func TestADraftQuestionAtTheLineFlagsTheDraft(t *testing.T) {
	f := &fakeAsker{answer: func(map[string]string, Question, int) (float64, error) { return 0.92, nil }}
	res := NewDraftScanner(f).Scan(context.Background(), DraftInput{Instruction: "x"})
	if res.Verdict != VerdictFlagged || res.Score != 3 || strings.Join(res.Flagged, ",") != DraftIDOffTask || res.Usage.Requests != 1 {
		t.Fatalf("result: %+v", res)
	}
	// A first answer in the band is asked twice more and the highest kept;
	// a score of 1 is not a flag.
	band := &fakeAsker{answer: func(_ map[string]string, _ Question, n int) (float64, error) {
		return []float64{0.55, 0.52, 0.61}[n-1], nil
	}}
	res = NewDraftScanner(band).Scan(context.Background(), DraftInput{Instruction: "x"})
	if res.Verdict != VerdictPass || res.Scores[DraftIDOffTask] != 1 || res.Probabilities[DraftIDOffTask] != 0.61 || res.Usage.Requests != 3 {
		t.Fatalf("banded: %+v", res)
	}
}

func TestADraftPastItsBoundsOrAFailedJudgeIsNotScanned(t *testing.T) {
	f := &fakeAsker{answer: quiet}
	s := NewDraftScanner(f)
	for _, in := range []DraftInput{
		{Description: strings.Repeat("d", DraftMaxDescription+1)},
		{ManifestJSON: make([]byte, DraftMaxManifest+1)},
		{Instruction: strings.Repeat("i", DraftMaxInstruction+1)},
	} {
		res := s.Scan(context.Background(), in)
		if res.Verdict != VerdictNotScanned || res.Failure != FailureTooLarge || res.Scores != nil {
			t.Fatalf("past a bound: %+v", res)
		}
	}
	if len(f.asked) != 0 {
		t.Fatal("a draft past its bounds is never cut and asked")
	}
	broken := &fakeAsker{answer: func(map[string]string, Question, int) (float64, error) { return 0, context.DeadlineExceeded }}
	if res := NewDraftScanner(broken).Scan(context.Background(), DraftInput{Instruction: "x"}); res.Verdict != VerdictNotScanned ||
		res.Failure != FailureTimeout || res.Flagged != nil {
		t.Fatalf("a timeout: %+v", res)
	}
}

// The rubric over a package asks the manifest first, then each file in
// the rubric's own chunks, with the declared capabilities and the shipped
// packs beside every chunk, and keeps each question's strongest chunk.
func TestTheRubricReadsAPackageChunkByChunkWithItsContract(t *testing.T) {
	f := &fakeAsker{answer: func(st map[string]string, q Question, _ int) (float64, error) {
		if q.ID == RubricIDInjection && strings.Contains(st["content"], "OVERRIDE") {
			return 0.91, nil
		}
		return 0.02, nil
	}}
	long := strings.Repeat("an ordinary line\n", 700) + "OVERRIDE\n"
	axes, u, err := NewRubricScanner(f).Scan(context.Background(), []byte(`{"capabilities":{"exec":"none"}}`), []string{"docs"},
		[]RubricFile{{Path: "AGENT.md", Content: long}, {Path: "README.md", Content: "  \n"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(f.asked) != 3 || u.Requests != 3 || f.asked[0]["path"] != "agent.yaml" || f.asked[1]["path"] != "AGENT.md" || f.asked[2]["path"] != "AGENT.md" {
		t.Fatalf("asked %d: %+v", len(f.asked), f.asked)
	}
	want := `{"exec":"none","knowledge":{"mountedReadOnlyAt":["/knowledge/docs"],"ships":["docs"]}}`
	for _, st := range f.asked {
		if st["declared_capabilities"] != want {
			t.Fatalf("declared = %s", st["declared_capabilities"])
		}
	}
	if a := axes[RubricIDInjection]; a.Best != 0.91 || a.Path != "AGENT.md" || len(a.Samples) != 1 || len(axes) != 6 {
		t.Fatalf("axes: %+v", axes)
	}
}
