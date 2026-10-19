package judge

import (
	"context"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"
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
	// A probability of 0.70 is a score of 2, and a score of 2 is a flag; the
	// highest sample is kept wherever it falls, and 0.70 sits in the band.
	edge := &fakeAsker{answer: func(_ map[string]string, _ Question, n int) (float64, error) {
		return []float64{0.7, 0.4, 0.2}[n-1], nil
	}}
	res = NewDraftScanner(edge).Scan(context.Background(), DraftInput{Instruction: "x"})
	if res.Verdict != VerdictFlagged || res.Score != 2 || res.Scores[DraftIDOffTask] != 2 || res.Probabilities[DraftIDOffTask] != 0.7 ||
		strings.Join(res.Flagged, ",") != DraftIDOffTask || res.Usage.Requests != 3 {
		t.Fatalf("a score of 2: %+v", res)
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
	// The refusal says which sizes were seen and which bounds they broke,
	// and the record of the model and question set is still filled.
	res := s.Scan(context.Background(), DraftInput{Description: "dd", ManifestJSON: []byte("mmm"), Instruction: strings.Repeat("i", 32769)})
	if res.Err == nil || res.Err.Error() != "judge: a draft of 2/3/32769 bytes is past the bounds 8192/16384/32768, 49152 in all" ||
		res.Model != DefaultModel || res.QuestionSet != s.QuestionSet() || res.Usage.Requests != 0 {
		t.Fatalf("the refusal: %+v", res)
	}
	broken := &fakeAsker{answer: func(map[string]string, Question, int) (float64, error) { return 0, context.DeadlineExceeded }}
	if res := NewDraftScanner(broken).Scan(context.Background(), DraftInput{Instruction: "x"}); res.Verdict != VerdictNotScanned ||
		res.Failure != FailureTimeout || res.Flagged != nil {
		t.Fatalf("a timeout: %+v", res)
	}
	// Any other failure is a judge error, and the request made is counted.
	boom := errors.New("judge: typesafe endpoint returned 500: oops")
	failing := &fakeAsker{answer: func(map[string]string, Question, int) (float64, error) { return 0, boom }}
	if res := NewDraftScanner(failing).Scan(context.Background(), DraftInput{Instruction: "x"}); res.Verdict != VerdictNotScanned ||
		res.Failure != FailureJudgeError || !errors.Is(res.Err, boom) || res.Flagged != nil || res.Scores != nil || res.Usage.Requests != 1 {
		t.Fatalf("a judge error: %+v", res)
	}
}

// The instruction bound is 32 KiB, the cap the Drafter holds its own
// to: a drafted instruction of 20–30 KB, and one at the bound, is asked
// off_task whole. The state as a whole is held to 48 KiB, so a long
// instruction beside a manifest and description at their bounds is not
// scanned and never cut.
func TestALongDraftedInstructionIsAskedWholeUpToTheBound(t *testing.T) {
	if DraftMaxInstruction != 32<<10 || DraftMaxState != 48<<10 {
		t.Fatalf("bounds %d and %d, want 32 KiB (the Drafter's cap) and 48 KiB", DraftMaxInstruction, DraftMaxState)
	}
	for _, n := range []int{30_000, DraftMaxInstruction} {
		f := &fakeAsker{answer: quiet}
		long := strings.Repeat("i", n)
		res := NewDraftScanner(f).Scan(context.Background(), DraftInput{Description: strings.Repeat("d", 8000), ManifestJSON: make([]byte, 4096), Instruction: long})
		if res.Verdict != VerdictPass || res.Failure != "" || len(f.asked) != 1 || f.asked[0]["instruction"] != long {
			t.Fatalf("a %d-byte instruction: %+v, asked %d", n, res, len(f.asked))
		}
	}
	f := &fakeAsker{answer: quiet}
	res := NewDraftScanner(f).Scan(context.Background(), DraftInput{
		Description: strings.Repeat("d", DraftMaxDescription), ManifestJSON: make([]byte, DraftMaxManifest), Instruction: strings.Repeat("i", DraftMaxInstruction),
	})
	if res.Verdict != VerdictNotScanned || res.Failure != FailureTooLarge || len(f.asked) != 0 {
		t.Fatalf("every part at its bound, past the state's: %+v, asked %d", res, len(f.asked))
	}

	// Each bound is inclusive and its own: a description of 8192 bytes, a
	// manifest of 16384 and a state of 49152 are asked, one byte more of any
	// is not. The sizes are spelled out, not read from the constants.
	for _, c := range []struct {
		name         string
		desc, man, i int
		asked        bool
	}{
		{"description at its bound", 8192, 0, 0, true},
		{"description one over", 8193, 0, 0, false},
		{"manifest at its bound", 0, 16384, 0, true},
		{"manifest one over", 0, 16385, 0, false},
		{"instruction at its bound", 0, 0, 32768, true},
		{"instruction one over", 0, 0, 32769, false},
		{"state at its bound", 8192, 8192, 32768, true},
		{"state one over", 8192, 8193, 32768, false},
		{"state one under", 8192, 8191, 32768, true},
	} {
		f := &fakeAsker{answer: quiet}
		res := NewDraftScanner(f).Scan(context.Background(), DraftInput{Description: strings.Repeat("d", c.desc), ManifestJSON: make([]byte, c.man), Instruction: strings.Repeat("i", c.i)})
		if got := res.Verdict == VerdictPass && len(f.asked) == 1; got != c.asked || (!c.asked && (res.Failure != FailureTooLarge || len(f.asked) != 0)) {
			t.Fatalf("%s: %+v, asked %d, want asked=%v", c.name, res, len(f.asked), c.asked)
		}
	}
	if DraftMaxDescription != 8192 || DraftMaxManifest != 16384 {
		t.Fatalf("bounds %d and %d, want 8 KiB and 16 KiB", DraftMaxDescription, DraftMaxManifest)
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

	ctx := context.Background()
	quietRubric := func(map[string]string, Question, int) (float64, error) { return 0.02, nil }

	// The rubric's own split: a line end is the cut when it falls at or
	// after the half of a piece, the last one in the piece; otherwise the
	// cut is at the size, inside a character if need be.
	for _, c := range []struct {
		in   string
		n    int
		want []string
	}{
		{"short", 10, []string{"short"}},
		{"0123456789", 10, []string{"0123456789"}},
		{"0123456789a", 10, []string{"0123456789", "a"}},
		{"aaaa\nbbbbbbbbbbbbbbb", 10, []string{"aaaa\nbbbbb", "bbbbbbbbbb"}},
		{"aaaaa\nbbbbbbbbbbbbbb", 10, []string{"aaaaa", "\nbbbbbbbbb", "bbbbb"}},
		{"aaaaaa\nbb\ncccccccccc", 10, []string{"aaaaaa\nbb", "\nccccccccc", "c"}},
		{strings.Repeat("\u00e9", 8), 5, []string{"\u00e9\u00e9\xc3", "\xa9\u00e9\u00e9", "\u00e9\u00e9\xc3", "\xa9"}},
	} {
		got := RubricChunk(c.in, c.n)
		if strings.Join(got, "|") != strings.Join(c.want, "|") || strings.Join(got, "") != c.in {
			t.Fatalf("RubricChunk(%q, %d) = %q, want %q", c.in, c.n, got, c.want)
		}
	}

	// What the manifest declares, as compact JSON in key order, with the
	// shipped packs added under knowledge and the whole bounded at 4096.
	pad := func(n int) string { return `{"capabilities":{"k":"` + strings.Repeat("p", n) + `"}}` }
	exact, over := `{"k":"`+strings.Repeat("p", 4088)+`"}`, `{"k":"`+strings.Repeat("p", 4089)+`"}`
	for name, c := range map[string]struct {
		manifest string
		ships    []string
		want     string
	}{
		"not json":                 {`not json`, []string{"docs"}, `{}`},
		"no capabilities":          {`{"name":"x"}`, nil, `{}`},
		"empty capabilities":       {`{"capabilities":{}}`, nil, `{}`},
		"null capabilities":        {`{"capabilities":null}`, nil, `{}`},
		"capabilities not object":  {`{"capabilities":[1,2]}`, []string{"docs"}, `{}`},
		"capabilities a string":    {`{"capabilities":"all"}`, nil, `{}`},
		"keys in order":            {`{"capabilities":{"net": true, "exec" : "none"}}`, nil, `{"exec":"none","net":true}`},
		"packs only":               {`{}`, []string{"docs"}, `{"knowledge":{"mountedReadOnlyAt":["/knowledge/docs"],"ships":["docs"]}}`},
		"packs sorted":             {`{"capabilities":{"exec":"none"}}`, []string{"zeta", "alpha"}, `{"exec":"none","knowledge":{"mountedReadOnlyAt":["/knowledge/alpha","/knowledge/zeta"],"ships":["alpha","zeta"]}}`},
		"packs replace a declared": {`{"capabilities":{"knowledge":{"ships":["fake"]}}}`, []string{"docs"}, `{"knowledge":{"mountedReadOnlyAt":["/knowledge/docs"],"ships":["docs"]}}`},
		"exactly the bound":        {pad(4088), nil, exact},
		"one over the bound":       {pad(4089), nil, over[:4096] + truncatedMark},
	} {
		if got := DeclaredCapabilities([]byte(c.manifest), c.ships); got != c.want {
			t.Fatalf("%s: %q, want %q", name, got, c.want)
		}
	}
	if len(exact) != 4096 || DeclaredCapabilitiesCap != 4096 {
		t.Fatalf("fixture %d bytes against a bound of %d", len(exact), DeclaredCapabilitiesCap)
	}
	ships := []string{"zeta", "alpha"}
	DeclaredCapabilities([]byte(`{}`), ships)
	if ships[0] != "zeta" {
		t.Fatal("the caller's list must not be reordered")
	}

	// The request shapes: the shipped one asks the six together, the
	// by-hand ones in groups of three or singly; an unknown shape is the
	// shipped one, in the hash too.
	for shape, groups := range map[int][]string{
		RubricBatchOne: {"C1_injection,C2_exfiltration,C3_undeclared_capability,C4_user_deception,C5_obfuscation,C6_destructive_actions"},
		RubricBatchTwo: {"C1_injection,C3_undeclared_capability,C5_obfuscation", "C2_exfiltration,C4_user_deception,C6_destructive_actions"},
		RubricBatchSix: {"C1_injection", "C2_exfiltration", "C3_undeclared_capability", "C4_user_deception", "C5_obfuscation", "C6_destructive_actions"},
		0:              {"C1_injection,C2_exfiltration,C3_undeclared_capability,C4_user_deception,C5_obfuscation,C6_destructive_actions"},
		3:              {"C1_injection,C2_exfiltration,C3_undeclared_capability,C4_user_deception,C5_obfuscation,C6_destructive_actions"},
		-2:             {"C1_injection,C2_exfiltration,C3_undeclared_capability,C4_user_deception,C5_obfuscation,C6_destructive_actions"},
		7:              {"C1_injection,C2_exfiltration,C3_undeclared_capability,C4_user_deception,C5_obfuscation,C6_destructive_actions"},
	} {
		f := &fakeAsker{answer: quietRubric}
		sc := NewRubricScannerShape(f, shape)
		if _, u, err := sc.Scan(ctx, []byte(`{}`), nil, nil); err != nil || u.Requests != len(groups) || len(f.qsets) != len(groups) {
			t.Fatalf("shape %d: %d requests, %v", shape, len(f.qsets), err)
		}
		for i, qs := range f.qsets {
			var ids []string
			for _, q := range qs {
				ids = append(ids, q.ID)
			}
			if strings.Join(ids, ",") != groups[i] {
				t.Fatalf("shape %d request %d asks %v, want %s", shape, i, ids, groups[i])
			}
		}
		if (shape == 3 || shape == 0 || shape == -2 || shape == 7) && sc.Hash() != NewRubricScanner(f).Hash() {
			t.Fatalf("shape %d is the shipped shape and hashes as it", shape)
		}
	}
	hf := &fakeAsker{answer: quietRubric}
	if NewRubricScannerShape(hf, 2).Hash() == NewRubricScanner(hf).Hash() || NewRubricScannerShape(hf, 6).Hash() == NewRubricScannerShape(hf, 2).Hash() {
		t.Fatal("the shape is in the hash")
	}

	// A failed request fails the scan: no axes, no usage, the error.
	boom := errors.New("judge: typesafe endpoint returned 500: oops")
	failing := &fakeAsker{answer: func(_ map[string]string, _ Question, n int) (float64, error) {
		if n == 2 {
			return 0, boom
		}
		return 0.02, nil
	}}
	axes, u, err = NewRubricScanner(failing).Scan(ctx, []byte(`{}`), nil, []RubricFile{{Path: "AGENT.md", Content: "text"}})
	if !errors.Is(err, boom) || axes != nil || u != (Usage{}) {
		t.Fatalf("a failed request: %v %v %+v", axes, err, u)
	}

	// Equal evidence stays with the chunk that drew it first; the band is
	// closed at 0.30 and 0.70, three samples at most are drawn and every one
	// is kept, the best of them standing for the axis.
	f = &fakeAsker{answer: quietRubric}
	axes, _, err = NewRubricScanner(f).Scan(ctx, []byte(`{}`), nil, []RubricFile{{Path: "a.md", Content: "one"}, {Path: "b.md", Content: "two"}})
	if err != nil || axes[RubricIDInjection].Path != "agent.yaml" || axes[RubricIDDestructive].Path != "agent.yaml" || len(f.asked) != 3 {
		t.Fatalf("ties: %+v", axes)
	}
	for _, c := range []struct {
		answers  []float64
		requests int
		best     float64
	}{
		{[]float64{0.4, 0.6, 0.5}, 3, 0.6},
		{[]float64{0.5, 0.65, 0.4}, 3, 0.65},
		{[]float64{0.4, 0.4, 0.4}, 3, 0.4},
		{[]float64{0.29, 0.9, 0.9}, 1, 0.29},
		{[]float64{0.30, 0.2, 0.1}, 3, 0.30},
		{[]float64{0.70, 0.1, 0.1}, 3, 0.70},
		{[]float64{0.71, 0.9, 0.9}, 1, 0.71},
	} {
		f := &fakeAsker{answer: func(_ map[string]string, q Question, n int) (float64, error) {
			if q.ID == RubricIDInjection {
				return c.answers[min(n, len(c.answers))-1], nil
			}
			return 0.02, nil
		}}
		axes, u, err := NewRubricScanner(f).Scan(ctx, []byte(`{}`), nil, nil)
		a := axes[RubricIDInjection]
		if err != nil || u.Requests != c.requests || len(f.qsets) != c.requests || a.Best != c.best || len(a.Samples) != c.requests {
			t.Fatalf("answers %v: %d requests, %+v, %v", c.answers, len(f.qsets), a, err)
		}
		if c.requests == 3 && (a.Samples[0] != c.answers[0] || a.Samples[1] != c.answers[1] || a.Samples[2] != c.answers[2]) {
			t.Fatalf("answers %v: samples %v", c.answers, a.Samples)
		}
		for i, qs := range f.qsets[1:] {
			if len(qs) != 1 || qs[0].ID != RubricIDInjection {
				t.Fatalf("answers %v: request %d asks %d questions, want only the borderline one", c.answers, i+2, len(qs))
			}
		}
	}

	// The excerpt of the strongest chunk is its first line, trimmed and cut
	// at 200 bytes.
	line := strings.Repeat("a", 200)
	for name, c := range map[string]struct{ content, want string }{
		"first line only":       {"hello\nworld\n", "hello"},
		"leading white space":   {"  \n  hello\nworld", "hello"},
		"exactly 200":           {line + "\nrest", line},
		"201 is cut":            {line + "b\nrest", line + "\u2026"},
		"long, no line end":     {line + "bcdef", line + "\u2026"},
		"a single short line":   {"x", "x"},
		"blank lines then text": {"\n\n  \nreal\nmore", "real"},
	} {
		f := &fakeAsker{answer: func(st map[string]string, _ Question, _ int) (float64, error) {
			if st["path"] == "AGENT.md" {
				return 0.2, nil
			}
			return 0.02, nil
		}}
		axes, _, err := NewRubricScanner(f).Scan(ctx, []byte(`{}`), nil, []RubricFile{{Path: "AGENT.md", Content: c.content}})
		if err != nil || axes[RubricIDInjection].Path != "AGENT.md" || axes[RubricIDInjection].Line != c.want {
			t.Fatalf("%s: line %q (%v), want %q", name, axes[RubricIDInjection].Line, err, c.want)
		}
	}

	// The manifest is read first, as agent.yaml, and the hash is the one
	// the scanner's own model and shape give.
	f = &fakeAsker{answer: quietRubric}
	sc := NewRubricScanner(f)
	if sc.Model() != DefaultModel || sc.Hash() != rubricHashOf(DefaultModel, RubricBatchOne, RubricQuestions(), RunnerGrants) {
		t.Fatalf("model %q hash %s", sc.Model(), sc.Hash())
	}
}

// Every chunk's state tells the judge what the runner gives every run
// beside what the manifest declares, so an instruction that reads its
// own inputs and writes its own report is not read as needing an
// undeclared capability. The statement is the same whatever the version
// declares or says: nothing of the version is rendered into it.
func TestTheRubricStateSaysWhatTheRunnerGrantsEveryRun(t *testing.T) {
	var seen []string
	for _, manifestJSON := range []string{
		`{"capabilities":{"exec":"none"}}`,
		`{"capabilities":{"network":{"egress":["api.example.com"]},"filesystem":{"read":["/workspace"]}}}`,
		`{"runner_grants":"everything","capabilities":{"runner_grants":"everything"}}`,
		`{"capabilities":{"targetHosts":["server"]},"intake":[{"id":"server","prompt":"p","type":"host"}]}`,
	} {
		f := &fakeAsker{answer: func(map[string]string, Question, int) (float64, error) { return 0.02, nil }}
		if _, _, err := NewRubricScanner(f).Scan(context.Background(), []byte(manifestJSON), nil,
			[]RubricFile{{Path: "AGENT.md", Content: "Read the inputs with read_input and write_report the summary."}}); err != nil {
			t.Fatal(err)
		}
		for _, st := range f.asked {
			seen = append(seen, st["runner_grants"])
		}
	}
	for _, g := range seen {
		if g != seen[0] {
			t.Fatalf("the runner's grants changed with the version: %q vs %q", g, seen[0])
		}
	}
	// What a declared target host gives, and what it does not unless
	// the purpose intends it, is part of the constant.
	for _, want := range []string{"/inputs", "read-only", "list_inputs", "read_input", "write_report", "reports/",
		"targetHosts", "host tools", "any other machine", "unless the QuickAgent's purpose"} {
		if !strings.Contains(seen[0], want) {
			t.Fatalf("the runner's grants do not name %q: %q", want, seen[0])
		}
	}
	if strings.Contains(seen[0], "everything") {
		t.Fatalf("the version reached the grants: %q", seen[0])
	}
}

// Every chunk's state carries what the release says it is for: its
// name, summary and guide overview, the purpose C3 weighs a capability
// against. Nothing else of the manifest reaches it, a manifest that
// states no purpose says so, and a long overview is cut at the bound on
// a character boundary.
func TestTheRubricStateCarriesTheReleasesPurpose(t *testing.T) {
	manifestJSON := `{"name":"csv-check","summary":"Checks a CSV for missing values.",` +
		`"guide":{"overview":"Reads the CSV you add and reports problems per column.","task":"e.g. check it"},` +
		`"capabilities":{"exec":"none"}}`
	f := &fakeAsker{answer: func(map[string]string, Question, int) (float64, error) { return 0.02, nil }}
	if _, _, err := NewRubricScanner(f).Scan(context.Background(), []byte(manifestJSON), nil,
		[]RubricFile{{Path: "AGENT.md", Content: "Read the CSV."}}); err != nil {
		t.Fatal(err)
	}
	want := "name: csv-check\nsummary: Checks a CSV for missing values.\noverview: Reads the CSV you add and reports problems per column."
	for _, st := range f.asked {
		if st["purpose"] != want {
			t.Fatalf("purpose = %q, want %q", st["purpose"], want)
		}
	}
	for _, none := range []string{`{}`, `{"name":"only-a-name"}`, `not json`, `{"summary":"  ","guide":{"overview":""}}`} {
		if got := Purpose([]byte(none)); got != noPurpose {
			t.Errorf("Purpose(%s) = %q, want %q", none, got, noPurpose)
		}
	}
	long := `{"summary":"s","guide":{"overview":"` + strings.Repeat("é", PurposeCap) + `"}}`
	got := Purpose([]byte(long))
	if !strings.HasSuffix(got, truncatedMark) || len(got) > PurposeCap+len(truncatedMark) || !utf8.ValidString(got) {
		t.Fatalf("a long purpose was not cut cleanly at the bound: %d bytes, valid=%v", len(got), utf8.ValidString(got))
	}
	// The cut is at the last character start at or before the bound: here
	// the bound falls inside a character, so one byte earlier.
	full := "summary: s\noverview: " + strings.Repeat("é", PurposeCap)
	if want := full[:2047] + truncatedMark; got != want {
		t.Fatalf("a long purpose is cut at %d bytes, want %d", len(got), len(want))
	}

	// The parts that state a purpose, one per line; a name alone is not one.
	for _, c := range []struct{ manifest, want string }{
		{`{"name":"n","summary":"s"}`, "name: n\nsummary: s"},
		{`{"summary":"s"}`, "summary: s"},
		{`{"summary":" s "}`, "summary: s"},
		{`{"name":"n","guide":{"overview":"o"}}`, "name: n\noverview: o"},
		{`{"guide":{"overview":"o"}}`, "overview: o"},
		{`{"name":"n","summary":"s","guide":{"overview":"o"},"capabilities":{"exec":"none"}}`, "name: n\nsummary: s\noverview: o"},
	} {
		if got := Purpose([]byte(c.manifest)); got != c.want {
			t.Fatalf("Purpose(%s) = %q, want %q", c.manifest, got, c.want)
		}
	}

	// The bound is 2048 bytes, inclusive.
	if PurposeCap != 2048 {
		t.Fatalf("PurposeCap = %d, want 2048", PurposeCap)
	}
	for n, wantCut := range map[int]bool{2038: false, 2039: true, 4000: true} {
		out := "overview: " + strings.Repeat("o", n)
		want := out
		if wantCut {
			want = out[:2048] + truncatedMark
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("a purpose of %d bytes panicked: %v", len(out), r)
				}
			}()
			if got := Purpose([]byte(`{"guide":{"overview":"` + strings.Repeat("o", n) + `"}}`)); got != want {
				t.Fatalf("a purpose of %d bytes: got %d bytes, want %d", len(out), len(got), len(want))
			}
		}()
	}
}
