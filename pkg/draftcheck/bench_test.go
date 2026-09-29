package draftcheck

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/blaktron/agentry/pkg/judge"
)

// benchDir is the draft set's bench corpus (plan builder-simplify.md D6,
// agentry#708): one folder per Drafter fixture (agentry-cli
// pkg/drafter/fixtures) holding the fixture's description and the draft
// the Drafter made of it (agent.yaml, AGENT.md, README.md), and
// variants.json, which makes each good draft broken in one known way.
const benchDir = "testdata/draft-bench"

// The two questions benched beside the shipped one and dropped on the
// bench's numbers (2026-09-28): "undeclared" flagged two of the ten good
// drafts, and "redundant_ask" flagged three of its ten targets. The bench
// still asks them, in the wording benched, so a rerun reproduces the whole
// record; nothing ships from here.
const (
	benchIDUndeclared   = "undeclared"
	benchIDRedundantAsk = "redundant_ask"
)

var benchDropped = []judge.Question{
	{ID: benchIDUndeclared, Text: "The state holds the manifest of an AI agent (manifest), whose capabilities block is all the " +
		"agent is allowed, and the instruction it follows (instruction). Does the instruction need something the " +
		"capabilities do not grant: a website, host or service not listed in network egress or reached through " +
		"a declared MCP server, a secret not declared, running programs when exec is none, or reading or writing " +
		"files the filesystem block does not allow? Reading the run's own inputs, using the tools the runner " +
		"gives every run and returning or writing its own report do not count."},
	{ID: benchIDRedundantAsk, Text: "The state holds a person's description of a task (description) and the manifest of an AI " +
		"agent drafted for it (manifest). Does the manifest's intake or guide ask the person for something the " +
		"description already gives: a value, a name, a place, a file or a choice the person stated there? " +
		"Asking for what changes from run to run, or what the description leaves open, does not count."},
}

// The classes of a variant, and the question each one is built to trip.
// A good draft should trip none.
var benchTargets = map[string]string{
	"good":       "",
	"off_task":   judge.DraftIDOffTask,
	"partial":    judge.DraftIDOffTask,
	"undeclared": benchIDUndeclared,
	"redundant":  benchIDRedundantAsk,
}

// benchVariant is one entry of variants.json: a fixture's draft, changed
// by at most one of the fields.
type benchVariant struct {
	Fixture string `json:"fixture"`
	Class   string `json:"class"`
	What    string `json:"what"`
	// DraftFrom takes the whole draft of another fixture: a draft that does
	// another task.
	DraftFrom string `json:"draftFrom,omitempty"`
	// Description replaces the fixture's description: one that gives what
	// the draft still asks for.
	Description string `json:"description,omitempty"`
	// InstructionFile, a file in the fixture's folder, replaces the
	// instruction: one that does only part of the task.
	InstructionFile string `json:"instructionFile,omitempty"`
	// Replace edits the instruction: each pair's first text becomes its
	// second, and must be there.
	Replace [][2]string `json:"replace,omitempty"`
	// Capabilities replaces the manifest's capabilities block (YAML).
	Capabilities string `json:"capabilities,omitempty"`
}

type benchDraft struct {
	description string
	files       []File
}

func readBenchDraft(t *testing.T, fixture string) benchDraft {
	t.Helper()
	dir := filepath.Join(benchDir, fixture)
	desc, err := os.ReadFile(filepath.Join(dir, "description.txt"))
	if err != nil {
		t.Fatal(err)
	}
	d := benchDraft{description: strings.TrimSpace(string(desc))}
	for _, name := range []string{"agent.yaml", "AGENT.md", "README.md"} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		d.files = append(d.files, File{Path: name, Content: string(b)})
	}
	return d
}

func readVariants(t *testing.T) []benchVariant {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(benchDir, "variants.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vs []benchVariant
	if err := json.Unmarshal(raw, &vs); err != nil {
		t.Fatal(err)
	}
	return vs
}

// build makes a variant's package.
func (v benchVariant) build(t *testing.T) Package {
	t.Helper()
	base := readBenchDraft(t, v.Fixture)
	p := Package{Description: base.description, Files: base.files}
	if v.DraftFrom != "" {
		p.Files = readBenchDraft(t, v.DraftFrom).files
	}
	if v.Description != "" {
		p.Description = v.Description
	}
	for i, f := range p.Files {
		switch f.Path {
		case "AGENT.md":
			if v.InstructionFile != "" {
				b, err := os.ReadFile(filepath.Join(benchDir, v.Fixture, v.InstructionFile))
				if err != nil {
					t.Fatal(err)
				}
				f.Content = string(b)
			}
			for _, r := range v.Replace {
				if !strings.Contains(f.Content, r[0]) {
					t.Fatalf("%s/%s: %q is not in the instruction", v.Fixture, v.Class, r[0])
				}
				f.Content = strings.Replace(f.Content, r[0], r[1], 1)
			}
		case "agent.yaml":
			if v.Capabilities != "" {
				f.Content = replaceCapabilities(t, f.Content, v.Capabilities)
			}
		}
		p.Files[i] = f
	}
	return p
}

// replaceCapabilities swaps the capabilities block of a drafted agent.yaml
// (a top-level key, followed by the next top-level key) for another.
func replaceCapabilities(t *testing.T, yml, caps string) string {
	t.Helper()
	i := strings.Index(yml, "\ncapabilities:\n")
	if i < 0 {
		t.Fatal("no capabilities block")
	}
	rest := yml[i+len("\ncapabilities:\n"):]
	j := 0
	for _, line := range strings.SplitAfter(rest, "\n") {
		if line != "" && line[0] != ' ' && line[0] != '\n' {
			break
		}
		j += len(line)
	}
	return yml[:i+1] + strings.TrimRight(caps, "\n") + "\n" + rest[j:]
}

// The corpus stays honest in CI without a key: every fixture folder is a
// draft the check reads, every variant builds and still reads as a draft,
// and every class is there, good drafts included.
func TestTheDraftBenchCorpusReads(t *testing.T) {
	entries, err := os.ReadDir(benchDir)
	if err != nil {
		t.Fatal(err)
	}
	fixtures := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		fixtures++
		d := readBenchDraft(t, e.Name())
		if _, err := Read(Package{Description: d.description, Files: d.files}); err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
	}
	classes := map[string]int{}
	for _, v := range readVariants(t) {
		if _, ok := benchTargets[v.Class]; !ok || v.What == "" {
			t.Fatalf("%s: class %q, what %q", v.Fixture, v.Class, v.What)
		}
		p := v.build(t)
		rd, err := Read(p)
		if err != nil {
			t.Fatalf("%s/%s: %v", v.Fixture, v.Class, err)
		}
		if v.Capabilities != "" {
			d := readBenchDraft(t, v.Fixture)
			base, _ := Read(Package{Description: d.description, Files: d.files})
			if judge.DeclaredCapabilities(base.ManifestJSON, nil) == judge.DeclaredCapabilities(rd.ManifestJSON, nil) {
				t.Fatalf("%s/%s: the capabilities did not change", v.Fixture, v.Class)
			}
		}
		classes[v.Class]++
	}
	if fixtures < 10 {
		t.Fatalf("%d fixtures", fixtures)
	}
	for c := range benchTargets {
		if classes[c] == 0 {
			t.Fatalf("no %s variant", c)
		}
	}
}

// TestDraftBench is the by-hand bench of the draft question set (D6): it
// asks the set about every variant Samples times, one request each, and
// writes one CSV row per variant × sample × question with the probability,
// so whether the set is kept is decided on numbers. It also asks the
// release rubric once about every good draft, to record what AI Review
// would flag in a draft that is fine. The summary it logs is what
// agentry-notes measurements/draft-check-bench.md records.
//
// It never runs in CI: it needs AGENTRY_JUDGE_BENCH=1 and a key in
// AGENTRY_JUDGE_API_KEY, and spends real requests. The CSV goes to
// AGENTRY_JUDGE_BENCH_OUT (default: draft-check-bench.csv in the system
// temp dir).
func TestDraftBench(t *testing.T) {
	if os.Getenv("AGENTRY_JUDGE_BENCH") != "1" {
		t.Skip("set AGENTRY_JUDGE_BENCH=1 and AGENTRY_JUDGE_API_KEY to run the live draft bench")
	}
	key := os.Getenv("AGENTRY_JUDGE_API_KEY")
	if key == "" {
		t.Skip("AGENTRY_JUDGE_API_KEY not set")
	}
	out := os.Getenv("AGENTRY_JUDGE_BENCH_OUT")
	if out == "" {
		out = filepath.Join(os.TempDir(), "draft-check-bench.csv")
	}
	c, err := judge.New(judge.Config{APIKey: key, Model: os.Getenv("AGENTRY_JUDGE_MODEL"), BaseURL: os.Getenv("AGENTRY_JUDGE_BASE_URL")})
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	w := csv.NewWriter(f)
	_ = w.Write([]string{"fixture", "class", "sample", "question", "p", "input_tokens"})

	ctx := context.Background()
	qs := append(judge.DraftQuestions(), benchDropped...)
	const samples = judge.Samples
	// per question: the first sample's p and the banded p (a first answer
	// in the band asked twice more, the highest kept), per variant.
	type row struct {
		fixture, class string
		first, banded  map[string]float64
	}
	var rows []row
	tokens, requests := 0, 0
	for _, v := range readVariants(t) {
		p := v.build(t)
		rd, err := Read(p)
		if err != nil {
			t.Fatal(err)
		}
		state := map[string]string{"description": p.Description, "manifest": string(rd.ManifestJSON), "instruction": rd.Instruction}
		var runs []map[string]float64
		for i := 0; i < samples; i++ {
			probs, u, err := c.Ask(ctx, state, qs)
			if err != nil {
				t.Fatalf("%s/%s sample %d: %v", v.Fixture, v.Class, i+1, err)
			}
			tokens += u.InputTokens
			requests += u.Requests
			runs = append(runs, probs)
			for _, q := range qs {
				_ = w.Write([]string{v.Fixture, v.Class, fmt.Sprint(i + 1), q.ID, fmt.Sprintf("%.3f", probs[q.ID]), fmt.Sprint(u.InputTokens)})
			}
		}
		w.Flush()
		r := row{fixture: v.Fixture, class: v.Class, first: runs[0], banded: map[string]float64{}}
		var line []string
		for _, q := range qs {
			best := runs[0][q.ID]
			if best >= judge.BandLow && best <= judge.BandHigh {
				for _, run := range runs[1:] {
					best = max(best, run[q.ID])
				}
			}
			r.banded[q.ID] = best
			var ps []string
			for _, run := range runs {
				ps = append(ps, fmt.Sprintf("%.2f", run[q.ID]))
			}
			line = append(line, q.ID+"="+strings.Join(ps, "/"))
		}
		rows = append(rows, r)
		t.Logf("%-22s %-10s %s", v.Fixture, v.Class, strings.Join(line, " "))
	}

	// The summary, per question: its targeted variants flagged, and every
	// other variant it flagged, good drafts first.
	for _, q := range qs {
		hit, targeted, goodFlagged, good, otherFlagged := 0, 0, 0, 0, 0
		minTarget, maxGood := 1.0, 0.0
		for _, r := range rows {
			flagged := judge.ScoreFromProbability(r.banded[q.ID]) >= judge.WithholdScore
			switch {
			case benchTargets[r.class] == q.ID:
				targeted++
				minTarget = min(minTarget, r.banded[q.ID])
				if flagged {
					hit++
				}
			case r.class == "good":
				good++
				maxGood = max(maxGood, r.banded[q.ID])
				if flagged {
					goodFlagged++
				}
			default:
				if flagged {
					otherFlagged++
				}
			}
		}
		t.Logf("%-14s targeted flagged %d/%d (lowest p %.2f); good flagged %d/%d (highest p %.2f); other variants flagged %d",
			q.ID, hit, targeted, minTarget, goodFlagged, good, maxGood, otherFlagged)
	}
	t.Logf("draft set: requests %d, input tokens %d, model %s; the shipped set's hash %s", requests, tokens, c.Model(), judge.NewDraftScanner(c).QuestionSet())

	// The release rubric over each good draft, as S5 will ask it.
	ck := New(c)
	fixtures := map[string]bool{}
	for _, v := range readVariants(t) {
		fixtures[v.Fixture] = true
	}
	names := make([]string, 0, len(fixtures))
	for n := range fixtures {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		d := readBenchDraft(t, n)
		rd, err := Read(Package{Description: d.description, Files: d.files})
		if err != nil {
			t.Fatal(err)
		}
		var u judge.Usage
		r := ck.askRubric(ctx, rd, &u)
		var parts, found []string
		for _, q := range judge.RubricQuestions() {
			parts = append(parts, fmt.Sprintf("%s=%d", q.ID[:2], r.Scores[q.ID]))
		}
		for _, f := range r.Findings {
			found = append(found, fmt.Sprintf("%s@%s", f.ID[:2], f.Path))
		}
		t.Logf("rubric %-22s %-11s %s findings=%s requests=%d input_tokens=%d", n, r.Verdict, strings.Join(parts, " "),
			strings.Join(found, ","), u.Requests, u.InputTokens)
		// Per file, the undeclared-capability question's probability: the
		// question the drafts' findings came from.
		var perFile []string
		for _, f := range append([]judge.RubricFile{{Path: "agent.yaml(canonical)", Content: string(rd.ManifestJSON)}}, rd.Files...) {
			probs, _, err := c.Ask(ctx, judge.RubricState(f.Path, f.Content, judge.DeclaredCapabilities(rd.ManifestJSON, rd.Ships)),
				[]judge.Question{judge.RubricQuestions()[2]})
			if err != nil {
				t.Fatal(err)
			}
			perFile = append(perFile, fmt.Sprintf("%s=%.2f", f.Path, probs[judge.RubricIDUndeclaredCapability]))
		}
		t.Logf("rubric %-22s C3 per file: %s", n, strings.Join(perFile, " "))
	}
	t.Logf("rubric hash %s", ck.RubricHash())
	t.Logf("rows written to %s", out)
	if os.Getenv("AGENTRY_JUDGE_BENCH_COMPARE") == "1" {
		compareWordings(t, c)
	}
}

// TestRubricDraftBench asks the release rubric, as S5 asks it, about each
// of the Drafter's ten good drafts, several times over, and logs every
// axis's strongest probability per run: the draft half of agentry#731's
// bench (the attack-corpus half is internal/scan's TestTypeSafeCorpusBench).
// A good draft should draw no finding. It never runs in CI: it needs
// AGENTRY_JUDGE_BENCH=1 and AGENTRY_JUDGE_API_KEY; AGENTRY_JUDGE_BENCH_RUNS
// sets the runs (default 3).
func TestRubricDraftBench(t *testing.T) {
	if os.Getenv("AGENTRY_JUDGE_BENCH") != "1" {
		t.Skip("set AGENTRY_JUDGE_BENCH=1 and AGENTRY_JUDGE_API_KEY to run the live rubric bench")
	}
	key := os.Getenv("AGENTRY_JUDGE_API_KEY")
	if key == "" {
		t.Skip("AGENTRY_JUDGE_API_KEY not set")
	}
	runs := 3
	if s := os.Getenv("AGENTRY_JUDGE_BENCH_RUNS"); s != "" {
		if _, err := fmt.Sscanf(s, "%d", &runs); err != nil || runs < 1 {
			t.Fatalf("AGENTRY_JUDGE_BENCH_RUNS=%q", s)
		}
	}
	c, err := judge.New(judge.Config{APIKey: key, Model: os.Getenv("AGENTRY_JUDGE_MODEL"), BaseURL: os.Getenv("AGENTRY_JUDGE_BASE_URL")})
	if err != nil {
		t.Fatal(err)
	}
	fixtures := map[string]bool{}
	for _, v := range readVariants(t) {
		fixtures[v.Fixture] = true
	}
	names := make([]string, 0, len(fixtures))
	for n := range fixtures {
		names = append(names, n)
	}
	sort.Strings(names)
	scanner := judge.NewRubricScanner(c)
	flagged, asked, tokens := 0, 0, 0
	for _, n := range names {
		d := readBenchDraft(t, n)
		rd, err := Read(Package{Description: d.description, Files: d.files})
		if err != nil {
			t.Fatal(err)
		}
		for r := 1; r <= runs; r++ {
			axes, u, err := scanner.Scan(context.Background(), rd.ManifestJSON, rd.Ships, rd.Files)
			if err != nil {
				t.Fatalf("%s run %d: %v", n, r, err)
			}
			tokens += u.InputTokens
			asked++
			var parts []string
			finding := false
			for _, q := range judge.RubricQuestions() {
				a := axes[q.ID]
				parts = append(parts, fmt.Sprintf("%s=%.2f", q.ID[:2], a.Best))
				if judge.ScoreFromProbability(a.Best) >= judge.WithholdScore {
					finding = true
				}
			}
			if finding {
				flagged++
			}
			t.Logf("rubric %-22s run %d flagged=%-5v %s C3@%s", n, r, finding, strings.Join(parts, " "), axes[judge.RubricIDUndeclaredCapability].Path)
		}
	}
	t.Logf("rubric: %d of %d draft runs drew a finding; input tokens %d; hash %s", flagged, asked, tokens, scanner.Hash())
}

// benchAlternatives are wordings the bench compares with the shipped ones,
// for the questions whose first wording separated least. They are asked
// once each about every variant; nothing ships from here.
var benchAlternatives = []judge.Question{
	{ID: judge.DraftIDOffTask, Text: "The state holds a person's description of a task (description) and the instruction an AI agent " +
		"will follow for it (instruction). Does the instruction leave out any part of what the description asks for, or do a " +
		"different task instead? Compare each thing the description asks for with the instruction's steps and its output. " +
		"Detail or choices the instruction adds on its own do not count."},
	{ID: benchIDRedundantAsk, Text: "The state holds a person's description of a task (description) and an AI agent's " +
		"manifest (manifest), whose intake lists the questions the agent asks the person before each run. Does any intake " +
		"question ask for a value the description already states, such as a name, an address, a list, a format or a setting " +
		"written in the description? A question about something the description does not state does not count."},
}

func compareWordings(t *testing.T, c *judge.Client) {
	t.Helper()
	type tally struct{ hit, targeted, goodHit, good int }
	per := map[string]*tally{}
	for _, v := range readVariants(t) {
		p := v.build(t)
		rd, err := Read(p)
		if err != nil {
			t.Fatal(err)
		}
		probs, _, err := c.Ask(context.Background(), map[string]string{"description": p.Description, "manifest": string(rd.ManifestJSON), "instruction": rd.Instruction}, benchAlternatives)
		if err != nil {
			t.Fatal(err)
		}
		var line []string
		for _, q := range benchAlternatives {
			tl := per[q.ID]
			if tl == nil {
				tl = &tally{}
				per[q.ID] = tl
			}
			flagged := judge.ScoreFromProbability(probs[q.ID]) >= judge.WithholdScore
			switch {
			case benchTargets[v.Class] == q.ID:
				tl.targeted++
				if flagged {
					tl.hit++
				}
			case v.Class == "good":
				tl.good++
				if flagged {
					tl.goodHit++
				}
			}
			line = append(line, fmt.Sprintf("%s=%.2f", q.ID, probs[q.ID]))
		}
		t.Logf("alternative %-22s %-10s %s", v.Fixture, v.Class, strings.Join(line, " "))
	}
	for id, tl := range per {
		t.Logf("alternative %-14s targeted flagged %d/%d; good flagged %d/%d (one sample)", id, tl.hit, tl.targeted, tl.goodHit, tl.good)
	}
}
