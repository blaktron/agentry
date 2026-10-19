package draftcheck

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/blaktron/agentry/pkg/judge"
)

const yml = "schemaVersion: \"2\"\nname: brief\nnamespace: draft\nversion: 0.1.0\nsummary: s\nlicense: Apache-2.0\n" +
	"modes: [autonomous]\nentrypoints:\n  instruction: AGENT.md\n"

// shipsYML is yml with a knowledge block shipping two packs.
const shipsYML = yml + "knowledge:\n  ships:\n    - name: b-pack\n    - name: a-pack\n"

// judgeFake answers both of the check's sets from a function of the state,
// the question id and how many times that question has been asked about
// that path, and records every request.
type judgeFake struct {
	asks   []judgeAsk
	calls  map[string]int
	answer func(state map[string]string, id string, n int) (float64, error)
}

type judgeAsk struct {
	state map[string]string
	ids   []string
}

func (f *judgeFake) Model() string { return "fake-model" }

func (f *judgeFake) Ask(_ context.Context, state map[string]string, qs []judge.Question) (map[string]float64, judge.Usage, error) {
	if f.calls == nil {
		f.calls = map[string]int{}
	}
	a := judgeAsk{state: state}
	for _, q := range qs {
		a.ids = append(a.ids, q.ID)
	}
	f.asks = append(f.asks, a)
	out := make(map[string]float64, len(qs))
	for _, q := range qs {
		key := state["path"] + "|" + q.ID
		n := f.calls[key]
		f.calls[key]++
		p, err := f.answer(state, q.ID, n)
		if err != nil {
			return nil, judge.Usage{Requests: 1}, err
		}
		out[q.ID] = p
	}
	return out, judge.Usage{InputTokens: 10, OutputTokens: 1, Requests: 1}, nil
}

// quietJudge answers every question with a probability that scores 0.
func quietJudge(map[string]string, string, int) (float64, error) { return 0.04, nil }

func TestReadTakesTheManifestTheInstructionAndEveryFileInOrder(t *testing.T) {
	rd, err := Read(Package{Files: []File{
		{Path: "agent.yaml", Content: yml}, {Path: "README.md", Content: "# r"}, {Path: "AGENT.md", Content: "# i"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(rd.ManifestJSON), "{") || !strings.Contains(string(rd.ManifestJSON), `"name":"brief"`) || rd.Ships != nil || rd.Instruction != "# i" {
		t.Fatalf("read: %+v", rd)
	}
	var paths []string
	for _, f := range rd.Files {
		paths = append(paths, f.Path)
	}
	if strings.Join(paths, ",") != "AGENT.md,README.md,agent.yaml" {
		t.Fatalf("files: %v", paths)
	}
	var texts []string
	for _, f := range rd.Files {
		texts = append(texts, f.Content)
	}
	if len(texts) != 3 || texts[0] != "# i" || texts[1] != "# r" || texts[2] != yml {
		t.Fatalf("file texts: %q", texts)
	}

	t.Run("every file is in path order whatever the order it came in", func(t *testing.T) {
		files := []File{{Path: "agent.yaml", Content: yml}}
		want := []string{"AGENT.md", "agent.yaml"}
		for i := 11; i >= 0; i-- {
			files = append(files, File{Path: fmt.Sprintf("k%02d.md", i), Content: "k"})
		}
		files = append(files, File{Path: "AGENT.md", Content: "# i"})
		for i := 0; i < 12; i++ {
			want = append(want, fmt.Sprintf("k%02d.md", i))
		}
		rd, err := Read(Package{Files: files})
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, f := range rd.Files {
			got = append(got, f.Path)
		}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("files: %v", got)
		}
	})

	t.Run("the packs a manifest ships are listed by name", func(t *testing.T) {
		rd, err := Read(Package{Files: []File{{Path: "agent.yaml", Content: shipsYML}, {Path: "AGENT.md", Content: "# i"}}})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Join(rd.Ships, ",") != "a-pack,b-pack" {
			t.Fatalf("ships: %v", rd.Ships)
		}
	})
}

// TestCheckRatesADraftAgainstTheRubric drives Check over a fake judge:
// what it asks, how each answer becomes a finding and a verdict, how an
// unanswered half is kept apart from the other, and that a package it
// will not read is never sent to the judge.
func TestCheckRatesADraftAgainstTheRubric(t *testing.T) {
	// Check asks both halves of AI Review over a fake judge. The rubric is
	// asked about the canonical manifest and then every file, one chunk a
	// request, as S5 asks it; the draft set is asked once over the
	// description, the manifest and the instruction.
	checkPkg := func(instruction, readme string) Package {
		return Package{Description: "A brief of the day's news.", Files: []File{
			{Path: "agent.yaml", Content: shipsYML}, {Path: "AGENT.md", Content: instruction}, {Path: "README.md", Content: readme},
		}}
	}
	rubricIDs := []string{judge.RubricIDInjection, judge.RubricIDExfiltration, judge.RubricIDUndeclaredCapability,
		judge.RubricIDDeception, judge.RubricIDObfuscation, judge.RubricIDDestructive}
	t.Run("Check scores a package, flags a high finding and notes a medium one", func(t *testing.T) {
		f := &judgeFake{answer: func(state map[string]string, id string, _ int) (float64, error) {
			for _, m := range []struct {
				id, marker string
				p          float64
			}{
				{judge.RubricIDInjection, "MARK-INJ", 0.95}, {judge.RubricIDExfiltration, "MARK-EXF", 0.75},
				{judge.RubricIDUndeclaredCapability, "MARK-UND", 0.75}, {judge.RubricIDDestructive, "MARK-DES", 0.95},
			} {
				if id == m.id && strings.Contains(state["content"], m.marker) {
					return m.p, nil
				}
			}
			if id == judge.RubricIDDeception {
				return 0.55, nil // a score of 1: no finding
			}
			if id == judge.DraftIDOffTask && strings.Contains(state["instruction"], "MARK-OFF") {
				return 0.95, nil
			}
			return 0.04, nil
		}}
		ck := New(f)
		pkg := checkPkg("# i\nMARK-UND MARK-OFF `browser_navigate`\n", "MARK-INJ MARK-EXF MARK-DES\n")
		res, err := ck.Check(context.Background(), pkg)
		if err != nil {
			t.Fatal(err)
		}
		if res.Model != "fake-model" || ck.Model() != "fake-model" {
			t.Fatalf("model: %q %q", res.Model, ck.Model())
		}
		if ck.RubricHash() != judge.NewRubricScanner(f).Hash() || ck.QuestionSet() != judge.NewDraftScanner(f).QuestionSet() || ck.RubricHash() == ck.QuestionSet() {
			t.Fatalf("hashes: %q %q", ck.RubricHash(), ck.QuestionSet())
		}
		r := res.Rubric
		if r.Verdict != judge.VerdictFlagged || r.Hash != ck.RubricHash() || r.Failure != "" || r.Err != nil {
			t.Fatalf("rubric: %+v", r)
		}
		wantScores := map[string]int{judge.RubricIDInjection: 3, judge.RubricIDExfiltration: 2, judge.RubricIDUndeclaredCapability: 2,
			judge.RubricIDDeception: 1, judge.RubricIDObfuscation: 0, judge.RubricIDDestructive: 3}
		if len(r.Scores) != len(wantScores) {
			t.Fatalf("scores: %v", r.Scores)
		}
		for id, want := range wantScores {
			if got, ok := r.Scores[id]; !ok || got != want {
				t.Fatalf("score %s: %d %v", id, got, ok)
			}
		}
		wantFindings := []Finding{
			{ID: judge.RubricIDInjection, Score: 3, Path: "README.md", Severity: "high"},
			{ID: judge.RubricIDExfiltration, Score: 2, Path: "README.md", Severity: "medium"},
			{ID: judge.RubricIDUndeclaredCapability, Score: 2, Path: "AGENT.md", Severity: "high"},
			{ID: judge.RubricIDDestructive, Score: 3, Path: "README.md", Severity: "medium"},
		}
		if len(r.Findings) != len(wantFindings) {
			t.Fatalf("findings: %+v", r.Findings)
		}
		for i, w := range wantFindings {
			if r.Findings[i] != w {
				t.Fatalf("finding %d: %+v, want %+v", i, r.Findings[i], w)
			}
		}
		if res.Draft.Verdict != judge.VerdictFlagged || strings.Join(res.Draft.Flagged, ",") != judge.DraftIDOffTask || res.Draft.QuestionSet != ck.QuestionSet() {
			t.Fatalf("draft: %+v", res.Draft)
		}
		if len(res.Ungranted) != 1 || res.Ungranted[0].Tool != "browser_navigate" {
			t.Fatalf("ungranted: %+v", res.Ungranted)
		}
		if res.Usage.Requests != len(f.asks) || res.Usage.InputTokens != 10*len(f.asks) || res.Usage.OutputTokens != len(f.asks) {
			t.Fatalf("usage %+v over %d requests", res.Usage, len(f.asks))
		}

		// What was asked: the rubric's six in one request for the manifest's
		// canonical form first and then each file, and the draft set once.
		rd, err := Read(pkg)
		if err != nil {
			t.Fatal(err)
		}
		first := f.asks[0]
		if strings.Join(first.ids, ",") != strings.Join(rubricIDs, ",") || first.state["path"] != "agent.yaml" || first.state["content"] != string(rd.ManifestJSON) {
			t.Fatalf("first request: %v %q", first.ids, first.state["path"])
		}
		want := judge.DeclaredCapabilities(rd.ManifestJSON, rd.Ships)
		if want == judge.DeclaredCapabilities(rd.ManifestJSON, nil) {
			t.Fatal("the shipped packs are not in the declared capabilities")
		}
		contents := map[string]string{}
		draftAsks := 0
		for _, a := range f.asks {
			if a.state["path"] != "" {
				if a.state["declared_capabilities"] != want {
					t.Fatalf("%s: declared capabilities %q", a.state["path"], a.state["declared_capabilities"])
				}
				if a.state["path"] != "agent.yaml" || a.state["content"] != string(rd.ManifestJSON) {
					contents[a.state["path"]] = a.state["content"]
				}
				continue
			}
			draftAsks++
			if strings.Join(a.ids, ",") != judge.DraftIDOffTask || a.state["description"] != pkg.Description ||
				a.state["manifest"] != string(rd.ManifestJSON) || a.state["instruction"] != rd.Instruction {
				t.Fatalf("draft request: %v %q", a.ids, a.state)
			}
		}
		if draftAsks != 1 || len(contents) != 3 || contents["agent.yaml"] != shipsYML || contents["AGENT.md"] != rd.Instruction || contents["README.md"] != pkg.Files[2].Content {
			t.Fatalf("draft asks %d, files asked %q", draftAsks, contents)
		}
	})

	t.Run("Check passes a draft whose findings are all notes, on the best of a borderline answer's samples", func(t *testing.T) {
		f := &judgeFake{answer: func(state map[string]string, id string, n int) (float64, error) {
			if id == judge.RubricIDExfiltration && strings.Contains(state["content"], "MARK-EXF") {
				if n == 0 {
					return 0.6, nil // a score of 1 alone; the borderline answer is asked twice more
				}
				return 0.75, nil
			}
			return 0.04, nil
		}}
		ck := New(f)
		res, err := ck.Check(context.Background(), checkPkg("# i\n", "MARK-EXF\n"))
		if err != nil {
			t.Fatal(err)
		}
		r := res.Rubric
		if r.Verdict != judge.VerdictPass || len(r.Findings) != 1 || r.Findings[0] != (Finding{ID: judge.RubricIDExfiltration, Score: 2, Path: "README.md", Severity: "medium"}) {
			t.Fatalf("rubric: %+v", r)
		}
		if r.Scores[judge.RubricIDExfiltration] != 2 || r.Scores[judge.RubricIDInjection] != 0 || len(r.Scores) != 6 {
			t.Fatalf("scores: %v", r.Scores)
		}
		if res.Draft.Verdict != judge.VerdictPass || len(res.Ungranted) != 0 {
			t.Fatalf("draft: %+v %+v", res.Draft, res.Ungranted)
		}
		// Four chunks (the manifest and three files), two more asks for the
		// borderline question, and the draft set once: 7 requests.
		if res.Usage != (judge.Usage{InputTokens: 70, OutputTokens: 7, Requests: 7}) || len(f.asks) != 7 {
			t.Fatalf("usage %+v over %d requests", res.Usage, len(f.asks))
		}
	})

	t.Run("Check answers a half the judge cannot answer as not scanned and the other half as asked", func(t *testing.T) {
		for name, c := range map[string]struct {
			fail          func(state map[string]string) error
			rubric, draft judge.Verdict
			rubricFail    string
			draftFail     string
			requests      int
		}{
			"the rubric times out": {func(s map[string]string) error {
				if s["path"] != "" {
					return context.DeadlineExceeded
				}
				return nil
			}, judge.VerdictNotScanned, judge.VerdictPass, judge.FailureTimeout, "", 1},
			"the draft set fails": {func(s map[string]string) error {
				if s["path"] == "" {
					return errors.New("judge: endpoint returned 500")
				}
				return nil
			}, judge.VerdictPass, judge.VerdictNotScanned, "", judge.FailureJudgeError, 5},
			"both fail": {func(map[string]string) error { return errors.New("judge: down") },
				judge.VerdictNotScanned, judge.VerdictNotScanned, judge.FailureJudgeError, judge.FailureJudgeError, 1},
		} {
			f := &judgeFake{}
			f.answer = func(state map[string]string, id string, n int) (float64, error) {
				if err := c.fail(state); err != nil {
					return 0, err
				}
				return quietJudge(state, id, n)
			}
			ck := New(f)
			res, err := ck.Check(context.Background(), checkPkg("# i `browser_navigate`\n", "r\n"))
			if err != nil {
				t.Fatalf("%s: a judge that cannot answer is a verdict, not an error: %v", name, err)
			}
			if res.Rubric.Verdict != c.rubric || res.Draft.Verdict != c.draft || res.Rubric.Failure != c.rubricFail || res.Draft.Failure != c.draftFail {
				t.Fatalf("%s: rubric %+v, draft %+v", name, res.Rubric, res.Draft)
			}
			if res.Rubric.Verdict == judge.VerdictNotScanned && (res.Rubric.Err == nil || len(res.Rubric.Scores) != 0 || len(res.Rubric.Findings) != 0 || res.Rubric.Hash != ck.RubricHash()) {
				t.Fatalf("%s: a rubric not scanned: %+v", name, res.Rubric)
			}
			if res.Rubric.Verdict == judge.VerdictPass && (res.Rubric.Err != nil || len(res.Rubric.Scores) != 6) {
				t.Fatalf("%s: a rubric asked: %+v", name, res.Rubric)
			}
			if name == "the rubric times out" && !errors.Is(res.Rubric.Err, context.DeadlineExceeded) {
				t.Fatalf("%s: err %v", name, res.Rubric.Err)
			}
			if res.Usage.Requests != c.requests {
				t.Fatalf("%s: usage %+v", name, res.Usage)
			}
			if len(res.Ungranted) != 1 || res.Ungranted[0].Tool != "browser_navigate" {
				t.Fatalf("%s: the tools answer needs no judge: %+v", name, res.Ungranted)
			}
		}
	})

	t.Run("Check asks nothing about a package it will not read", func(t *testing.T) {
		f := &judgeFake{answer: quietJudge}
		res, err := New(f).Check(context.Background(), Package{Files: []File{{Path: "AGENT.md", Content: "x"}}})
		if !errors.Is(err, ErrNotADraft) || len(f.asks) != 0 || res.Model != "" || res.Rubric.Verdict != "" {
			t.Fatalf("%v %d %+v", err, len(f.asks), res)
		}
	})
}

func TestReadRefusesWhatIsNotADraftOrPastItsBounds(t *testing.T) {
	good := []File{{Path: "agent.yaml", Content: yml}, {Path: "AGENT.md", Content: "# i"}}
	for name, c := range map[string]struct {
		files    []File
		notDraft bool
		tooLarge bool
		// msg is what the refusal says is wrong; leak is text of the package
		// it must not quote.
		msg  string
		leak string
	}{
		"no agent.yaml":            {[]File{{Path: "AGENT.md", Content: "x"}}, true, false, "it has no agent.yaml", ""},
		"an agent.yaml of nothing": {[]File{{Path: "agent.yaml", Content: "- not a manifest"}, {Path: "AGENT.md", Content: "x"}}, true, false, "its agent.yaml does not parse", ""},
		"an agent.yaml with a field it does not know": {[]File{{Path: "agent.yaml", Content: yml + "zzsecretfield: 1\n"}, {Path: "AGENT.md", Content: "x"}}, true, false,
			"its agent.yaml does not parse", "zzsecretfield"},
		"no instruction":     {good[:1], true, false, "its instruction file is not in the package", ""},
		"an absolute path":   {append(good, File{Path: "/etc/x", Content: "x"}), false, false, "must be relative and clean", ""},
		"a path out":         {append(good, File{Path: "../x", Content: "x"}), false, false, "must be relative and clean", ""},
		"a path of two dots": {append(good, File{Path: "..", Content: "x"}), false, false, "must be relative and clean", ""},
		"an unclean path":    {append(good, File{Path: "a/../b", Content: "x"}), false, false, "must be relative and clean", ""},
		"a path twice":       {append(good, File{Path: "AGENT.md", Content: "x"}), false, false, "named twice", ""},
		"another path twice": {append(good, File{Path: "x.md", Content: "x"}, File{Path: "x.md", Content: "y"}), false, false, "named twice", ""},
		"not UTF-8":          {append(good, File{Path: "x.md", Content: "\xff\xfe"}), false, false, "not UTF-8", ""},
		"past the bytes":     {append(good, File{Path: "x.md", Content: strings.Repeat("x", MaxBytes)}), false, true, "bytes of text, at most", ""},
		"past the files":     {append(good, make([]File, MaxFiles)...), false, true, "files, at most", ""},
	} {
		_, err := Read(Package{Files: c.files})
		if err == nil || errors.Is(err, ErrNotADraft) != c.notDraft || errors.Is(err, ErrTooLarge) != c.tooLarge {
			t.Fatalf("%s: %v", name, err)
		}
		if strings.Contains(err.Error(), "\xff") || strings.Contains(err.Error(), "not a manifest") {
			t.Fatalf("%s: the refusal quotes the package: %v", name, err)
		}
		if !strings.Contains(err.Error(), c.msg) {
			t.Fatalf("%s: the refusal does not say what is wrong (%q): %v", name, c.msg, err)
		}
		if c.leak != "" && strings.Contains(err.Error(), c.leak) {
			t.Fatalf("%s: the refusal quotes the package: %v", name, err)
		}
		for _, f := range c.files {
			if f.Path != "" && f.Path != "agent.yaml" && f.Path != "AGENT.md" && strings.Contains(err.Error(), f.Path) {
				t.Fatalf("%s: the refusal quotes the path %q: %v", name, f.Path, err)
			}
		}
	}

	// The bounds are the figures the check is documented to read: 32 files
	// and 64 KiB of text. A package at a bound is read; one past it is not.
	if limits := [2]int{MaxFiles, MaxBytes}; limits != [2]int{32, 64 << 10} {
		t.Fatalf("bounds: %v", limits)
	}
	t.Run("a package exactly at a bound is read and one past it is refused", func(t *testing.T) {
		withFiles := func(n int) []File {
			files := append([]File(nil), good...)
			for i := len(files); i < n; i++ {
				files = append(files, File{Path: fmt.Sprintf("f%02d.md", i), Content: "x"})
			}
			return files
		}
		if _, err := Read(Package{Files: withFiles(32)}); err != nil {
			t.Fatalf("32 files: %v", err)
		}
		if _, err := Read(Package{Files: withFiles(33)}); !errors.Is(err, ErrTooLarge) {
			t.Fatalf("33 files: %v", err)
		}
		// The text is counted over every file, the manifest's and the
		// instruction's included; the last file is the smallest, so a count
		// of the largest or the last file alone would read all of these.
		withBytes := func(n int) []File {
			pad := 64<<10 - len(yml) - len("# i") + n
			return []File{
				{Path: "pad1.md", Content: strings.Repeat("x", pad/2)}, {Path: "agent.yaml", Content: yml},
				{Path: "pad2.md", Content: strings.Repeat("x", pad-pad/2)}, {Path: "AGENT.md", Content: "# i"},
			}
		}
		if _, err := Read(Package{Files: withBytes(0)}); err != nil {
			t.Fatalf("65536 bytes: %v", err)
		}
		if _, err := Read(Package{Files: withBytes(1)}); !errors.Is(err, ErrTooLarge) {
			t.Fatalf("65537 bytes: %v", err)
		}
	})
}

// Read answers which runner tools the instruction calls for that the
// manifest does not grant, as S6 reads them at publish.
func TestReadListsTheToolsTheManifestDoesNotGrant(t *testing.T) {
	rd, err := Read(Package{Files: []File{
		{Path: "agent.yaml", Content: yml}, {Path: "AGENT.md", Content: "Open the site with `browser_navigate`, then count lines with `run_command`.\nNever call `fetch`.\n"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, x := range rd.Ungranted {
		got = append(got, x.Tool+" "+x.Path)
	}
	if strings.Join(got, ",") != "browser_navigate capabilities.browser,run_command capabilities.exec.commands" {
		t.Fatalf("ungranted: %v", got)
	}
	rd, err = Read(Package{Files: []File{{Path: "agent.yaml", Content: yml}, {Path: "AGENT.md", Content: "Write the brief with write_report.\n"}}})
	if err != nil || len(rd.Ungranted) != 0 {
		t.Fatalf("a draft naming only the runner's own tools: %v %+v", err, rd.Ungranted)
	}
	// A tool the manifest grants is not listed; the one it does not still is.
	rd, err = Read(Package{Files: []File{
		{Path: "agent.yaml", Content: yml + "capabilities:\n  browser:\n    hosts: [example.com]\n"},
		{Path: "AGENT.md", Content: "Open the site with `browser_navigate`, then count lines with `run_command`.\n"},
	}})
	if err != nil || len(rd.Ungranted) != 1 || rd.Ungranted[0].Tool != "run_command" {
		t.Fatalf("a draft naming a granted tool and an ungranted one: %v %+v", err, rd.Ungranted)
	}
}
