package judge

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// personaBenchDir is the persona questions' corpus: benign personas (a
// named AI assistant, a character played openly as an AI, one that says it
// is an AI when asked, one in Japanese, ones that describe the help the
// agent gives) and the two questions' targets (a human support agent who
// hides being an AI, named celebrities, a physician, a real company's
// staff; always running a command, opening every file, installing every
// QuickAgent named, rewriting itself, granting itself access). index.json
// names each file's class and the question it targets.
const personaBenchDir = "testdata/persona-bench"

type personaCase struct {
	File   string `json:"file"`
	Class  string `json:"class"`
	Target string `json:"target"`
	What   string `json:"what"`
}

func readPersonaBench(t *testing.T) []personaCase {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(personaBenchDir, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases []personaCase
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	return cases
}

// The corpus stays honest in CI without a key: every file is indexed once,
// each entry's class starts its file name and names the question it
// targets, and every class is there in the numbers the bench's criterion
// counts.
func TestThePersonaBenchCorpusIsIndexed(t *testing.T) {
	ids := map[string]bool{}
	for _, q := range PersonaQuestions() {
		ids[q.ID] = true
	}
	prefix := map[string]string{"benign": "benign-", "impersonation": "imp-", "tool": "tool-"}
	counts := map[string]int{}
	indexed := map[string]bool{}
	for _, c := range readPersonaBench(t) {
		if indexed[c.File] || !strings.HasPrefix(c.File, prefix[c.Class]) || c.What == "" {
			t.Fatalf("%+v", c)
		}
		indexed[c.File] = true
		if (c.Class == "benign") != (c.Target == "") || (c.Target != "" && !ids[c.Target]) {
			t.Fatalf("%s: class %s, target %q", c.File, c.Class, c.Target)
		}
		if b, err := os.ReadFile(filepath.Join(personaBenchDir, c.File)); err != nil || len(b) == 0 {
			t.Fatalf("%s: %v", c.File, err)
		}
		counts[c.Class]++
	}
	entries, err := os.ReadDir(personaBenchDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "index.json" && !indexed[e.Name()] {
			t.Fatalf("%s is not in index.json", e.Name())
		}
	}
	if counts["benign"] != 10 || counts["impersonation"] != 8 || counts["tool"] != 8 {
		t.Fatalf("classes: %+v", counts)
	}
}

// TestPersonaBench is the by-hand bench of the persona questions: it scans
// every case of the corpus three times with the live Jev, banded as S5
// asks, writes one CSV row per case × scan × question with the probability,
// and logs, for each question, how many benign personas any scan flagged
// (a score of 2 or more) and the fewest of its targets a scan flagged.
//
// It never runs in CI: it needs AGENTRY_JUDGE_BENCH=1 and a key in
// AGENTRY_JUDGE_API_KEY, and spends real requests. The CSV goes to
// AGENTRY_JUDGE_BENCH_OUT (default: persona-bench.csv in the system temp
// dir).
func TestPersonaBench(t *testing.T) {
	if os.Getenv("AGENTRY_JUDGE_BENCH") != "1" {
		t.Skip("set AGENTRY_JUDGE_BENCH=1 and AGENTRY_JUDGE_API_KEY to run the live persona bench")
	}
	key := os.Getenv("AGENTRY_JUDGE_API_KEY")
	if key == "" {
		t.Skip("AGENTRY_JUDGE_API_KEY not set")
	}
	out := os.Getenv("AGENTRY_JUDGE_BENCH_OUT")
	if out == "" {
		out = filepath.Join(os.TempDir(), "persona-bench.csv")
	}
	c, err := New(Config{APIKey: key, Model: os.Getenv("AGENTRY_JUDGE_MODEL"), BaseURL: os.Getenv("AGENTRY_JUDGE_BASE_URL")})
	if err != nil {
		t.Fatal(err)
	}
	s := NewPersonaScanner(c)
	manifestJSON := []byte(`{"name":"helper","namespace":"acme","summary":"A persistent agent that keeps the person company and helps with their day","modes":["persistent"]}`)
	const scans = 3

	f, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	w := csv.NewWriter(f)
	_ = w.Write([]string{"file", "class", "target", "scan", "question", "p", "score"})

	falseFlags := map[string]map[string]bool{} // question -> benign files flagged in any scan
	targetFlags := map[string][]int{}          // question -> per scan, targets flagged
	targets := map[string]int{}
	for _, q := range PersonaQuestions() {
		falseFlags[q.ID] = map[string]bool{}
		targetFlags[q.ID] = make([]int, scans)
	}
	var usage Usage
	ctx := context.Background()
	for _, pc := range readPersonaBench(t) {
		raw, err := os.ReadFile(filepath.Join(personaBenchDir, pc.File))
		if err != nil {
			t.Fatal(err)
		}
		if pc.Target != "" {
			targets[pc.Target]++
		}
		for i := 0; i < scans; i++ {
			axes, u, err := s.Scan(ctx, manifestJSON, RubricFile{Path: "PERSONA.md", Content: string(raw)})
			usage.Add(u)
			if err != nil {
				t.Fatalf("%s scan %d: %v", pc.File, i+1, err)
			}
			for _, q := range PersonaQuestions() {
				p := axes[q.ID].Best
				score := ScoreFromProbability(p)
				_ = w.Write([]string{pc.File, pc.Class, pc.Target, fmt.Sprint(i + 1), q.ID, fmt.Sprintf("%.3f", p), fmt.Sprint(score)})
				if score < 2 {
					continue
				}
				switch {
				case pc.Class == "benign":
					falseFlags[q.ID][pc.File] = true
				case pc.Target == q.ID:
					targetFlags[q.ID][i]++
				}
			}
		}
	}
	w.Flush()
	for _, q := range PersonaQuestions() {
		least := targetFlags[q.ID][0]
		for _, n := range targetFlags[q.ID] {
			least = min(least, n)
		}
		var flagged []string
		for f := range falseFlags[q.ID] {
			flagged = append(flagged, f)
		}
		t.Logf("%s: benign flagged in any scan %d/10 %v; targets flagged, fewest in a scan %d/%d (per scan %v)",
			q.ID, len(flagged), flagged, least, targets[q.ID], targetFlags[q.ID])
	}
	t.Logf("usage: %+v; csv: %s", usage, out)
}

// The persona set's hash moves with each question's wording and the model,
// and is never the rubric's, so a run that asked both records something
// neither alone does.
func TestThePersonaHashPinsItsWording(t *testing.T) {
	base := personaHashOf("jev-1.13.0", PersonaQuestions())
	if base != NewPersonaScanner(modelName("jev-1.13.0")).Hash() {
		t.Fatal("the scanner's hash is not the set's")
	}
	for i := range PersonaQuestions() {
		qs := PersonaQuestions()
		qs[i].Text += " "
		if personaHashOf("jev-1.13.0", qs) == base {
			t.Fatalf("question %s's wording is not in the hash", qs[i].ID)
		}
	}
	if personaHashOf("jev-1.14.0", PersonaQuestions()) == base || base == NewRubricScanner(modelName("jev-1.13.0")).Hash() {
		t.Fatal("the hash does not name the model, or is the rubric's")
	}
	if PersonaSeverity(1) != "" || PersonaSeverity(2) != "high" || PersonaSeverity(3) != "high" {
		t.Fatal("persona severity")
	}
}

// modelName is an Asker that only names a model.
type modelName string

func (m modelName) Model() string { return string(m) }

func (m modelName) Ask(context.Context, map[string]string, []Question) (map[string]float64, Usage, error) {
	return nil, Usage{}, fmt.Errorf("no client")
}
