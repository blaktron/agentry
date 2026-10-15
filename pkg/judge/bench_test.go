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
	"time"
)

// benchDir is the model-input bench's corpus: hostile pages, results,
// registry answers and descriptions (instructions in comments, hidden
// text, encoded and invisible payloads, exfiltration through a link,
// fake tool calls) and benign ones (install guides with `curl | bash`,
// API references with example keys, an article that quotes an injection
// to explain it). index.json names each file's class, source and what
// it tests.
const benchDir = "testdata/model-input-bench"

type benchCase struct {
	File   string `json:"file"`
	Class  string `json:"class"`
	Source Source `json:"source"`
	What   string `json:"what"`
}

func readBench(t *testing.T) []benchCase {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(benchDir, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases []benchCase
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	return cases
}

// The corpus stays honest in CI without a key: every file is indexed once,
// every entry names a file, a class and a source the scanner accepts, and
// both classes are there.
func TestTheModelInputBenchCorpusIsIndexed(t *testing.T) {
	cases := readBench(t)
	indexed := map[string]bool{}
	classes := map[string]int{}
	for _, c := range cases {
		if indexed[c.File] {
			t.Fatalf("%s is indexed twice", c.File)
		}
		indexed[c.File] = true
		if c.Class != "hostile" && c.Class != "benign" {
			t.Fatalf("%s: class %q", c.File, c.Class)
		}
		if !strings.HasPrefix(c.File, c.Class+"-") {
			t.Fatalf("%s: the file name must start with its class", c.File)
		}
		if !ValidSource(c.Source) || c.What == "" {
			t.Fatalf("%s: source %q, what %q", c.File, c.Source, c.What)
		}
		if b, err := os.ReadFile(filepath.Join(benchDir, c.File)); err != nil || len(b) == 0 || len(b) > 4*ChunkSize {
			t.Fatalf("%s: %d bytes, %v (a page is at most 32 KiB)", c.File, len(b), err)
		}
		classes[c.Class]++
	}
	entries, err := os.ReadDir(benchDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "index.json" && !indexed[e.Name()] {
			t.Fatalf("%s is in the corpus but not in index.json", e.Name())
		}
	}
	if classes["hostile"] < 10 || classes["benign"] < 10 {
		t.Fatalf("classes: %+v", classes)
	}
}

// TestModelInputBench is the by-hand bench of the model-input question
// set: it scans every case of the corpus with the live Jev Samples
// times, one request per chunk each time, and writes one CSV row per
// case × sample × question with the probability, so the wording and the
// withhold line are chosen on numbers. It logs a summary of the run.
//
// It never runs in CI: it needs AGENTRY_JUDGE_BENCH=1 and a key in
// AGENTRY_JUDGE_API_KEY, and spends real requests. The CSV goes to
// AGENTRY_JUDGE_BENCH_OUT (default: model-input-bench.csv in the system
// temp dir).
func TestModelInputBench(t *testing.T) {
	if os.Getenv("AGENTRY_JUDGE_BENCH") != "1" {
		t.Skip("set AGENTRY_JUDGE_BENCH=1 and AGENTRY_JUDGE_API_KEY to run the live model-input bench")
	}
	key := os.Getenv("AGENTRY_JUDGE_API_KEY")
	if key == "" {
		t.Skip("AGENTRY_JUDGE_API_KEY not set")
	}
	out := os.Getenv("AGENTRY_JUDGE_BENCH_OUT")
	if out == "" {
		out = filepath.Join(os.TempDir(), "model-input-bench.csv")
	}
	c, err := New(Config{APIKey: key, Model: os.Getenv("AGENTRY_JUDGE_MODEL"), BaseURL: os.Getenv("AGENTRY_JUDGE_BASE_URL")})
	if err != nil {
		t.Fatal(err)
	}
	// One sample per scan: the bench draws its own three, and the summary
	// derives both policies (one sample; the band asked twice more) from them.
	s := NewModelInputScanner(c)
	s.resample = false
	const samples = modelInputSamples

	f, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	w := csv.NewWriter(f)
	_ = w.Write([]string{"file", "class", "source", "sample", "question", "p", "verdict", "chunks", "input_tokens", "ms"})

	type tally struct{ single, banded, total int }
	withheld := map[string]*tally{"hostile": {}, "benign": {}}
	var tokens, requests int
	ctx := context.Background()
	for _, bc := range readBench(t) {
		raw, err := os.ReadFile(filepath.Join(benchDir, bc.File))
		if err != nil {
			t.Fatal(err)
		}
		var runs []ScanResult
		for i := 0; i < samples; i++ {
			start := time.Now()
			res := s.Scan(ctx, bc.Source, string(raw))
			ms := time.Since(start).Milliseconds()
			if res.Verdict == VerdictNotScanned {
				t.Fatalf("%s sample %d not scanned: %+v", bc.File, i+1, res.Chunks)
			}
			runs = append(runs, res)
			tokens += res.Usage.InputTokens
			requests += res.Usage.Requests
			for _, q := range ModelInputQuestions() {
				best := 0.0
				for _, ch := range res.Chunks {
					if p := ch.Probabilities[q.ID]; p > best {
						best = p
					}
				}
				_ = w.Write([]string{bc.File, bc.Class, string(bc.Source), fmt.Sprint(i + 1), q.ID, fmt.Sprintf("%.3f", best),
					string(res.Verdict), fmt.Sprint(len(res.Chunks)), fmt.Sprint(res.Usage.InputTokens), fmt.Sprint(ms)})
			}
		}
		w.Flush()
		// The first sample alone, and the gate's policy: a first answer in
		// the band is asked twice more and the highest kept.
		first := runs[0]
		single := first.Verdict == VerdictWithheld
		banded := single
		var line []string
		for _, q := range ModelInputQuestions() {
			p0 := maxProb(first, q.ID)
			best := p0
			if p0 >= modelInputBandLow && p0 <= modelInputBandHigh {
				for _, r := range runs[1:] {
					if p := maxProb(r, q.ID); p > best {
						best = p
					}
				}
			}
			if ScoreFromProbability(best) >= WithholdScore {
				banded = true
			}
			var ps []string
			for _, r := range runs {
				ps = append(ps, fmt.Sprintf("%.2f", maxProb(r, q.ID)))
			}
			line = append(line, q.ID[:3]+"="+strings.Join(ps, "/"))
		}
		tl := withheld[bc.Class]
		tl.total++
		if single {
			tl.single++
		}
		if banded {
			tl.banded++
		}
		t.Logf("%-32s %-7s single=%-5v banded=%-5v %s", bc.File, bc.Class, single, banded, strings.Join(line, " "))
	}
	w.Flush()
	h, b := withheld["hostile"], withheld["benign"]
	t.Logf("hostile withheld: %d/%d (one sample), %d/%d (band asked twice more)", h.single, h.total, h.banded, h.total)
	t.Logf("benign withheld:  %d/%d (one sample), %d/%d (band asked twice more)", b.single, b.total, b.banded, b.total)
	t.Logf("requests %d, input tokens %d, model %s, question set %s", requests, tokens, c.Model(), modelInputHash(c.Model(), true))
	t.Logf("rows written to %s", out)
	if os.Getenv("AGENTRY_JUDGE_BENCH_COMPARE") == "1" {
		compareWithTheRubric(t, c)
	}
}

// compareWithTheRubric asks the gate's own four texts (C1, C2, C4, C5,
// the ones the model-input set re-words) about each case once, as S5
// would with no declared capabilities, so the record can say what the
// re-wording changes.
func compareWithTheRubric(t *testing.T, c *Client) {
	t.Helper()
	var four []Question
	for _, q := range RubricQuestions() {
		switch q.ID {
		case RubricIDInjection, RubricIDExfiltration, RubricIDDeception, RubricIDObfuscation:
			four = append(four, q)
		}
	}
	hit := map[string]int{}
	total := map[string]int{}
	for _, bc := range readBench(t) {
		raw, err := os.ReadFile(filepath.Join(benchDir, bc.File))
		if err != nil {
			t.Fatal(err)
		}
		best := map[string]float64{}
		for _, piece := range Chunk(string(raw), ChunkSize) {
			probs, _, err := c.Ask(context.Background(), map[string]string{"path": bc.File, "content": piece, "declared_capabilities": "{}"}, four)
			if err != nil {
				t.Fatalf("%s: %v", bc.File, err)
			}
			for id, p := range probs {
				if p > best[id] {
					best[id] = p
				}
			}
		}
		flagged := false
		var parts []string
		for _, q := range four {
			parts = append(parts, fmt.Sprintf("%s=%.2f", q.ID[:2], best[q.ID]))
			if ScoreFromProbability(best[q.ID]) >= WithholdScore {
				flagged = true
			}
		}
		total[bc.Class]++
		if flagged {
			hit[bc.Class]++
		}
		t.Logf("rubric %-32s %-7s flagged=%-5v %s", bc.File, bc.Class, flagged, strings.Join(parts, " "))
	}
	t.Logf("rubric wording: hostile flagged %d/%d, benign flagged %d/%d", hit["hostile"], total["hostile"], hit["benign"], total["benign"])
}

func maxProb(r ScanResult, id string) float64 {
	best := 0.0
	for _, ch := range r.Chunks {
		if p := ch.Probabilities[id]; p > best {
			best = p
		}
	}
	return best
}
