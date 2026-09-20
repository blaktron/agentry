package scan

import (
	"context"
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// TestTypeSafeCorpusBench is the by-hand corpus check of the plan
// (judge-jev-provider.md §5, M1): it runs the live Jev provider over the
// attack corpus's S4 fixtures and their benign twins, in each of the three
// request shapes (one request with six questions, two of three, six of
// one), three samples each, and writes one CSV row per fixture × shape ×
// axis with the samples, so the wording of the questions and the shape that
// ships can be chosen on numbers and recorded in the register.
//
// It never runs in CI: it needs AGENTRY_JUDGE_BENCH=1 and a key in
// AGENTRY_JUDGE_API_KEY, spends real requests, and is not a gate. The CSV
// goes to AGENTRY_JUDGE_BENCH_OUT (default: judge-bench.csv in the
// system temp dir); AGENTRY_JUDGE_BENCH_SHAPES narrows the shapes ("1").
func TestTypeSafeCorpusBench(t *testing.T) {
	if os.Getenv("AGENTRY_JUDGE_BENCH") != "1" {
		t.Skip("set AGENTRY_JUDGE_BENCH=1 and AGENTRY_JUDGE_API_KEY to run the live corpus check")
	}
	key := os.Getenv("AGENTRY_JUDGE_API_KEY")
	if key == "" {
		t.Skip("AGENTRY_JUDGE_API_KEY not set")
	}
	out := os.Getenv("AGENTRY_JUDGE_BENCH_OUT")
	if out == "" {
		out = filepath.Join(os.TempDir(), "judge-bench.csv")
	}
	shapes := []int{1, 2, 6}
	if s := os.Getenv("AGENTRY_JUDGE_BENCH_SHAPES"); s != "" {
		shapes = nil
		for _, p := range strings.Split(s, ",") {
			var n int
			if _, err := fmt.Sscanf(strings.TrimSpace(p), "%d", &n); err == nil {
				shapes = append(shapes, n)
			}
		}
	}
	const samples = 3

	entries, err := os.ReadDir(corpusRoot)
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []string
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() && (strings.HasPrefix(n, "s4-") || strings.HasPrefix(n, "incident-") || strings.HasPrefix(n, "script-")) {
			fixtures = append(fixtures, n)
		}
	}
	sort.Strings(fixtures)

	f, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	w := csv.NewWriter(f)
	_ = w.Write([]string{"fixture", "class", "shape", "axis", "s1", "s2", "s3", "max", "requests", "input_tokens", "ms"})

	ctx := context.Background()
	for _, name := range fixtures {
		dir := filepath.Join(corpusRoot, name)
		exp, ok := readCorpusExpectation(t, dir)
		if !ok {
			continue
		}
		class := "attack"
		if exp.ExpectClean || strings.HasSuffix(name, "-benign") || strings.Contains(name, "-benign-") {
			class = "benign"
		}
		content := benchContent(t, dir, exp)
		for _, shape := range shapes {
			j := NewTypeSafeJudge(JudgeConfig{Provider: "typesafe", APIKey: key, Model: os.Getenv("AGENTRY_JUDGE_MODEL"), BaseURL: os.Getenv("AGENTRY_JUDGE_BASE_URL")})
			j.batch = shape
			per := map[JudgeCategory][]float64{}
			var requests, tokens int
			start := time.Now()
			for i := 0; i < samples; i++ {
				axes, usage, err := j.judgeAxes(ctx, content)
				if err != nil {
					t.Fatalf("%s shape %d sample %d: %v", name, shape, i+1, err)
				}
				tokens += usage.PromptTokens
				for _, cat := range AllJudgeCategories() {
					p := 0.0
					if r := axes[cat]; r != nil {
						p = r.best
					}
					per[cat] = append(per[cat], p)
				}
				requests += len(content.Files) + 1
			}
			ms := time.Since(start).Milliseconds()
			for _, cat := range AllJudgeCategories() {
				s := per[cat]
				best := s[0]
				for _, p := range s[1:] {
					if p > best {
						best = p
					}
				}
				_ = w.Write([]string{name, class, fmt.Sprint(shape), string(cat),
					fmt.Sprintf("%.2f", s[0]), fmt.Sprintf("%.2f", s[1]), fmt.Sprintf("%.2f", s[2]), fmt.Sprintf("%.2f", best),
					fmt.Sprint(requests), fmt.Sprint(tokens), fmt.Sprint(ms)})
			}
			w.Flush()
			t.Logf("%-40s %-6s shape=%d C1=%s C3=%s tokens=%d %dms", name, class, shape,
				benchFmt(per[CatInjection]), benchFmt(per[CatUndeclaredCap]), tokens, ms)
		}
	}
	w.Flush()
	t.Logf("rows written to %s", out)
}

// benchContent stages a fixture the way S5 sees it: the manifest and every
// text file.
func benchContent(t *testing.T, dir string, exp corpusExpectation) JudgeContent {
	t.Helper()
	in := stageFixture(t, dir, exp)
	var files []JudgeFile
	_ = filepath.WalkDir(in.Dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(in.Dir, p)
		if rel == "expected.yaml" {
			return nil
		}
		files = append(files, JudgeFile{Path: rel, Content: string(b)})
		return nil
	})
	sort.Slice(files, func(a, b int) bool { return files[a].Path < files[b].Path })
	return JudgeContent{ManifestJSON: in.ManifestJSON, Files: files}
}

func benchFmt(s []float64) string {
	parts := make([]string, len(s))
	for i, p := range s {
		parts[i] = fmt.Sprintf("%.2f", p)
	}
	return strings.Join(parts, "/")
}
