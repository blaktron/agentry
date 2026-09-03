package redteam

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/blaktron/agentry/pkg/rules"
)

// DefaultCorpusDirs are tried in order when no corpus directory is
// configured: the image ships the corpus at the first, a source checkout
// has it at the second.
var DefaultCorpusDirs = []string{"/srv/agentry/attack-corpus", "testdata/attack-corpus"}

// FindCorpus resolves the corpus directory.
func FindCorpus(configured string) (string, error) {
	cands := DefaultCorpusDirs
	if configured != "" {
		cands = []string{configured}
	}
	for _, d := range cands {
		if fi, err := os.Stat(d); err == nil && fi.IsDir() {
			return d, nil
		}
	}
	return "", fmt.Errorf("redteam: attack corpus not found (tried %s)", strings.Join(cands, ", "))
}

// Report is one run's outcome.
type Report struct {
	RulesetSemver string `json:"rulesetSemver"`
	BundleDigest  string `json:"bundleDigest"`
	CorpusDir     string `json:"corpusDir"`
	StartedAt     string `json:"startedAt"`
	DurationMs    int64  `json:"durationMs"`
	// Fixtures is the number of attack fixtures with S3/S4 expectations.
	Fixtures int `json:"fixtures"`
	// Cases is fixtures × applicable mutators; Evaded counts cases where at
	// least one expected rule stopped firing.
	Cases  int `json:"cases"`
	Evaded int `json:"evaded"`
	// ByMutator summarizes per rewrite.
	ByMutator []MutatorSummary `json:"byMutator"`
	// Evasions lists every evaded case (what to look at first).
	Evasions []Evasion `json:"evasions"`
}

// MutatorSummary is the per-mutator tally.
type MutatorSummary struct {
	Mutator string `json:"mutator"`
	Family  string `json:"family"`
	Cases   int    `json:"cases"`
	Evaded  int    `json:"evaded"`
}

// Evasion is one rewrite an expected rule no longer catches.
type Evasion struct {
	Fixture   string   `json:"fixture"`
	Technique string   `json:"technique,omitempty"`
	Mutator   string   `json:"mutator"`
	Missing   []string `json:"missing"`
	Fired     []string `json:"fired"`
}

// expectation is the corpus expected.yaml subset this package needs; the
// file is decoded loosely because the pipeline's own gate owns its schema.
type expectation struct {
	Technique string   `yaml:"technique"`
	Expect    []string `yaml:"expect"`
}

// Run scans every attack fixture's rewrites with bundle and reports.
func Run(bundle *rules.Bundle, corpusDir string) (*Report, error) {
	start := time.Now()
	rep := &Report{CorpusDir: corpusDir, StartedAt: start.UTC().Format(time.RFC3339)}
	if bundle != nil {
		rep.RulesetSemver = bundle.Version()
		rep.BundleDigest = bundle.Digest()
	}
	entries, err := os.ReadDir(corpusDir)
	if err != nil {
		return nil, err
	}
	muts := Mutators()
	tally := make([]MutatorSummary, len(muts))
	for i, m := range muts {
		tally[i] = MutatorSummary{Mutator: m.Name, Family: m.Family}
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(corpusDir, e.Name())
		exp, ok := readExpectation(dir)
		if !ok {
			continue
		}
		want := ruleLevel(exp.Expect)
		if len(want) == 0 {
			continue
		}
		files, err := readFiles(dir)
		if err != nil {
			return nil, err
		}
		// Sanity: the unmutated fixture must fire (the corpus gate pins
		// this); a fixture that does not is reported once, not per mutator.
		if missing := missingIDs(want, rules.Scan(bundle, files)); len(missing) > 0 {
			rep.Evasions = append(rep.Evasions, Evasion{Fixture: e.Name(), Technique: exp.Technique, Mutator: "(unmutated)", Missing: missing})
			continue
		}
		rep.Fixtures++
		for i, m := range muts {
			mutated, applied := mutateFiles(files, m)
			if !applied {
				continue
			}
			rep.Cases++
			tally[i].Cases++
			findings := rules.Scan(bundle, mutated)
			if missing := missingIDs(want, findings); len(missing) > 0 {
				rep.Evaded++
				tally[i].Evaded++
				rep.Evasions = append(rep.Evasions, Evasion{
					Fixture: e.Name(), Technique: exp.Technique, Mutator: m.Name,
					Missing: missing, Fired: ids(findings),
				})
			}
		}
	}
	rep.ByMutator = tally
	sort.Slice(rep.Evasions, func(i, j int) bool {
		if rep.Evasions[i].Fixture != rep.Evasions[j].Fixture {
			return rep.Evasions[i].Fixture < rep.Evasions[j].Fixture
		}
		return rep.Evasions[i].Mutator < rep.Evasions[j].Mutator
	})
	rep.DurationMs = time.Since(start).Milliseconds()
	return rep, nil
}

func readExpectation(dir string) (expectation, bool) {
	raw, err := os.ReadFile(filepath.Join(dir, "expected.yaml")) //nolint:gosec // corpus path
	if err != nil {
		return expectation{}, false
	}
	var exp expectation
	if err := yaml.Unmarshal(raw, &exp); err != nil {
		return expectation{}, false
	}
	return exp, true
}

// ruleLevel keeps the S3/S4 ids — the only stages pkg/rules runs.
func ruleLevel(idsIn []string) []string {
	var out []string
	for _, id := range idsIn {
		if strings.HasPrefix(id, "S3/") || strings.HasPrefix(id, "S4/") {
			out = append(out, id)
		}
	}
	return out
}

func readFiles(dir string) ([]rules.File, error) {
	var files []rules.File
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() == "expected.yaml" {
			return err
		}
		b, rerr := os.ReadFile(p) //nolint:gosec // corpus path
		if rerr != nil {
			return rerr
		}
		rel, _ := filepath.Rel(dir, p)
		files = append(files, rules.File{Path: filepath.ToSlash(rel), Content: b})
		return nil
	})
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, err
}

// mutateFiles applies m to the prose files (the ones S4 reads); the rest
// pass through unchanged.
func mutateFiles(files []rules.File, m Mutator) ([]rules.File, bool) {
	out := make([]rules.File, len(files))
	applied := false
	for i, f := range files {
		out[i] = f
		ext := strings.ToLower(filepath.Ext(f.Path))
		if ext != ".md" && ext != ".txt" && ext != ".markdown" {
			continue
		}
		if s, ok := m.Apply(string(f.Content)); ok {
			out[i] = rules.File{Path: f.Path, Content: []byte(s)}
			applied = true
		}
	}
	return out, applied
}

func ids(findings []rules.Finding) []string {
	set := map[string]bool{}
	for _, f := range findings {
		set[f.RuleID] = true
	}
	out := make([]string, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func missingIDs(want []string, findings []rules.Finding) []string {
	got := map[string]bool{}
	for _, f := range findings {
		got[f.RuleID] = true
	}
	var missing []string
	for _, id := range want {
		if !got[id] {
			missing = append(missing, id)
		}
	}
	return missing
}
