package rules

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// corpusDir is the golden corpus at the repo root (§17.3), relative to this
// package.
const corpusDir = "../../testdata/attack-corpus"

// expectation is the parsed expected.yaml of one corpus fixture directory.
type expectation struct {
	// Technique names the technique class the fixture reproduces.
	Technique string `yaml:"technique"`
	// Expect lists rule ids that MUST appear when the fixture is scanned.
	Expect []string `yaml:"expect"`
	// Forbid lists rule ids that MUST NOT appear.
	Forbid []string `yaml:"forbid"`
	// ExpectClean requires the fixture to produce zero findings overall.
	ExpectClean bool `yaml:"expectClean"`
}

// TestCorpus is the golden-corpus gate of §17.3: it walks every fixture
// directory, scans its files with S3 + the shipped S4 bundle, and asserts
// 100% recall on `expect` ids, absence of `forbid` ids, and — for benign
// twins marked expectClean — zero findings at all (precision regression).
func TestCorpus(t *testing.T) {
	bundle := loadShippedBundle(t)

	entries, err := os.ReadDir(corpusDir)
	if err != nil {
		t.Fatalf("reading corpus dir: %v", err)
	}
	ran := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(corpusDir, e.Name())
		t.Run(e.Name(), func(t *testing.T) {
			exp := readExpectation(t, dir)
			findings := Scan(bundle, readFixtureFiles(t, dir))

			got := map[string]bool{}
			var gotIDs []string
			for _, f := range findings {
				if !got[f.RuleID] {
					got[f.RuleID] = true
					gotIDs = append(gotIDs, f.RuleID)
				}
			}
			sort.Strings(gotIDs)

			for _, id := range exp.Expect {
				if !got[id] {
					t.Errorf("recall: expected %s, got %v", id, gotIDs)
				}
			}
			for _, id := range exp.Forbid {
				if got[id] {
					t.Errorf("precision: forbidden %s fired (findings: %v)", id, gotIDs)
				}
			}
			if exp.ExpectClean && len(findings) > 0 {
				t.Errorf("precision: expected zero findings, got %v", gotIDs)
			}
		})
		ran++
	}
	if ran == 0 {
		t.Fatal("no corpus fixtures found")
	}
}

// readExpectation loads and validates a fixture's expected.yaml.
func readExpectation(t *testing.T, dir string) expectation {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "expected.yaml"))
	if err != nil {
		t.Fatalf("fixture %s has no expected.yaml (corpus README requires one): %v", dir, err)
	}
	var exp expectation
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&exp); err != nil {
		t.Fatalf("parsing %s/expected.yaml: %v", dir, err)
	}
	if len(exp.Expect) == 0 && !exp.ExpectClean {
		t.Fatalf("%s/expected.yaml must either expect findings or set expectClean", dir)
	}
	return exp
}

// readFixtureFiles loads every file in a fixture directory except
// expected.yaml, as Scan input.
func readFixtureFiles(t *testing.T, dir string) []File {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	var files []File
	for _, e := range entries {
		if e.IsDir() || e.Name() == "expected.yaml" {
			continue
		}
		content, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("reading %s/%s: %v", dir, e.Name(), err)
		}
		files = append(files, File{Path: e.Name(), Content: content})
	}
	if len(files) == 0 {
		t.Fatalf("fixture %s has no content files", dir)
	}
	return files
}
