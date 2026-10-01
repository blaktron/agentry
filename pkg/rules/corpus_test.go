package rules

import (
	"io/fs"
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
//
// The same file is read by the pipeline's corpus gate (internal/scan), which
// runs every stage. This package runs only S3 and S4, so it asserts only the
// "S3/" and "S4/" expectations and ignores the rest — a fixture whose expected
// finding is S7's install-script detector has nothing to say here, and
// pretending otherwise would either fail this test or force the corpus to be
// split in two.
type expectation struct {
	// Technique names the technique class the fixture reproduces.
	Technique string `yaml:"technique"`
	// Expect lists finding ids that MUST appear when the fixture is scanned.
	Expect []string `yaml:"expect"`
	// Forbid lists finding ids that MUST NOT appear.
	Forbid []string `yaml:"forbid"`
	// ExpectClean requires the fixture to produce zero S3/S4 findings.
	ExpectClean bool `yaml:"expectClean"`

	// Fields below are pipeline-level fixture context, consumed by
	// internal/scan's corpus gate. They are declared here because the YAML is
	// decoded with KnownFields(true) in both places.
	Incident      string   `yaml:"incident"`
	ExpectOutcome string   `yaml:"expectOutcome"`
	Kind          string   `yaml:"kind"`
	Manifest      string   `yaml:"manifest"`
	Version       string   `yaml:"version"`
	Prev          string   `yaml:"prev"`
	AgentName     string   `yaml:"agentName"`
	Summary       string   `yaml:"summary"`
	PopularAgents []string `yaml:"popularAgents"`
	Publisher     *struct {
		AccountAgeDays  int `yaml:"accountAgeDays"`
		RecentPublishes int `yaml:"recentPublishes"`
	} `yaml:"publisher"`
}

// ruleLevel reports whether an expectation id names a detector this package
// implements.
func ruleLevel(id string) bool {
	return strings.HasPrefix(id, "S3/") || strings.HasPrefix(id, "S4/")
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
				if ruleLevel(id) && !got[id] {
					t.Errorf("recall: expected %s, got %v", id, gotIDs)
				}
			}
			for _, id := range exp.Forbid {
				if ruleLevel(id) && got[id] {
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

// readFixtureFiles loads every file in a fixture directory tree except
// expected.yaml, as Scan input. It recurses: incident fixtures put code under
// src/, and a precision claim that skipped subdirectories would be a claim
// about only part of the package.
func readFixtureFiles(t *testing.T, dir string) []File {
	t.Helper()
	var files []File
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() == "expected.yaml" {
			return err
		}
		content, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		rel, rerr := filepath.Rel(dir, p)
		if rerr != nil {
			return rerr
		}
		files = append(files, File{Path: filepath.ToSlash(rel), Content: content})
		return nil
	})
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	if len(files) == 0 {
		t.Fatalf("fixture %s has no content files", dir)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files
}
