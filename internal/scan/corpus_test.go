package scan

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/PLACEHOLDER_ORG/agentry/internal/scan/ruleset"
)

// The §17.3 pipeline golden-corpus gate, run through the ORCHESTRATOR (not
// just pkg/rules): every attack fixture must surface its expected finding
// (100% recall) and never auto-publish; every benign lookalike must be clean
// of the forbidden family (precision) and must not be rejected. This is the
// crown-jewel gate — a precision regression fails the build.

type corpusExpectation struct {
	Technique   string   `yaml:"technique"`
	Expect      []string `yaml:"expect"`
	Forbid      []string `yaml:"forbid"`
	ExpectClean bool     `yaml:"expectClean"`
}

func TestAttackCorpusGate(t *testing.T) {
	bundle, err := ruleset.Load()
	if err != nil {
		t.Fatalf("load ruleset: %v", err)
	}
	orch := NewOrchestrator(bundle, StaticProvider{}, nil)

	root := "../../testdata/attack-corpus"
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}

	var attackCount, benignCount int
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(root, e.Name())
		expPath := filepath.Join(dir, "expected.yaml")
		raw, err := os.ReadFile(expPath)
		if err != nil {
			continue // not a fixture dir
		}
		var exp corpusExpectation
		if err := yaml.Unmarshal(raw, &exp); err != nil {
			t.Fatalf("%s: parse expected: %v", e.Name(), err)
		}

		// Stage the fixture's content files (exclude the test metadata).
		ws := t.TempDir()
		copyFixtureContent(t, dir, ws)

		// Minimal manifest so S6/S7/S9 stay quiet on prose fixtures.
		manifest := []byte(`{"kind":"prompt-agent","capabilities":{}}`)
		result := orch.Run(context.Background(), RunParams{
			Input:  Input{Dir: ws, ManifestJSON: manifest, Kind: "prompt-agent"},
			Policy: DefaultBaseline(),
			Public: true,
		})

		got := map[string]bool{}
		worst := SevInfo
		for _, f := range result.Findings {
			got[f.Scanner] = true
			if confidenceRank(f.Confidence) >= confidenceRank(ConfMedium) && severityRank(f.Severity) > severityRank(worst) {
				worst = f.Severity
			}
		}

		t.Run(e.Name(), func(t *testing.T) {
			// Recall: every expected finding must be present.
			for _, want := range exp.Expect {
				if !got[want] {
					t.Errorf("%s: MISSING expected finding %q (got %v)", e.Name(), want, keys(got))
				}
			}
			// Precision: forbidden findings must be absent.
			for _, forbid := range exp.Forbid {
				if got[forbid] {
					t.Errorf("%s: FALSE POSITIVE %q on benign lookalike", e.Name(), forbid)
				}
			}
			// Attack fixtures must never auto-publish; benign must never be
			// rejected (a security doc discussing injection must be publishable).
			if exp.ExpectClean {
				benignCount++
				if result.Decision.Outcome == OutcomeRejected {
					t.Errorf("%s: benign lookalike was REJECTED (%s)", e.Name(), result.Decision.Reason)
				}
			} else {
				attackCount++
				// A medium+ attack must gate (needs_review or rejected).
				// Low/info-by-design techniques (trailing whitespace, NFC
				// deltas, bare HTML comments) legitimately auto-publish with
				// findings visible on the page (§8.5) — recall above is what
				// the corpus enforces for those.
				if severityRank(worst) >= severityRank(SevMedium) && result.Decision.Outcome == OutcomePublish {
					t.Errorf("%s: medium+ attack fixture AUTO-PUBLISHED (should gate): worst=%s", e.Name(), worst)
				}
			}
		})
	}
	if attackCount == 0 || benignCount == 0 {
		t.Fatalf("corpus too small: %d attack, %d benign", attackCount, benignCount)
	}
	t.Logf("attack-corpus gate: %d attack + %d benign fixtures through the orchestrator", attackCount, benignCount)
}

// copyFixtureContent copies everything except the test-metadata files.
func copyFixtureContent(t *testing.T, src, dst string) {
	t.Helper()
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		name := e.Name()
		// expected.yaml is test metadata; every other file (including the
		// fixture's readme.md, which carries the payload) is agent content.
		if name == "expected.yaml" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(src, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
