package scan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/blaktron/agentry/pkg/ruleset"
)

// The §17.3 pipeline golden-corpus gate, run through the ORCHESTRATOR (not
// just pkg/rules): every attack fixture must surface its expected finding
// (100% recall) and never auto-publish; every benign lookalike must be clean
// of the forbidden family (precision) and must not be rejected. This is the
// crown-jewel gate — a precision regression fails the build.
//
// Fixtures may carry pipeline context beyond their files: an agent kind, a
// manifest, a version, publisher-behaviour signals, and — for the release-diff
// reproductions — the name of the sibling fixture that plays the PREVIOUS
// published version. A fixture with `prev:` is staged as a pair and run
// through S9's content diff, which is the only way to exercise the
// clean-then-malicious shape the corpus exists to pin down.

type corpusExpectation struct {
	Technique   string   `yaml:"technique"`
	Expect      []string `yaml:"expect"`
	Forbid      []string `yaml:"forbid"`
	ExpectClean bool     `yaml:"expectClean"`

	// Incident names the Appendix A entry this fixture reproduces, when it
	// reproduces one. Documentation only; the corpus README carries the table.
	Incident string `yaml:"incident"`
	// Kind is the agent kind to scan as (default prompt-agent). S6 and S7 only
	// run for code kinds, so a dependency fixture must say `mcp-server`.
	Kind string `yaml:"kind"`
	// Manifest is the exact manifest JSON to scan with. Defaults to an empty
	// capability set for the declared kind.
	Manifest string `yaml:"manifest"`
	// Version and Prev drive S9: Prev names a sibling fixture directory whose
	// content is the previous published version, and the two versions'
	// difference classifies the bump.
	Version string `yaml:"version"`
	Prev    string `yaml:"prev"`
	// AgentName, Summary and PopularAgents feed S8.
	AgentName     string   `yaml:"agentName"`
	Summary       string   `yaml:"summary"`
	PopularAgents []string `yaml:"popularAgents"`
	// Publisher supplies the account-age/velocity context S8 reads. Absent
	// means "no publisher signal", not "a brand-new account".
	Publisher *corpusPublisher `yaml:"publisher"`
}

type corpusPublisher struct {
	AccountAgeDays  int `yaml:"accountAgeDays"`
	RecentPublishes int `yaml:"recentPublishes"`
}

const corpusRoot = "../../testdata/attack-corpus"

func TestAttackCorpusGate(t *testing.T) {
	bundle, err := ruleset.Load()
	if err != nil {
		t.Fatalf("load ruleset: %v", err)
	}
	orch := NewOrchestrator(bundle, StaticProvider{}, nil)

	entries, err := os.ReadDir(corpusRoot)
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}

	var attackCount, benignCount, pairCount int
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(corpusRoot, e.Name())
		exp, ok := readCorpusExpectation(t, dir)
		if !ok {
			continue // not a fixture dir
		}

		in := stageFixture(t, dir, exp)
		// Corpus-shape counters live out here, not inside the subtest: they
		// describe what the corpus CONTAINS, and `-run .../one-fixture` must
		// not make the corpus look empty.
		if exp.Prev != "" {
			pairCount++
		}
		if exp.ExpectClean {
			benignCount++
		} else {
			attackCount++
		}
		result := orch.Run(context.Background(), RunParams{
			Input:             in,
			Policy:            DefaultBaseline(),
			Public:            true,
			AgentName:         exp.AgentName,
			PopularAgentNames: exp.PopularAgents,
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
				if result.Decision.Outcome == OutcomeRejected {
					t.Errorf("%s: benign lookalike was REJECTED (%s)", e.Name(), result.Decision.Reason)
				}
			} else {
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
	if pairCount == 0 {
		t.Fatal("corpus has no release-diff pair: the postmark-mcp shape is unexercised (§17.3)")
	}
	t.Logf("attack-corpus gate: %d attack + %d benign fixtures (%d release-diff pairs) through the orchestrator",
		attackCount, benignCount, pairCount)
}

// readCorpusExpectation loads a fixture's expected.yaml; ok is false for a
// directory that has none (not a fixture).
func readCorpusExpectation(t *testing.T, dir string) (corpusExpectation, bool) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "expected.yaml"))
	if err != nil {
		return corpusExpectation{}, false
	}
	var exp corpusExpectation
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&exp); err != nil {
		t.Fatalf("%s: parse expected: %v", dir, err)
	}
	return exp, true
}

// stageFixture materializes a fixture (and its `prev` twin, when it has one)
// into temp directories and builds the scan Input.
func stageFixture(t *testing.T, dir string, exp corpusExpectation) Input {
	t.Helper()
	kind := exp.Kind
	if kind == "" {
		kind = "prompt-agent"
	}
	ws := t.TempDir()
	copyFixtureContent(t, dir, ws)

	in := Input{
		Dir:          ws,
		ManifestJSON: fixtureManifest(exp.Manifest, kind),
		Kind:         kind,
		Version:      exp.Version,
		Summary:      exp.Summary,
		// -1 means "no publisher context supplied": 0 would read as an account
		// created today, which is itself one of the signals S8 looks for.
		AccountAgeDays: -1,
	}
	if exp.Publisher != nil {
		in.AccountAgeDays = exp.Publisher.AccountAgeDays
		in.RecentPublishCount = exp.Publisher.RecentPublishes
	}
	if exp.Prev != "" {
		prevDir := filepath.Join(corpusRoot, exp.Prev)
		prevExp, ok := readCorpusExpectation(t, prevDir)
		if !ok {
			t.Fatalf("%s: prev fixture %q has no expected.yaml", dir, exp.Prev)
		}
		prevWS := t.TempDir()
		copyFixtureContent(t, prevDir, prevWS)
		prevKind := prevExp.Kind
		if prevKind == "" {
			prevKind = kind
		}
		in.PrevArchiveDir = prevWS
		in.PrevManifestJSON = fixtureManifest(prevExp.Manifest, prevKind)
		in.PrevVersion = prevExp.Version
	}
	return in
}

// fixtureManifest returns the fixture's manifest, or a minimal one for its
// kind so S6/S7/S9 stay quiet on prose fixtures.
func fixtureManifest(manifest, kind string) []byte {
	if strings.TrimSpace(manifest) != "" {
		return []byte(manifest)
	}
	return []byte(`{"kind":"` + kind + `","capabilities":{}}`)
}

// copyFixtureContent copies a fixture's agent content, recursively, excluding
// the test-metadata file.
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
		srcPath := filepath.Join(src, name)
		dstPath := filepath.Join(dst, name)
		if e.IsDir() {
			if err := os.MkdirAll(dstPath, 0o750); err != nil {
				t.Fatal(err)
			}
			copyFixtureContent(t, srcPath, dstPath)
			continue
		}
		data, err := os.ReadFile(srcPath)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dstPath, data, 0o644); err != nil {
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
