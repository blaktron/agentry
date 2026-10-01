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
// (100% recall) and gate unless it is named with the reason it publishes;
// every benign lookalike must be clean of the forbidden family (precision)
// and must not be rejected. This is the
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
	// Manifest is the exact manifest JSON to scan with. Defaults to an empty
	// capability set.
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
		run := func(threshold string) RunResult {
			pol := DefaultBaseline()
			if threshold != "" {
				pol.MaxAutoPublishSeverity = threshold
			}
			return orch.Run(context.Background(), RunParams{
				Input:             in,
				Policy:            pol,
				Public:            true,
				AgentName:         exp.AgentName,
				PopularAgentNames: exp.PopularAgents,
			})
		}
		result := run("")

		got := map[string]bool{}
		for _, f := range result.Findings {
			got[f.Scanner] = true
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
			// Benign must never be rejected (a security doc discussing
			// injection must be publishable).
			if exp.ExpectClean {
				if result.Decision.Outcome == OutcomeRejected {
					t.Errorf("%s: benign lookalike was REJECTED (%s)", e.Name(), result.Decision.Reason)
				}
				return
			}
			// An attack fixture must gate (needs_review or rejected), by
			// outcome, at the baseline (threshold medium since ruleset
			// 0.3.0) and at threshold low (an organization that holds
			// medium), unless it is named below with the reason it
			// publishes with its findings on the page. The lists are exact
			// both ways, so a fixture that changes outcome changes this file.
			for _, th := range []struct {
				name      string
				result    RunResult
				publishes map[string]string
			}{
				{"the baseline", result, corpusPublishesAtMedium},
				{"threshold low", run("low"), corpusPublishesAtLow},
			} {
				published := th.result.Decision.Outcome == OutcomePublish
				why, listed := th.publishes[e.Name()]
				switch {
				case published && !listed:
					t.Errorf("%s: attack fixture AUTO-PUBLISHED at %s (should gate): %s", e.Name(), th.name, th.result.Decision.Reason)
				case !published && listed:
					t.Errorf("%s: listed as publishing at %s (%s) but the gate said %s: take it off the list", e.Name(), th.name, why, th.result.Decision.Outcome)
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

// corpusPublishesAtLow are the attack fixtures threshold low publishes (an
// organization that holds medium; the baseline before ruleset 0.3.0), each
// with its findings on the page (§8.5).
var corpusPublishesAtLow = map[string]string{
	"s3-html-comment":        "a bare HTML comment is low by design",
	"s3-nfc-delta":           "an NFC normalization delta is info",
	"s3-trailing-whitespace": "trailing whitespace is low, at low confidence",
}

// corpusPublishesAtMedium adds what threshold medium, the baseline since
// ruleset 0.3.0 (agentry#773), publishes: the medium
// findings outside undeclared capabilities and attempted injections, which
// the operator chose to publish with their findings shown "for now" (D6 of
// plan scan-and-run-tweaks, agentry#771).
var corpusPublishesAtMedium = func() map[string]string {
	m := map[string]string{
		"incident-clawhavoc":           "S8's publisher velocity is a medium campaign signal",
		"manifest-env-token-plain-key": "S2's token-shaped value in a declared server's env is medium",
		"manifest-env-token-unquoted":  "S2's secret-named env key and token-shaped value are medium",
		"s3-css-hidden":                "S3's CSS-hidden heuristic is medium",
		"s3-data-uri":                  "S3's data URI heuristic is medium",
		"s3-encoded-blob":              "S3's encoded blob heuristic is medium",
		"s3-mixed-script":              "S3's mixed-script heuristic is medium",
		"s3-private-use":               "S3's private-use-area heuristic is medium",
	}
	for k, v := range corpusPublishesAtLow {
		m[k] = v
	}
	return m
}()

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
	ws := t.TempDir()
	copyFixtureContent(t, dir, ws)

	in := Input{
		Dir:          ws,
		ManifestJSON: fixtureManifest(exp.Manifest),
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
		in.PrevArchiveDir = prevWS
		in.PrevManifestJSON = fixtureManifest(prevExp.Manifest)
		in.PrevVersion = prevExp.Version
	}
	return in
}

// fixtureManifest returns the fixture's manifest, or a minimal one with an
// empty capability set so S9's manifest diff stays quiet on prose fixtures.
func fixtureManifest(manifest string) []byte {
	if strings.TrimSpace(manifest) != "" {
		return []byte(manifest)
	}
	return []byte(`{"capabilities":{}}`)
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
