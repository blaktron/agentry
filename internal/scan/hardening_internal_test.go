package scan

// Fail-closed hardening: the places where the pipeline used to lose the
// information that something went wrong. These are internal tests because the
// behaviour under test is deliberately not reachable from outside — the point
// is that it can no longer be reached at all.

import (
	"context"
	"errors"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// panickingStage stands in for a scanner that hits a bug on hostile input.
type panickingStage struct{ id string }

func (s panickingStage) ID() string { return s.id }
func (s panickingStage) Run(stageContext, *Input) StageResult {
	panic("index out of range parsing frontmatter")
}

// TestStagePanicKeepsValueAndStack pins that a recovered stage panic carries
// what actually happened. It used to collapse to the constant string "panic in
// stage" with the value and stack discarded — leaving a crash reachable from
// attacker-supplied package content with no way to find it.
func TestStagePanicKeepsValueAndStack(t *testing.T) {
	o := NewOrchestrator(nil, StaticProvider{}, slog.New(slog.DiscardHandler))
	res := o.runStage(stageContext{ctx: context.Background(), log: o.log}, panickingStage{id: "S3S4"}, &Input{})

	if res.Err == nil {
		t.Fatal("a panicking stage produced no error")
	}
	if !strings.Contains(res.Err.Error(), "index out of range parsing frontmatter") {
		t.Fatalf("error %q does not carry the panic value", res.Err)
	}
	if !strings.Contains(res.Err.Error(), "S3S4") {
		t.Fatalf("error %q does not name the stage", res.Err)
	}
	var pe panicError
	if !errors.As(res.Err, &pe) {
		t.Fatalf("error %T is not a panicError", res.Err)
	}
	if len(pe.stack) == 0 {
		t.Fatal("panic recorded no stack")
	}
	if !strings.Contains(string(pe.stack), "scan") {
		t.Fatalf("stack does not look like ours:\n%s", pe.stack)
	}
}

// TestReportDigestFailsLoudly pins that an unserializable report is an error,
// not an empty digest. The digest is the subject of the DSSE attestation
// (§8.8): signing "" asserts nothing while looking exactly like a valid
// attestation, so the run has to end instead.
func TestReportDigestFailsLoudly(t *testing.T) {
	good, err := reportDigest(Report{SchemaVersion: "1"})
	if err != nil {
		t.Fatalf("digest of a plain report: %v", err)
	}
	if !strings.HasPrefix(good, "sha256:") {
		t.Fatalf("digest = %q", good)
	}

	// NaN has no JSON representation; a stage that put one in a finding
	// detail used to silently produce an empty digest.
	bad := Report{
		SchemaVersion: "1",
		Findings: []Finding{{
			Scanner: "S7", Severity: SevLow, Confidence: ConfLow,
			Detail: map[string]any{"score": math.NaN()},
		}},
	}
	digest, err := reportDigest(bad)
	if err == nil {
		t.Fatalf("unserializable report produced digest %q instead of an error", digest)
	}
	if digest != "" {
		t.Fatalf("digest = %q on error, want empty", digest)
	}
}

// TestUnreadableFileBecomesFinding pins that a file S1 cannot read is reported
// rather than treated as an empty one. Silently reading "" meant S3/S4/S5/S6
// all passed over content that would still ship — an unscanned file cleared as
// if it were clean.
func TestUnreadableFileBecomesFinding(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: chmod cannot make a file unreadable")
	}
	dir := t.TempDir()
	readable := filepath.Join(dir, "README.md")
	if err := os.WriteFile(readable, []byte("# fine\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(dir, "SKILL.md")
	if err := os.WriteFile(secret, []byte("instructions the scanner never sees\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(secret, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(secret, 0o600) })

	in := &Input{Dir: dir}
	res := S1Inventory{}.Run(stageContext{ctx: context.Background(), log: slog.New(slog.DiscardHandler)}, in)
	if res.Err != nil {
		t.Fatalf("S1 failed outright: %v", res.Err)
	}
	var found *Finding
	for i := range res.Findings {
		if res.Findings[i].Scanner == "S1/unreadable-file" {
			found = &res.Findings[i]
		}
	}
	if found == nil {
		t.Fatalf("no unreadable-file finding; findings = %+v", res.Findings)
	}
	if found.FilePath != "SKILL.md" {
		t.Fatalf("finding names %q, want SKILL.md", found.FilePath)
	}
	// It has to gate: medium at high confidence routes the version to review.
	if found.Severity != SevMedium || found.Confidence != ConfHigh {
		t.Fatalf("unreadable file finding is %s/%s; it must be able to gate",
			found.Severity, found.Confidence)
	}
}

// TestResumeNeverSkipsInventory pins the one stage that can never be resumed:
// S1 builds the file inventory every other stage reads, so skipping it would
// hand S3–S9 an empty package and clear it.
func TestResumeNeverSkipsInventory(t *testing.T) {
	r := Resume{Skip: map[string]bool{"S1": true, "S2": true}}
	if r.skips("S1") {
		t.Fatal("S1 was skippable; every later stage would see an empty inventory")
	}
	if !r.skips("S2") {
		t.Fatal("S2 was not skipped despite a recorded result")
	}
}

// TestCacheableStagesMatchSpec pins the §8.7 set: the deterministic scanners.
// S5 (the judge) must not be cached — §8.7 re-adjudicates it only on major
// bumps, which is a decision for the sweep, not a cache lookup.
func TestCacheableStagesMatchSpec(t *testing.T) {
	got := map[string]bool{}
	for _, s := range CacheableStages() {
		got[s] = true
	}
	for _, want := range []string{"S2", "S3S4", "S8"} {
		if !got[want] {
			t.Errorf("%s is not cacheable but §8.7 lists it as deterministic", want)
		}
	}
	for _, never := range []string{"S1", "S5", "S9"} {
		if got[never] {
			t.Errorf("%s must never be answered from the results cache", never)
		}
	}
}

// TestRubricHashChangesWithRubric pins §8.4.4's purpose: the hash identifies
// the rubric a verdict came from, so two different rubrics cannot share one.
func TestRubricHashChangesWithRubric(t *testing.T) {
	a := RubricHash("rubric", "v1")
	b := RubricHash("rubric", "v2")
	if a == b {
		t.Fatal("different rubrics hash the same; the recorded hash proves nothing")
	}
	if a != RubricHash("rubric", "v1") {
		t.Fatal("rubric hash is not stable")
	}
	if !strings.HasPrefix(a, "sha256:") {
		t.Fatalf("hash = %q", a)
	}
}
