package scan_test

// §8.7 rescan sweep: detection improves after publication, so already-published
// versions are re-scanned when a new ruleset ships. A version that newly trips
// a high finding is quarantined and gets an advisory — that is the mechanism
// protecting consumers of an agent that was clean when they installed it.

import (
	"context"
	"testing"

	"github.com/blaktron/agentry/internal/registry"
	"github.com/blaktron/agentry/internal/scan"
)

// laterRulesetProvider is a judge that scores nothing on the first pass and
// finds an injection on the second — standing in for "the ruleset learned
// something after this version was published".
type laterRulesetProvider struct{ armed *bool }

func (laterRulesetProvider) Name() string              { return "later-ruleset" }
func (laterRulesetProvider) RequiresHumanReview() bool { return false }
func (laterRulesetProvider) ModelID() string           { return "" }
func (laterRulesetProvider) InputLimit() int           { return 0 }
func (p laterRulesetProvider) Judge(_ context.Context, _ scan.JudgeContent) (scan.JudgeVerdict, error) {
	v := scan.JudgeVerdict{Scores: map[scan.JudgeCategory]int{}, Excerpts: map[scan.JudgeCategory]string{}, Model: "later-ruleset"}
	if *p.armed {
		v.Scores[scan.CatInjection] = 3
		v.Excerpts[scan.CatInjection] = "detected by the newer ruleset"
	}
	return v, nil
}

func TestRescanSweepQuarantinesAndAdvises(t *testing.T) {
	e := newPipeEnv(t)
	ctx := context.Background()
	u, _ := e.st.Queries().GetUserByID(ctx, e.owner)

	// Publish clean under the "old" ruleset.
	armed := false
	e.pipe.SetOrchestratorForTest(scan.NewOrchestrator(nil, laterRulesetProvider{armed: &armed}, nil))
	v := e.publish("sleeper", "public", map[string]string{
		"agent.yaml": skillManifest(u.Handle, "sleeper", "1.0.0"),
		"README.md":  "# sleeper\nLooks fine today.\n",
		"SKILL.md":   "Summarize the input.\n",
		"LICENSE":    "Apache-2.0\n",
	})
	if v.Status != "published" {
		t.Fatalf("expected published under the old ruleset, got %s", v.Status)
	}

	// A newer ruleset now detects something in the same bytes.
	armed = true
	if err := e.pipe.RescanSweep(ctx); err != nil {
		t.Fatalf("rescan sweep: %v", err)
	}

	after, err := e.st.Queries().GetVersionByID(ctx, v.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Status != string(registry.StatusQuarantined) {
		t.Fatalf("version status after rescan = %s, want quarantined", after.Status)
	}

	// An advisory exists for the agent.
	advisories, err := e.st.Queries().ListAdvisoriesForAgent(ctx, after.AgentID)
	if err != nil {
		t.Fatal(err)
	}
	if len(advisories) == 0 {
		t.Fatal("rescan quarantine did not raise an advisory (§8.7)")
	}
	if advisories[0].Severity != "high" {
		t.Fatalf("advisory severity = %s, want high", advisories[0].Severity)
	}

	// The archive is untouched: a quarantined version still verifies for
	// anyone who already installed it (§5.5 yank/quarantine semantics).
	if after.ArchiveDigest == nil || *after.ArchiveDigest == "" {
		t.Fatal("quarantine cleared the archive digest — installed copies would stop verifying")
	}

	// Resolution excludes it: a range no longer returns a quarantined version.
	if _, err := e.reg.ResolveVersion(ctx, mustAgent(t, e, u.Handle, "sleeper"), "^1.0", "stable"); err == nil {
		t.Fatal("range resolution still returns a quarantined version")
	}
}

func mustAgent(t *testing.T, e *pipeEnv, ns, name string) registry.Agent {
	t.Helper()
	a, err := e.reg.Resolve(context.Background(), ns, name)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// TestRescanSweepLeavesCleanVersionsAlone guards the other direction: a sweep
// must not churn versions that are still clean.
func TestRescanSweepLeavesCleanVersionsAlone(t *testing.T) {
	e := newPipeEnv(t)
	ctx := context.Background()
	u, _ := e.st.Queries().GetUserByID(ctx, e.owner)

	v := e.publish("steady", "public", map[string]string{
		"agent.yaml": skillManifest(u.Handle, "steady", "1.0.0"),
		"README.md":  "# steady\nStill fine.\n",
		"SKILL.md":   "Summarize the input politely.\n",
		"LICENSE":    "Apache-2.0\n",
	})
	if v.Status != "published" {
		t.Fatalf("setup: status %s", v.Status)
	}
	if err := e.pipe.RescanSweep(ctx); err != nil {
		t.Fatalf("rescan sweep: %v", err)
	}
	after, err := e.st.Queries().GetVersionByID(ctx, v.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Status != "published" {
		t.Fatalf("clean version was disturbed by the sweep: %s", after.Status)
	}
}
