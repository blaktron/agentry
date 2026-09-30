package scan_test

// §8.7 rescan sweep: detection improves after publication, so already-published
// versions are re-scanned when a new ruleset ships. A version that newly trips
// a high finding is quarantined and gets an advisory — that is the mechanism
// protecting consumers of an agent that was clean when they installed it.

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/audit"
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

// scoredProvider is a judge whose scores the test sets between passes.
type scoredProvider struct {
	scores *map[scan.JudgeCategory]int
}

func (scoredProvider) Name() string              { return "scored" }
func (scoredProvider) RequiresHumanReview() bool { return false }
func (scoredProvider) ModelID() string           { return "" }
func (scoredProvider) InputLimit() int           { return 0 }
func (p scoredProvider) Judge(_ context.Context, _ scan.JudgeContent) (scan.JudgeVerdict, error) {
	v := scan.JudgeVerdict{Scores: map[scan.JudgeCategory]int{}, Excerpts: map[scan.JudgeCategory]string{}, Model: "scored"}
	for c, s := range *p.scores {
		v.Scores[c] = s
	}
	return v, nil
}

// approve decides the version's pending review item as a person would.
func approve(t *testing.T, e *pipeEnv, versionID uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	item, err := e.st.Queries().GetPendingReviewItemForVersion(ctx, versionID)
	if err != nil {
		t.Fatalf("no pending review item: %v", err)
	}
	reviewer := e.seedUser("rev" + suffix())
	if _, err := e.pipe.DecideReview(ctx, scan.ReviewDecision{
		ItemID: item.ID, VersionID: versionID, Target: registry.StatusPublished,
		State: "approved", Rationale: "read the finding, fine to ship",
		DecidedBy: reviewer, Audit: audit.Event{Actor: reviewer, ActorKind: audit.ActorUser},
	}); err != nil {
		t.Fatalf("approve: %v", err)
	}
}

func statusOf(t *testing.T, e *pipeEnv, versionID uuid.UUID) string {
	t.Helper()
	v, err := e.st.Queries().GetVersionByID(context.Background(), versionID)
	if err != nil {
		t.Fatal(err)
	}
	return v.Status
}

// TestRescanSweepLeavesWhatAReviewerApproved pins agentry#781: the sweep
// runs on every new ruleset, and a finding a person already decided on must
// not quarantine the version again, whether it was high when they saw it or
// a new ruleset re-rated it to high since. A finding the person never saw
// still quarantines.
func TestRescanSweepLeavesWhatAReviewerApproved(t *testing.T) {
	cases := []struct {
		name          string
		before, after map[scan.JudgeCategory]int
		want          registry.Status
	}{
		{"approved with a high finding", map[scan.JudgeCategory]int{scan.CatInjection: 3},
			map[scan.JudgeCategory]int{scan.CatInjection: 3}, registry.StatusPublished},
		{"approved with a medium a new ruleset rates high", map[scan.JudgeCategory]int{scan.CatDeception: 2},
			map[scan.JudgeCategory]int{scan.CatDeception: 3}, registry.StatusPublished},
		{"approved with one finding, rescanned with a new high", map[scan.JudgeCategory]int{scan.CatDeception: 2},
			map[scan.JudgeCategory]int{scan.CatDeception: 2, scan.CatInjection: 3}, registry.StatusQuarantined},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newPipeEnv(t)
			u, _ := e.st.Queries().GetUserByID(context.Background(), e.owner)
			scores := tc.before
			e.pipe.SetOrchestratorForTest(scan.NewOrchestrator(nil, scoredProvider{scores: &scores}, nil))
			name := "reviewed" + suffix()
			v := e.publish(name, "public", benignFiles(u.Handle, name, "1.0.0"))
			if v.Status != "needs_review" {
				t.Fatalf("setup: status %s, want needs_review", v.Status)
			}
			approve(t, e, v.ID)

			scores = tc.after
			if err := e.pipe.RescanSweep(context.Background()); err != nil {
				t.Fatalf("rescan sweep: %v", err)
			}
			if got := statusOf(t, e, v.ID); got != string(tc.want) {
				t.Fatalf("status after the sweep = %s, want %s", got, tc.want)
			}
		})
	}
}

// TestRescanSweepDoesNotRequarantineAClearedVersion: a reviewer who clears
// a quarantine has decided on its finding; the next ruleset's sweep leaves
// the version published (agentry#781).
func TestRescanSweepDoesNotRequarantineAClearedVersion(t *testing.T) {
	e := newPipeEnv(t)
	ctx := context.Background()
	u, _ := e.st.Queries().GetUserByID(ctx, e.owner)
	armed := false
	e.pipe.SetOrchestratorForTest(scan.NewOrchestrator(nil, laterRulesetProvider{armed: &armed}, nil))
	v := e.publish("cleared", "public", benignFiles(u.Handle, "cleared", "1.0.0"))
	if v.Status != "published" {
		t.Fatalf("setup: status %s", v.Status)
	}
	armed = true
	if err := e.pipe.RescanSweep(ctx); err != nil {
		t.Fatalf("first sweep: %v", err)
	}
	if got := statusOf(t, e, v.ID); got != string(registry.StatusQuarantined) {
		t.Fatalf("first sweep left %s, want quarantined", got)
	}
	approve(t, e, v.ID)
	if err := e.pipe.RescanSweep(ctx); err != nil {
		t.Fatalf("second sweep: %v", err)
	}
	if got := statusOf(t, e, v.ID); got != string(registry.StatusPublished) {
		t.Fatalf("second sweep left %s, want published", got)
	}
}

// TestRescanSweepLeavesAnOrgApprovedRerating pins the operator's decision of
// 2026-09-30 (agentry#781): a public agent an organization's reviewer
// approved with a medium finding stays published when a new ruleset rates
// that finding high, although a high on a public agent would go to the
// platform queue at submission. A re-rating never pulls an approved version.
func TestRescanSweepLeavesAnOrgApprovedRerating(t *testing.T) {
	e := newPipeEnv(t)
	org := e.seedOrg("rerate" + suffix())
	scores := map[scan.JudgeCategory]int{scan.CatUndeclaredCap: 2}
	e.pipe.SetOrchestratorForTest(scan.NewOrchestrator(nil, scoredProvider{scores: &scores}, nil))
	v := e.publishOrg(org, "rerated", "public", benignFiles(org.handle, "rerated", "1.0.0"))
	if v.Status != "needs_review" {
		t.Fatalf("setup: status %s, want needs_review", v.Status)
	}
	item, err := e.st.Queries().GetPendingReviewItemForVersion(context.Background(), v.ID)
	if err != nil || item.Queue != "org" {
		t.Fatalf("setup: review item %+v (%v), want the org queue", item, err)
	}
	approve(t, e, v.ID)

	scores = map[scan.JudgeCategory]int{scan.CatUndeclaredCap: 3}
	if err := e.pipe.RescanSweep(context.Background()); err != nil {
		t.Fatalf("rescan sweep: %v", err)
	}
	if got := statusOf(t, e, v.ID); got != string(registry.StatusPublished) {
		t.Fatalf("status after the sweep = %s, want published", got)
	}
}
