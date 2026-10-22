package scan_test

// The review queue a new ruleset redoes: every version waiting for a person is
// judged again under the new ruleset, and one the gate now passes is published
// by the gate, its review item superseded. Everything else stays where it was.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/queue"
	"github.com/blaktron/agentry/internal/registry"
	"github.com/blaktron/agentry/internal/scan"
	storegen "github.com/blaktron/agentry/internal/store/gen"
	"github.com/blaktron/agentry/pkg/rules"
	"github.com/blaktron/agentry/pkg/ruleset"
)

// nextRuleset registers a ruleset release no scan has used and points the
// pipeline at it: "a new ruleset has shipped".
func nextRuleset(t *testing.T, e *pipeEnv) uuid.UUID {
	t.Helper()
	row, err := e.st.Queries().CreateRulesetRelease(context.Background(), storegen.CreateRulesetReleaseParams{
		ID: mustV7(t), Semver: "9.99.1-redo" + suffix(), BundleDigest: "redo",
	})
	if err != nil {
		t.Fatal(err)
	}
	e.pipe.SetRulesetForTest(row.ID, row.Semver)
	return row.ID
}

func redo(t *testing.T, e *pipeEnv) scan.RedoSummary {
	t.Helper()
	sum, err := e.pipe.RedoReviewQueueWithSummary(context.Background())
	if err != nil {
		t.Fatalf("redo review queue: %v", err)
	}
	return sum
}

func reviewItem(t *testing.T, e *pipeEnv, id uuid.UUID) storegen.ReviewItem {
	t.Helper()
	item, err := e.st.Queries().GetReviewItem(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return item
}

func pendingItem(t *testing.T, e *pipeEnv, versionID uuid.UUID) storegen.ReviewItem {
	t.Helper()
	item, err := e.st.Queries().GetPendingReviewItemForVersion(context.Background(), versionID)
	if err != nil {
		t.Fatalf("no pending review item for %s: %v", versionID, err)
	}
	return item
}

func TestRedoReviewQueuePublishesWhatNowPasses(t *testing.T) {
	e := newPipeEnv(t)
	ctx := context.Background()
	u, _ := e.st.Queries().GetUserByID(ctx, e.owner)
	scores := map[scan.JudgeCategory]int{scan.CatDeception: 3}
	e.pipe.SetOrchestratorForTest(scan.NewOrchestrator(nil, scoredProvider{scores: &scores}, nil))
	name := "redone" + suffix()
	v := e.publish(name, "public", benignFiles(u.Handle, name, "1.0.0"))
	if v.Status != "needs_review" {
		t.Fatalf("setup: status %s, want needs_review", v.Status)
	}
	held := pendingItem(t, e, v.ID)

	// The next ruleset no longer finds what held it.
	scores = map[scan.JudgeCategory]int{}
	rid := nextRuleset(t, e)
	if sum := redo(t, e); sum.Published < 1 || sum.Rescanned < sum.Published {
		t.Fatalf("redo published %d of %d versions judged, want at least this one (%+v)", sum.Published, sum.Rescanned, sum)
	}

	after, err := e.st.Queries().GetVersionByID(ctx, v.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Status != string(registry.StatusPublished) {
		t.Fatalf("status after the redo = %s, want published", after.Status)
	}
	// Published exactly as a first-time publish is: signed, from a run that
	// names the new ruleset.
	if _, err := e.st.Queries().GetAttestation(ctx, v.ID); err != nil {
		t.Fatalf("the redo published without an attestation: %v", err)
	}
	run, err := e.st.Queries().LatestScanRunForVersion(ctx, v.ID)
	if err != nil {
		t.Fatal(err)
	}
	if run.RulesetReleaseID != rid {
		t.Fatalf("the publishing run names ruleset %s, want the new one %s", run.RulesetReleaseID, rid)
	}
	// The record says the gate published it, not a person.
	if after.StatusReason == nil || !strings.Contains(*after.StatusReason, "judged the review queue again") {
		t.Fatalf("status reason %v does not say the redo published it", after.StatusReason)
	}
	item := reviewItem(t, e, held.ID)
	if item.State != "superseded" || item.DecidedBy != nil || item.DecidedAt == nil {
		t.Fatalf("review item = state %s, decided by %v at %v; want superseded, by no one, dated", item.State, item.DecidedBy, item.DecidedAt)
	}
	release, err := e.st.Queries().GetRulesetByID(ctx, rid)
	if err != nil {
		t.Fatal(err)
	}
	if item.Rationale == nil || !strings.Contains(*item.Rationale, release.Semver) || !strings.Contains(*item.Rationale, "judged the review queue again") {
		t.Fatalf("item rationale %v does not name the ruleset %s and the redo", item.Rationale, release.Semver)
	}
	if !strings.Contains(*after.StatusReason, release.Semver) {
		t.Fatalf("status reason %q does not name the ruleset %s", *after.StatusReason, release.Semver)
	}
	var auditRaw []byte
	if err := e.st.Pool().QueryRow(ctx, `SELECT detail FROM audit_events WHERE action = 'review.decision' AND target_id = $1`, held.ID).Scan(&auditRaw); err != nil {
		t.Fatalf("no review.decision audit event for the superseded item: %v", err)
	}
	var auditDetail map[string]any
	if err := json.Unmarshal(auditRaw, &auditDetail); err != nil {
		t.Fatal(err)
	}
	if auditDetail["decision"] != "superseded" || auditDetail["version_id"] != v.ID.String() || auditDetail["target"] != "published" ||
		auditDetail["ruleset"] != release.Semver || auditDetail["run_id"] != run.ID.String() {
		t.Fatalf("review.decision detail = %v, want the supersession by this ruleset's run", auditDetail)
	}
	if _, err := e.st.Queries().GetPendingReviewItemForVersion(ctx, v.ID); err == nil {
		t.Fatal("the published version is still in the review queue")
	}

	// The gate taking the item back is no person's decision: when a later
	// ruleset finds the same thing again, the version is quarantined, as no
	// one ever read that finding.
	scores = map[scan.JudgeCategory]int{scan.CatDeception: 3}
	if err := e.pipe.RescanSweep(ctx); err != nil {
		t.Fatalf("rescan sweep: %v", err)
	}
	if got := statusOf(t, e, v.ID); got != string(registry.StatusQuarantined) {
		t.Fatalf("status after a rescan finding what the gate once held = %s, want quarantined", got)
	}
}

func TestRedoReviewQueueRefreshesWhatIsStillHeld(t *testing.T) {
	for _, tc := range []struct {
		name   string
		scores map[scan.JudgeCategory]int
	}{
		{"the same high", map[scan.JudgeCategory]int{scan.CatDeception: 3}},
		{"a new high", map[scan.JudgeCategory]int{scan.CatInjection: 3}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newPipeEnv(t)
			ctx := context.Background()
			u, _ := e.st.Queries().GetUserByID(ctx, e.owner)
			scores := map[scan.JudgeCategory]int{scan.CatDeception: 3}
			e.pipe.SetOrchestratorForTest(scan.NewOrchestrator(nil, scoredProvider{scores: &scores}, nil))
			name := "stillheld" + suffix()
			v := e.publish(name, "public", benignFiles(u.Handle, name, "1.0.0"))
			if v.Status != "needs_review" {
				t.Fatalf("setup: status %s, want needs_review", v.Status)
			}
			before := pendingItem(t, e, v.ID)

			scores = tc.scores
			rid := nextRuleset(t, e)
			if sum := redo(t, e); sum.Held < 1 || sum.Rescanned < sum.Held {
				t.Fatalf("redo summary %+v, want this version counted as held", sum)
			}

			if got := statusOf(t, e, v.ID); got != "needs_review" {
				t.Fatalf("status after the redo = %s, want needs_review", got)
			}
			if item := pendingItem(t, e, v.ID); item.ID != before.ID {
				t.Fatalf("pending review item = %s, want the same item %s", item.ID, before.ID)
			}
			run, err := e.st.Queries().LatestScanRunForVersion(ctx, v.ID)
			if err != nil {
				t.Fatal(err)
			}
			if run.RulesetReleaseID != rid || run.FinishedAt == nil {
				t.Fatalf("the report was not refreshed: latest run under %s (finished %v), want a finished run under %s", run.RulesetReleaseID, run.FinishedAt, rid)
			}
		})
	}
}

// forcedReviewProvider finds nothing and requires a person, as the `none`
// judge does.
type forcedReviewProvider struct{}

func (forcedReviewProvider) Name() string              { return "forced" }
func (forcedReviewProvider) RequiresHumanReview() bool { return true }
func (forcedReviewProvider) ModelID() string           { return "" }
func (forcedReviewProvider) InputLimit() int           { return 0 }
func (forcedReviewProvider) Judge(_ context.Context, _ scan.JudgeContent) (scan.JudgeVerdict, error) {
	return scan.JudgeVerdict{Scores: map[scan.JudgeCategory]int{}, Excerpts: map[scan.JudgeCategory]string{}, Model: "forced"}, nil
}

// TestRedoReviewQueueNeverPublishesPastAForcedReview: the redo goes through
// the gate's own Evaluate, so a version held by anything but the severity
// table stays held although it has no finding left.
func TestRedoReviewQueueNeverPublishesPastAForcedReview(t *testing.T) {
	t.Run("the judge requires a person", func(t *testing.T) {
		e := newPipeEnv(t)
		u, _ := e.st.Queries().GetUserByID(context.Background(), e.owner)
		e.pipe.SetOrchestratorForTest(scan.NewOrchestrator(nil, forcedReviewProvider{}, nil))
		name := "forced" + suffix()
		v := e.publish(name, "public", benignFiles(u.Handle, name, "1.0.0"))
		if v.Status != "needs_review" {
			t.Fatalf("setup: status %s, want needs_review", v.Status)
		}
		nextRuleset(t, e)
		redo(t, e)
		if got := statusOf(t, e, v.ID); got != "needs_review" {
			t.Fatalf("status after the redo = %s, want needs_review", got)
		}
	})
	t.Run("the policy requires a person", func(t *testing.T) {
		e := newPipeEnv(t)
		org := e.seedOrg("redopol" + suffix())
		e.setOrgPolicy(org, `{"requireHumanReview":"always"}`)
		scores := map[scan.JudgeCategory]int{}
		e.pipe.SetOrchestratorForTest(scan.NewOrchestrator(nil, scoredProvider{scores: &scores}, nil))
		v := e.publishOrg(org, "always", "private", benignFiles(org.handle, "always", "1.0.0"))
		if v.Status != "needs_review" {
			t.Fatalf("setup: status %s, want needs_review", v.Status)
		}
		nextRuleset(t, e)
		redo(t, e)
		if got := statusOf(t, e, v.ID); got != "needs_review" {
			t.Fatalf("status after the redo = %s, want needs_review", got)
		}
	})
	// The redo only ever takes a version out of the queue by publishing it: a
	// verdict that is now a rejection leaves it held for the person asked,
	// counted as held.
	t.Run("the policy now rejects it", func(t *testing.T) {
		e := newPipeEnv(t)
		u, _ := e.st.Queries().GetUserByID(context.Background(), e.owner)
		files := benignFiles(u.Handle, "nowrejected", "1.0.0")
		files["agent.yaml"] = wildcardEgressManifest(u.Handle, "nowrejected", "1.0.0")
		v := e.publish("nowrejected", "private", files)
		if v.Status != "needs_review" {
			t.Fatalf("setup: status %s, want needs_review", v.Status)
		}
		before := pendingItem(t, e, v.ID)
		e.setBaselinePolicy(`{"wildcardEgress":"reject"}`)
		nextRuleset(t, e)
		sum := redo(t, e)
		if sum.Held != 1 || sum.Published != 0 {
			t.Fatalf("redo summary %+v, want this version alone counted as held", sum)
		}
		if got := statusOf(t, e, v.ID); got != "needs_review" {
			t.Fatalf("status after the redo = %s, want needs_review", got)
		}
		if after := pendingItem(t, e, v.ID); after.ID != before.ID {
			t.Fatalf("pending review item = %s, want the same item %s", after.ID, before.ID)
		}
	})
}

// TestRedoReviewQueueLeavesWhatAPersonDecided: an approval whose publish was
// handed to the worker leaves its version in needs_review for a moment
// the redo must not judge it again, and a version a person
// published is not in the queue at all.
func TestRedoReviewQueueLeavesWhatAPersonDecided(t *testing.T) {
	e := newPipeEnv(t)
	ctx := context.Background()
	q := e.st.Queries()
	u, _ := q.GetUserByID(ctx, e.owner)
	scores := map[scan.JudgeCategory]int{scan.CatDeception: 3}
	e.pipe.SetOrchestratorForTest(scan.NewOrchestrator(nil, scoredProvider{scores: &scores}, nil))

	handedName := "handed" + suffix()
	handed := e.publish(handedName, "public", benignFiles(u.Handle, handedName, "1.0.0"))
	approvedName := "approved" + suffix()
	approved := e.publish(approvedName, "public", benignFiles(u.Handle, approvedName, "1.0.0"))
	if handed.Status != "needs_review" || approved.Status != "needs_review" {
		t.Fatalf("setup: statuses %s, %s, want needs_review", handed.Status, approved.Status)
	}
	item, err := q.GetPendingReviewItemForVersion(ctx, handed.ID)
	if err != nil {
		t.Fatal(err)
	}
	reviewer := e.seedUser("rev" + suffix())
	rationale := "fine"
	if n, err := q.DecideReviewItem(ctx, storegen.DecideReviewItemParams{
		ID: item.ID, State: "approved", DecidedBy: &reviewer, Rationale: &rationale,
	}); err != nil || n != 1 {
		t.Fatalf("decide: %d, %v", n, err)
	}
	if err := q.SetReviewPublishPending(ctx, storegen.SetReviewPublishPendingParams{ID: item.ID, PublishPending: true}); err != nil {
		t.Fatal(err)
	}
	approve(t, e, approved.ID)
	handedRun, err := q.LatestScanRunForVersion(ctx, handed.ID)
	if err != nil {
		t.Fatal(err)
	}
	approvedRun, err := q.LatestScanRunForVersion(ctx, approved.ID)
	if err != nil {
		t.Fatal(err)
	}

	// A held version admitted without a scan, and one of an agent whose
	// administrator turned the pipeline off, are not judged by a redo.
	skippedName := "skippedheld" + suffix()
	skippedV := e.publish(skippedName, "public", benignFiles(u.Handle, skippedName, "1.0.0"))
	pipeSkipName := "pipeskipheld" + suffix()
	pipeSkipV := e.publish(pipeSkipName, "private", benignFiles(u.Handle, pipeSkipName, "1.0.0"))
	if skippedV.Status != "needs_review" || pipeSkipV.Status != "needs_review" {
		t.Fatalf("setup: statuses %s, %s, want needs_review", skippedV.Status, pipeSkipV.Status)
	}
	if _, err := e.st.Pool().Exec(ctx, `UPDATE agent_versions SET scan_status = 'skipped' WHERE id = $1`, skippedV.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.Pool().Exec(ctx, `UPDATE agents SET pipeline_skip = true WHERE id = $1`, pipeSkipV.AgentID); err != nil {
		t.Fatal(err)
	}
	runsBefore := map[uuid.UUID]int{}
	for _, id := range []uuid.UUID{skippedV.ID, pipeSkipV.ID} {
		runsBefore[id] = countRows(t, e, `SELECT count(*) FROM scan_runs WHERE version_id = $1`, id)
	}

	scores = map[scan.JudgeCategory]int{}
	nextRuleset(t, e)
	redo(t, e)

	for name, id := range map[string]uuid.UUID{"unscanned": skippedV.ID, "pipeline_skip": pipeSkipV.ID} {
		if got := countRows(t, e, `SELECT count(*) FROM scan_runs WHERE version_id = $1`, id); got != runsBefore[id] {
			t.Fatalf("the redo judged a held %s version (%d runs → %d)", name, runsBefore[id], got)
		}
		if got := statusOf(t, e, id); got != "needs_review" {
			t.Fatalf("a held %s version is %s after the redo, want needs_review", name, got)
		}
	}
	if got := statusOf(t, e, handed.ID); got != "needs_review" {
		t.Fatalf("the handed-off approval is %s, want needs_review until its publish job runs", got)
	}
	if got := reviewItem(t, e, item.ID); got.State != "approved" || !got.PublishPending {
		t.Fatalf("the handed-off item is %s (publish pending %v), want approved and pending", got.State, got.PublishPending)
	}
	for _, c := range []struct {
		id  uuid.UUID
		run uuid.UUID
	}{{handed.ID, handedRun.ID}, {approved.ID, approvedRun.ID}} {
		run, err := q.LatestScanRunForVersion(ctx, c.id)
		if err != nil {
			t.Fatal(err)
		}
		if run.ID != c.run {
			t.Fatalf("the redo scanned version %s, which a person had decided", c.id)
		}
	}
}

// TestRedoReviewQueueTwiceDoesNothing: a second start on the same ruleset,
// or a redelivered job, judges nothing again.
func TestRedoReviewQueueTwiceDoesNothing(t *testing.T) {
	e := newPipeEnv(t)
	ctx := context.Background()
	u, _ := e.st.Queries().GetUserByID(ctx, e.owner)
	scores := map[scan.JudgeCategory]int{scan.CatDeception: 3}
	e.pipe.SetOrchestratorForTest(scan.NewOrchestrator(nil, scoredProvider{scores: &scores}, nil))
	name := "twice" + suffix()
	v := e.publish(name, "public", benignFiles(u.Handle, name, "1.0.0"))
	if v.Status != "needs_review" {
		t.Fatalf("setup: status %s, want needs_review", v.Status)
	}
	nextRuleset(t, e)
	redo(t, e)
	first, err := e.st.Queries().LatestScanRunForVersion(ctx, v.ID)
	if err != nil {
		t.Fatal(err)
	}
	// What the second pass would publish, if it judged again.
	scores = map[scan.JudgeCategory]int{}
	redo(t, e)
	second, err := e.st.Queries().LatestScanRunForVersion(ctx, v.ID)
	if err != nil {
		t.Fatal(err)
	}
	if second.ID != first.ID {
		t.Fatal("a second redo on the same ruleset judged the version again")
	}
	if got := statusOf(t, e, v.ID); got != "needs_review" {
		t.Fatalf("status after the second redo = %s, want needs_review", got)
	}
}

// TestRegisteringANewRulesetKeepsEveryEarlierRelease pins that
// a ruleset release row is never removed or rewritten by the
// next one, so every scan run keeps naming the bundle that judged it.
func TestRegisteringANewRulesetKeepsEveryEarlierRelease(t *testing.T) {
	e := newPipeEnv(t)
	ctx := context.Background()
	q := e.st.Queries()
	current, err := ruleset.Load()
	if err != nil {
		t.Fatal(err)
	}
	before, err := q.GetRulesetBySemver(ctx, current.Version())
	if err != nil {
		t.Fatalf("the embedded bundle is not registered: %v", err)
	}

	next := nextBundle(t, "9.99.2-keep"+suffix())
	reg, err := scan.RegisterRuleset(ctx, e.st, next)
	if err != nil {
		t.Fatal(err)
	}
	if !reg.New {
		t.Fatal("a new ruleset semver was not reported as new")
	}
	after, err := q.GetRulesetBySemver(ctx, current.Version())
	if err != nil {
		t.Fatalf("registering %s removed the release row of %s: %v", next.Version(), current.Version(), err)
	}
	if after.ID != before.ID || after.BundleDigest != before.BundleDigest {
		t.Fatalf("registering %s rewrote the release row of %s: %+v, was %+v", next.Version(), current.Version(), after, before)
	}
	if _, err := q.GetRulesetBySemver(ctx, next.Version()); err != nil {
		t.Fatalf("the new release row is missing: %v", err)
	}
}

// nextBundle is the shipped bundle under another version.
func nextBundle(t *testing.T, version string) *rules.Bundle {
	t.Helper()
	src := os.DirFS("../../rules")
	m := fstest.MapFS{}
	names, err := fs.Glob(src, "*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		b, err := fs.ReadFile(src, n)
		if err != nil {
			t.Fatal(err)
		}
		if n == "bundle.yaml" {
			lines := strings.Split(string(b), "\n")
			for i, l := range lines {
				if strings.HasPrefix(l, "version:") {
					lines[i] = `version: "` + version + `"`
				}
			}
			b = []byte(strings.Join(lines, "\n"))
		}
		m[n] = &fstest.MapFile{Data: b}
	}
	b, err := rules.LoadBundle(m, ".")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// failingJudge fails every call, as an unreachable AI Review endpoint does.
type failingJudge struct{}

func (failingJudge) Name() string              { return "failing" }
func (failingJudge) RequiresHumanReview() bool { return false }
func (failingJudge) ModelID() string           { return "" }
func (failingJudge) InputLimit() int           { return 0 }
func (failingJudge) Judge(_ context.Context, _ scan.JudgeContent) (scan.JudgeVerdict, error) {
	return scan.JudgeVerdict{}, errors.New("judge unreachable")
}

// TestRedoReviewQueueHoldsWhenAStageFails: a stage that fails in the redo's
// own run forces review, whatever held the version before.
func TestRedoReviewQueueHoldsWhenAStageFails(t *testing.T) {
	e := newPipeEnv(t)
	u, _ := e.st.Queries().GetUserByID(context.Background(), e.owner)
	scores := map[scan.JudgeCategory]int{scan.CatDeception: 3}
	e.pipe.SetOrchestratorForTest(scan.NewOrchestrator(nil, scoredProvider{scores: &scores}, nil))
	name := "stagefail" + suffix()
	v := e.publish(name, "public", benignFiles(u.Handle, name, "1.0.0"))
	if v.Status != "needs_review" {
		t.Fatalf("setup: status %s, want needs_review", v.Status)
	}
	e.pipe.SetOrchestratorForTest(scan.NewOrchestrator(nil, failingJudge{}, nil))
	nextRuleset(t, e)
	if sum := redo(t, e); sum.Held < 1 {
		t.Fatalf("redo summary %+v, want the version whose stage failed counted as held", sum)
	}
	if got := statusOf(t, e, v.ID); got != "needs_review" {
		t.Fatalf("status after a redo whose AI Review failed = %s, want needs_review", got)
	}

	// A version that cannot be judged again at all, as its organization's
	// policy no longer parses, stays held and is counted as failed.
	e.pipe.SetOrchestratorForTest(scan.NewOrchestrator(nil, scoredProvider{scores: &scores}, nil))
	org := e.seedOrg("redobad" + suffix())
	ov := e.publishOrg(org, "redobad", "public", benignFiles(org.handle, "redobad", "1.0.0"))
	if ov.Status != "needs_review" {
		t.Fatalf("setup: org version status %s, want needs_review", ov.Status)
	}
	e.setOrgPolicy(org, `{"maxAutoPublishSeverity":"catastrophic"}`)
	scores = map[scan.JudgeCategory]int{}
	nextRuleset(t, e)
	if sum := redo(t, e); sum.Failed < 1 {
		t.Fatalf("redo summary %+v, want the version that could not be judged counted as failed", sum)
	}
	if got := statusOf(t, e, ov.ID); got != "needs_review" {
		t.Fatalf("status of a version that could not be judged again = %s, want needs_review", got)
	}
}

// TestRedoReviewQueueNeverResumesAnOlderRulesetsRun: a run of the previous
// ruleset left running (a worker killed mid-scan) is not resumed by the new
// ruleset's redo, whose verdict would otherwise mix the old run's findings
// with its own and sign under a ruleset the run does not name.
func TestRedoReviewQueueNeverResumesAnOlderRulesetsRun(t *testing.T) {
	e := newPipeEnv(t)
	ctx := context.Background()
	q := e.st.Queries()
	u, _ := q.GetUserByID(ctx, e.owner)
	scores := map[scan.JudgeCategory]int{scan.CatDeception: 3}
	e.pipe.SetOrchestratorForTest(scan.NewOrchestrator(nil, scoredProvider{scores: &scores}, nil))
	name := "stale" + suffix()
	v := e.publish(name, "public", benignFiles(u.Handle, name, "1.0.0"))
	if v.Status != "needs_review" {
		t.Fatalf("setup: status %s, want needs_review", v.Status)
	}
	held, err := q.LatestScanRunForVersion(ctx, v.ID)
	if err != nil {
		t.Fatal(err)
	}
	// An interrupted rescan under the old ruleset whose finished AI Review
	// stage read an injection.
	stale := mustV7(t)
	if _, err := q.CreateScanRun(ctx, storegen.CreateScanRunParams{
		ID: stale, VersionID: v.ID, Trigger: "rescan", RulesetReleaseID: held.RulesetReleaseID, PolicySnapshot: []byte(`{}`),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := q.InsertFinding(ctx, storegen.InsertFindingParams{
		ID: mustV7(t), ScanRunID: stale, Scanner: "S5/" + string(scan.CatInjection),
		Severity: "high", Confidence: "high", Title: "read by the old ruleset", Detail: []byte(`{"score":3}`),
	}); err != nil {
		t.Fatal(err)
	}
	if err := q.UpsertStageResult(ctx, storegen.UpsertStageResultParams{
		ScanRunID: stale, Scanner: "S5", Status: "ok", Detail: []byte(`{"findings":1}`),
	}); err != nil {
		t.Fatal(err)
	}

	// A run of the new ruleset that was interrupted does not count as having
	// judged the version: the redo goes on with it.
	interrupted := newPipeEnvVersionHeld(t, e, "interrupted"+suffix(), u.Handle)
	scores = map[scan.JudgeCategory]int{}
	rid := nextRuleset(t, e)
	running := mustV7(t)
	if _, err := q.CreateScanRun(ctx, storegen.CreateScanRunParams{
		ID: running, VersionID: interrupted.ID, Trigger: "rescan", RulesetReleaseID: rid, PolicySnapshot: []byte(`{}`),
	}); err != nil {
		t.Fatal(err)
	}
	redo(t, e)
	if r, err := q.GetScanRun(ctx, running); err != nil || r.FinishedAt == nil {
		t.Fatalf("the interrupted run of the new ruleset = %+v, %v; want it resumed and finished", r, err)
	}

	if got := statusOf(t, e, v.ID); got != string(registry.StatusPublished) {
		t.Fatalf("status after the redo = %s, want published: the new ruleset's clean run was mixed with the old run's finding", got)
	}
	run, err := q.LatestFinishedScanRunForVersion(ctx, v.ID)
	if err != nil {
		t.Fatal(err)
	}
	if run.ID == stale || run.RulesetReleaseID != rid {
		t.Fatalf("the publishing run is %s under %s, want a fresh run under %s", run.ID, run.RulesetReleaseID, rid)
	}
}

// newPipeEnvVersionHeld publishes a version that the environment's current
// judge holds for review, and returns it.
func newPipeEnvVersionHeld(t *testing.T, e *pipeEnv, name, handle string) storegen.AgentVersion {
	t.Helper()
	v := e.publish(name, "public", benignFiles(handle, name, "1.0.0"))
	if v.Status != "needs_review" {
		t.Fatalf("setup: status %s, want needs_review", v.Status)
	}
	return v
}

// decidingJudge approves the version's review item, as a person would,
// while the redo's AI Review is running, then finds nothing.
type decidingJudge struct{ decide func() }

func (decidingJudge) Name() string              { return "deciding" }
func (decidingJudge) RequiresHumanReview() bool { return false }
func (decidingJudge) ModelID() string           { return "" }
func (decidingJudge) InputLimit() int           { return 0 }
func (j decidingJudge) Judge(_ context.Context, _ scan.JudgeContent) (scan.JudgeVerdict, error) {
	j.decide()
	return scan.JudgeVerdict{Scores: map[scan.JudgeCategory]int{}, Excerpts: map[scan.JudgeCategory]string{}, Model: "deciding"}, nil
}

// TestRedoReviewQueueYieldsToAReviewerWhoDecidesMeanwhile: a reviewer who
// approves while the redo scans the version publishes it from the report
// they read (the latest finished run, not the redo's run in progress), and
// the redo then finds the version moved and does nothing over it.
func TestRedoReviewQueueYieldsToAReviewerWhoDecidesMeanwhile(t *testing.T) {
	e := newPipeEnv(t)
	ctx := context.Background()
	q := e.st.Queries()
	u, _ := q.GetUserByID(ctx, e.owner)
	scores := map[scan.JudgeCategory]int{scan.CatDeception: 3}
	e.pipe.SetOrchestratorForTest(scan.NewOrchestrator(nil, scoredProvider{scores: &scores}, nil))
	name := "meanwhile" + suffix()
	v := e.publish(name, "public", benignFiles(u.Handle, name, "1.0.0"))
	if v.Status != "needs_review" {
		t.Fatalf("setup: status %s, want needs_review", v.Status)
	}
	item := pendingItem(t, e, v.ID)
	read, err := q.LatestScanRunForVersion(ctx, v.ID)
	if err != nil {
		t.Fatal(err)
	}
	decided := false
	e.pipe.SetOrchestratorForTest(scan.NewOrchestrator(nil, decidingJudge{decide: func() {
		if decided {
			return
		}
		decided = true
		approve(t, e, v.ID)
	}}, nil))
	nextRuleset(t, e)
	sum := redo(t, e)

	if !decided {
		t.Fatal("setup: the reviewer never decided during the redo")
	}
	if sum.Moved < 1 {
		t.Fatalf("redo summary %+v: the version the reviewer decided was not counted as moved", sum)
	}
	if got := statusOf(t, e, v.ID); got != string(registry.StatusPublished) {
		t.Fatalf("status = %s, want published by the reviewer", got)
	}
	if got := reviewItem(t, e, item.ID); got.State != "approved" || got.DecidedBy == nil {
		t.Fatalf("review item = %s by %v, want approved by the reviewer", got.State, got.DecidedBy)
	}
	att, err := q.GetAttestation(ctx, v.ID)
	if err != nil {
		t.Fatalf("the reviewer's publish has no attestation: %v", err)
	}
	var env struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(att.DsseEnvelope, &env); err != nil {
		t.Fatal(err)
	}
	stmt, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(stmt), read.ID.String()) {
		t.Fatalf("the reviewer's attestation does not name the run they read (%s): %s", read.ID, stmt)
	}

	// A reviewer whose approval was handed to the worker while the redo
	// judged leaves the version in needs_review for a moment: the redo does
	// not publish over the decision and counts the version as moved.
	scores = map[scan.JudgeCategory]int{scan.CatDeception: 3}
	e.pipe.SetOrchestratorForTest(scan.NewOrchestrator(nil, scoredProvider{scores: &scores}, nil))
	name2 := "handedmeanwhile" + suffix()
	v2 := e.publish(name2, "public", benignFiles(u.Handle, name2, "1.0.0"))
	if v2.Status != "needs_review" {
		t.Fatalf("setup: status %s, want needs_review", v2.Status)
	}
	item2 := pendingItem(t, e, v2.ID)
	reviewer := e.seedUser("rev" + suffix())
	rationale := "fine"
	handed := false
	e.pipe.SetOrchestratorForTest(scan.NewOrchestrator(nil, decidingJudge{decide: func() {
		if handed {
			return
		}
		handed = true
		if n, err := q.DecideReviewItem(ctx, storegen.DecideReviewItemParams{
			ID: item2.ID, State: "approved", DecidedBy: &reviewer, Rationale: &rationale,
		}); err != nil || n != 1 {
			t.Errorf("decide: %d, %v", n, err)
		}
		if err := q.SetReviewPublishPending(ctx, storegen.SetReviewPublishPendingParams{ID: item2.ID, PublishPending: true}); err != nil {
			t.Error(err)
		}
	}}, nil))
	nextRuleset(t, e)
	sum2 := redo(t, e)
	if !handed {
		t.Fatal("setup: the approval was never handed off during the redo")
	}
	if sum2.Moved < 1 {
		t.Fatalf("redo summary %+v: the version whose item was decided meanwhile should count as moved", sum2)
	}
	if got := statusOf(t, e, v2.ID); got != "needs_review" {
		t.Fatalf("status = %s, want needs_review until the worker publishes the approval", got)
	}
	if got := reviewItem(t, e, item2.ID); got.State != "approved" || !got.PublishPending || got.DecidedBy == nil || *got.DecidedBy != reviewer {
		t.Fatalf("review item = %s (publish pending %v, by %v), want the reviewer's approval kept", got.State, got.PublishPending, got.DecidedBy)
	}
	if _, err := q.GetAttestation(ctx, v2.ID); err == nil {
		t.Fatal("the redo signed a version whose approval it did not publish")
	}
}

// recordingQueue records what is enqueued, and with which arguments.
type recordingQueue struct {
	kinds []string
	args  []any
}

func (r *recordingQueue) Enqueue(_ context.Context, kind, queueName string, args any, _ ...queue.EnqueueOption) (uuid.UUID, error) {
	r.kinds = append(r.kinds, kind+"@"+queueName)
	r.args = append(r.args, args)
	return uuid.New(), nil
}
func (*recordingQueue) Register(string, queue.Handler)                      {}
func (*recordingQueue) Work(context.Context, ...string) error               { return nil }
func (*recordingQueue) CountWaiting(context.Context, string) (int64, error) { return 0, nil }

func TestANewRulesetEnqueuesTheSweepAndTheRedo(t *testing.T) {
	q := &recordingQueue{}
	scan.EnqueueNewRulesetWork(context.Background(), q, nil, scan.RulesetRegistration{Semver: "9.99.3", New: true})
	want := []string{scan.JobRescanSweep + "@sandbox", scan.JobRedoReviewQueue + "@sandbox"}
	if strings.Join(q.kinds, ",") != strings.Join(want, ",") {
		t.Fatalf("enqueued %v, want %v", q.kinds, want)
	}
	for i, a := range q.args {
		if a != any(scan.RescanSweepArgs{RulesetSemver: "9.99.3"}) {
			t.Fatalf("job %d carries %v, want it to name the ruleset 9.99.3", i, a)
		}
	}
	again := &recordingQueue{}
	scan.EnqueueNewRulesetWork(context.Background(), again, nil, scan.RulesetRegistration{Semver: "9.99.3", New: false})
	if len(again.kinds) != 0 {
		t.Fatalf("a restart on a known ruleset enqueued %v", again.kinds)
	}
	// No queue is not a crash, and a sweep that cannot be enqueued does not
	// keep the redo from being enqueued.
	scan.EnqueueNewRulesetWork(context.Background(), nil, nil, scan.RulesetRegistration{Semver: "9.99.3", New: true})
	sweepDown := &sweepDownQueue{}
	scan.EnqueueNewRulesetWork(context.Background(), sweepDown, nil, scan.RulesetRegistration{Semver: "9.99.3", New: true})
	if strings.Join(sweepDown.kinds, ",") != scan.JobRedoReviewQueue+"@sandbox" {
		t.Fatalf("with the sweep's enqueue failing, enqueued %v, want the redo still", sweepDown.kinds)
	}
}

// sweepDownQueue fails the enqueue of the catalogue sweep and takes the rest.
type sweepDownQueue struct{ recordingQueue }

func (s *sweepDownQueue) Enqueue(ctx context.Context, kind, queueName string, args any, opts ...queue.EnqueueOption) (uuid.UUID, error) {
	if kind == scan.JobRescanSweep {
		return uuid.Nil, errQueueDown
	}
	return s.recordingQueue.Enqueue(ctx, kind, queueName, args, opts...)
}

// handlerQueue keeps the handlers RegisterHandlers wires, so a test can hand
// one a job as the worker would.
type handlerQueue struct {
	recordingQueue
	handlers map[string]queue.Handler
}

func (h *handlerQueue) Register(kind string, fn queue.Handler) {
	if h.handlers == nil {
		h.handlers = map[string]queue.Handler{}
	}
	h.handlers[kind] = fn
}

func (*handlerQueue) CountWaiting(context.Context, string) (int64, error) { return 0, nil }

func rulesetJob(t *testing.T, semver string) queue.Job {
	t.Helper()
	raw, err := json.Marshal(scan.RescanSweepArgs{RulesetSemver: semver})
	if err != nil {
		t.Fatal(err)
	}
	return queue.Job{Kind: scan.JobRedoReviewQueue, Args: raw, Attempt: 1}
}

// A rolling deploy runs a worker of the outgoing build beside the api of the
// incoming one, which registers the new ruleset and enqueues its jobs
// (the sweep of a new ruleset must not run under the old one). A worker never does
// a newer ruleset's job under its own: it hands the job back for retry, so a
// worker of the new build takes it. An older ruleset's job is done by nothing:
// the newer registration enqueued its own.
func TestARulesetJobRunsOnlyUnderItsOwnRuleset(t *testing.T) {
	e := newPipeEnv(t)
	ctx := context.Background()
	u, _ := e.st.Queries().GetUserByID(ctx, e.owner)
	scores := map[scan.JudgeCategory]int{scan.CatDeception: 3}
	e.pipe.SetOrchestratorForTest(scan.NewOrchestrator(nil, scoredProvider{scores: &scores}, nil))
	name := "ownruleset" + suffix()
	v := e.publish(name, "public", benignFiles(u.Handle, name, "1.0.0"))
	if v.Status != "needs_review" {
		t.Fatalf("setup: status %s, want needs_review", v.Status)
	}
	scores = map[scan.JudgeCategory]int{}

	// This worker runs 9.99.1-redo…; the jobs below name other rulesets.
	release, err := e.st.Queries().GetRulesetByID(ctx, nextRuleset(t, e))
	if err != nil {
		t.Fatal(err)
	}
	hq := &handlerQueue{}
	e.pipe.RegisterHandlers(hq)
	stillHeld := func(when string) {
		t.Helper()
		after, err := e.st.Queries().GetVersionByID(ctx, v.ID)
		if err != nil {
			t.Fatal(err)
		}
		if after.Status != "needs_review" {
			t.Fatalf("%s: status %s, want needs_review (the job ran under this worker's ruleset)", when, after.Status)
		}
	}
	for _, kind := range []string{scan.JobRedoReviewQueue, scan.JobRescanSweep} {
		newer := rulesetJob(t, "99.0.0")
		newer.Kind = kind
		if err := hq.handlers[kind](ctx, newer); err == nil {
			t.Fatalf("%s for a newer ruleset returned nil; it must be handed back for retry", kind)
		}
		stillHeld(kind + " for a newer ruleset")
		older := rulesetJob(t, "0.0.1")
		older.Kind = kind
		if err := hq.handlers[kind](ctx, older); err != nil {
			t.Fatalf("%s for an older ruleset: %v; it is complete with nothing to do", kind, err)
		}
		stillHeld(kind + " for an older ruleset")
	}

	// The job for this worker's own ruleset runs.
	own := rulesetJob(t, release.Semver)
	if err := hq.handlers[scan.JobRedoReviewQueue](ctx, own); err != nil {
		t.Fatal(err)
	}
	after, err := e.st.Queries().GetVersionByID(ctx, v.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Status != string(registry.StatusPublished) {
		t.Fatalf("the redo for this worker's ruleset left the version %s, want published", after.Status)
	}

	// And the catalogue sweep for this worker's own ruleset runs: it rescans
	// the version the redo just published.
	rescans := func() int {
		return countRows(t, e, `SELECT count(*) FROM scan_runs WHERE version_id = $1 AND trigger = 'rescan'`, v.ID)
	}
	before := rescans()
	ownSweep := rulesetJob(t, release.Semver)
	ownSweep.Kind = scan.JobRescanSweep
	if err := hq.handlers[scan.JobRescanSweep](ctx, ownSweep); err != nil {
		t.Fatal(err)
	}
	if got := rescans(); got <= before {
		t.Fatalf("the sweep job for this worker's ruleset ran no rescan of the published version (%d runs → %d)", before, got)
	}
}

func TestANewRulesetsJobsOutlastARollingDeploy(t *testing.T) {
	q := &optionQueue{}
	scan.EnqueueNewRulesetWork(context.Background(), q, nil, scan.RulesetRegistration{Semver: "9.99.4", New: true})
	if len(q.opts) != 2 {
		t.Fatalf("enqueued %d jobs, want the sweep and the redo", len(q.opts))
	}
	for i, n := range q.opts {
		if n == 0 {
			t.Fatalf("job %d keeps the default retry budget: a worker of the outgoing build can exhaust it", i)
		}
	}

	// On the real queue the budget is twelve attempts, for each job.
	e := newPipeEnv(t)
	semver := "9.99.4-" + suffix()
	scan.EnqueueNewRulesetWork(context.Background(), queue.NewRiverClient(e.st, nil), nil, scan.RulesetRegistration{Semver: semver, New: true})
	rows, err := e.st.Pool().Query(context.Background(),
		`SELECT kind, queue, max_attempts FROM river_job WHERE args->>'rulesetSemver' = $1 ORDER BY kind`, semver)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var kind, queueName string
		var attempts int
		if err := rows.Scan(&kind, &queueName, &attempts); err != nil {
			t.Fatal(err)
		}
		got = append(got, fmt.Sprintf("%s@%s x%d", kind, queueName, attempts))
	}
	want := []string{scan.JobRedoReviewQueue + "@sandbox x12", scan.JobRescanSweep + "@sandbox x12"}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("jobs on the queue = %v, want %v", got, want)
	}
}

// optionQueue records how many options each enqueue carried.
type optionQueue struct {
	recordingQueue
	opts []int
}

func (o *optionQueue) Enqueue(ctx context.Context, kind, queueName string, args any, opts ...queue.EnqueueOption) (uuid.UUID, error) {
	o.opts = append(o.opts, len(opts))
	return o.recordingQueue.Enqueue(ctx, kind, queueName, args, opts...)
}

// TestTheWorkersJobHandlersDoTheirWork: each job kind the scan package hands
// the queue is registered, and its handler does the work the job names: it
// scans the version, signs the published versions that lack a signature,
// countersigns with the worker's key, re-checks the scanned MCP servers, and
// moves a scan the watchdog finds stuck to review. A job whose arguments do
// not decode is an error the queue retries.
func TestTheWorkersJobHandlersDoTheirWork(t *testing.T) {
	ctx := context.Background()
	a, _ := scan.NewFileSigner("", true)
	b, _ := scan.NewFileSigner("", true)
	ea := newPipeEnv(t, func(d *scan.PipelineDeps) { d.Signer = a })
	eb := newPipeEnv(t, func(d *scan.PipelineDeps) { d.Signer = b })
	u, _ := ea.st.Queries().GetUserByID(ctx, ea.owner)
	hq := &handlerQueue{}
	ea.pipe.RegisterHandlers(hq)
	hqB := &handlerQueue{}
	eb.pipe.RegisterHandlers(hqB)
	runOn := func(h *handlerQueue, kind string, args any) error {
		t.Helper()
		raw, err := json.Marshal(args)
		if err != nil {
			t.Fatal(err)
		}
		fn := h.handlers[kind]
		if fn == nil {
			t.Fatalf("no handler registered for %s", kind)
		}
		return fn(ctx, queue.Job{Kind: kind, Args: raw, Attempt: 1})
	}
	run := func(kind string, args any) error { return runOn(hq, kind, args) }
	for _, kind := range []string{scan.JobScanVersion, scan.JobRescanSweep, scan.JobRedoReviewQueue, scan.JobAttestSweep, scan.JobReattestSweep,
		scan.JobMCPSweep, scan.JobReinstateScan, scan.JobPublishApproved, scan.JobScanReconcile} {
		if hq.handlers[kind] == nil {
			t.Errorf("no handler for %s", kind)
		}
	}
	if len(hq.handlers) != 9 || len(hqB.handlers) != 9 {
		t.Errorf("%d and %d handlers registered, want the 9 job kinds", len(hq.handlers), len(hqB.handlers))
	}

	// scan.version: a submission handed to the queue is scanned by the job.
	submitted := &recordingQueue{}
	ea.reg.SetPipeline(scan.QueuePipeline{Q: submitted})
	queued := ea.publish("job-scan", "public", benignFiles(u.Handle, "job-scan", "1.0.0"))
	if queued.Status != "scanning" || len(submitted.kinds) != 1 || submitted.kinds[0] != scan.JobScanVersion+"@sandbox" {
		t.Fatalf("setup: queued submission is %s with %v enqueued, want scanning with one scan.version job", queued.Status, submitted.kinds)
	}
	if err := run(scan.JobScanVersion, submitted.args[0]); err != nil {
		t.Fatalf("scan.version job: %v", err)
	}
	if got := statusOf(t, ea, queued.ID); got != "published" {
		t.Fatalf("status after the scan.version job = %s, want published", got)
	}
	if err := hq.handlers[scan.JobScanVersion](ctx, queue.Job{Kind: scan.JobScanVersion, Args: []byte(`{"versionId":7}`), Attempt: 1}); err == nil {
		t.Fatal("a scan.version job whose arguments do not decode returned no error")
	}

	// scan.attest_sweep: a published version without an attestation gets one
	// from the worker's key.
	if _, err := ea.st.Pool().Exec(ctx, `DELETE FROM attestations WHERE version_id = $1`, queued.ID); err != nil {
		t.Fatal(err)
	}
	if err := run(scan.JobAttestSweep, struct{}{}); err != nil {
		t.Fatalf("attest sweep job: %v", err)
	}
	if att, err := ea.st.Queries().GetAttestation(ctx, queued.ID); err != nil || att.KeyID != a.KeyID() {
		t.Fatalf("attestation after the attest sweep job = %+v, %v; want one by the worker's key", att, err)
	}

	// scan.reattest_sweep: the worker's key countersigns what an earlier key
	// signed, even when the job was enqueued for another key id.
	ea.reg.SetPipeline(ea.pipe)
	old := ea.publish("job-reattest", "public", benignFiles(u.Handle, "job-reattest", "1.0.0"))
	if old.Status != "published" {
		t.Fatalf("setup: status %s, want published", old.Status)
	}
	if err := runOn(hqB, scan.JobReattestSweep, scan.ReattestSweepArgs{KeyID: "some-other-key", Pending: 1}); err != nil {
		t.Fatalf("reattest sweep job: %v", err)
	}
	if env := envelopeOf(t, ea, old.ID); len(env.Signatures) != 2 || env.Signatures[1].KeyID != b.KeyID() {
		t.Fatalf("envelope after the reattest sweep job = %+v, want the worker's countersignature", env.Signatures)
	}

	// scan.mcp_sweep: the scanned MCP servers are re-checked.
	osv := &sweepOSV{vulns: map[string][]scan.OSVVulnerability{}}
	ea.pipe.SetMCPScanning(osv, scan.NewStoreMCPScanCache(ea.st))
	pkg := "job-sweep-fixture-" + suffix()
	mv := ea.publish("job-mcp", "public", map[string]string{
		"agent.yaml": mcpServerManifest(u.Handle, "job-mcp", "2.0.0", pkg),
		"README.md":  "# job-mcp\n", "SKILL.md": "Summarize.\n", "LICENSE": "Apache-2.0\n",
	})
	if mv.Status != "published" {
		t.Fatalf("setup: mcp version status %s", mv.Status)
	}
	osv.vulns["npm/"+pkg+"@0.1.0"] = []scan.OSVVulnerability{{ID: "GHSA-job", Severity: "high", Summary: "x"}}
	if _, err := ea.st.Pool().Exec(ctx, `UPDATE mcp_server_scans SET last_checked_at = now() - interval '25 hours' WHERE ecosystem = 'npm' AND package = $1`, pkg); err != nil {
		t.Fatal(err)
	}
	if err := run(scan.JobMCPSweep, struct{}{}); err != nil {
		t.Fatalf("mcp sweep job: %v", err)
	}
	if open, _ := ea.st.Queries().ListOpenMCPDependencyAlertsForVersion(ctx, mv.ID); len(open) != 1 {
		t.Fatalf("alerts after the mcp sweep job = %+v, want one", open)
	}

	// scan.reconcile: a scan stuck past the cap goes to review.
	stuck := ea.publish("job-stuck", "public", benignFiles(u.Handle, "job-stuck", "1.0.0"))
	if _, err := ea.st.Pool().Exec(ctx, `UPDATE agent_versions SET status = 'scanning', updated_at = now() - interval '2 hours' WHERE id = $1`, stuck.ID); err != nil {
		t.Fatal(err)
	}
	if err := run(scan.JobScanReconcile, struct{}{}); err != nil {
		t.Fatalf("reconcile job: %v", err)
	}
	if got := statusOf(t, ea, stuck.ID); got != "needs_review" {
		t.Fatalf("status of a stuck scan after the reconcile job = %s, want needs_review", got)
	}
}
