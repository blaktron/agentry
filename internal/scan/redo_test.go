package scan_test

// The review queue a new ruleset redoes (agentry#772; the operator's D19 of
// 2026-09-30): every version waiting for a person is judged again under the
// new ruleset, and one the gate now passes is published by the gate, its
// review item superseded. Everything else stays where it was.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
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
	if sum := redo(t, e); sum.Published < 1 {
		t.Fatalf("redo published %d versions, want at least this one (%+v)", sum.Published, sum)
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
	if _, err := e.st.Queries().GetPendingReviewItemForVersion(ctx, v.ID); err == nil {
		t.Fatal("the published version is still in the review queue")
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
			redo(t, e)

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
// judge does (§8.4.6).
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
}

// TestRedoReviewQueueLeavesWhatAPersonDecided: an approval whose publish was
// handed to the worker leaves its version in needs_review for a moment
// (agentry#479); the redo must not judge it again, and a version a person
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

	scores = map[scan.JudgeCategory]int{}
	nextRuleset(t, e)
	redo(t, e)

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

// TestRegisteringANewRulesetKeepsEveryEarlierRelease pins D8 of the plan
// (agentry#772): a ruleset release row is never removed or rewritten by the
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
	redo(t, e)
	if got := statusOf(t, e, v.ID); got != "needs_review" {
		t.Fatalf("status after a redo whose AI Review failed = %s, want needs_review", got)
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

	scores = map[scan.JudgeCategory]int{}
	rid := nextRuleset(t, e)
	redo(t, e)

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
}

// recordingQueue records what is enqueued.
type recordingQueue struct{ kinds []string }

func (r *recordingQueue) Enqueue(_ context.Context, kind, queueName string, _ any, _ ...queue.EnqueueOption) (uuid.UUID, error) {
	r.kinds = append(r.kinds, kind+"@"+queueName)
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
	again := &recordingQueue{}
	scan.EnqueueNewRulesetWork(context.Background(), again, nil, scan.RulesetRegistration{Semver: "9.99.3", New: false})
	if len(again.kinds) != 0 {
		t.Fatalf("a restart on a known ruleset enqueued %v", again.kinds)
	}
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
// (agentry#805: production's 0.2.3 sweep ran under 0.2.2). A worker never does
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
