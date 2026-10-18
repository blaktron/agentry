package scan_test

// A platform reinstate asks for a fresh scan of each blocked or quarantined
// version and publishes nothing itself. A version returns to published only
// when the gate's verdict on that scan is publish; the rest stay held, each
// with an open platform review item.

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/queue"
	"github.com/blaktron/agentry/internal/registry"
	"github.com/blaktron/agentry/internal/scan"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// publishedWithJudge publishes a clean public version judged by a provider
// whose scores the test changes afterwards.
func publishedWithJudge(t *testing.T, e *pipeEnv, label string) (storegen.AgentVersion, registry.Agent, *map[scan.JudgeCategory]int) {
	t.Helper()
	ctx := context.Background()
	u, _ := e.st.Queries().GetUserByID(ctx, e.owner)
	scores := map[scan.JudgeCategory]int{}
	e.pipe.SetOrchestratorForTest(scan.NewOrchestrator(nil, scoredProvider{scores: &scores}, nil))
	name := label + suffix()
	v := e.publish(name, "public", benignFiles(u.Handle, name, "1.0.0"))
	if v.Status != "published" {
		t.Fatalf("setup: status %s, want published", v.Status)
	}
	return v, mustAgent(t, e, u.Handle, name), &scores
}

func versionStatus(t *testing.T, e *pipeEnv, id uuid.UUID) storegen.AgentVersion {
	t.Helper()
	v, err := e.st.Queries().GetVersionByID(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func attestationCount(t *testing.T, e *pipeEnv, id uuid.UUID) int {
	t.Helper()
	var n int
	if err := e.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM attestations WHERE version_id = $1`, id).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// A blocked version whose new scan is held does not come back: it becomes
// quarantined, waits in the platform queue against the new run, and keeps the
// attestation it has. Once the scan passes, a second reinstate publishes it,
// closes the review item with the reinstate's reason, and signs nothing twice.
func TestReinstatePublishesOnlyWhatTheGateNowPasses(t *testing.T) {
	e := newPipeEnv(t)
	ctx := context.Background()
	v, agent, scores := publishedWithJudge(t, e, "reinst")
	if _, err := e.pipe.Block(ctx, agent.ID, "confirmed malicious", staffEvent()); err != nil {
		t.Fatalf("block: %v", err)
	}

	// The judge still finds what it found: the gate holds the version.
	*scores = map[scan.JudgeCategory]int{scan.CatDeception: 3}
	asked, err := e.pipe.Reinstate(ctx, agent.ID, "appeal upheld")
	if err != nil || asked != 1 {
		t.Fatalf("reinstate asked for %d scans, err %v; want 1", asked, err)
	}
	held := versionStatus(t, e, v.ID)
	if held.Status != string(registry.StatusQuarantined) {
		t.Fatalf("status after a held verdict = %s, want quarantined", held.Status)
	}
	item := pendingItem(t, e, v.ID)
	if item.Queue != "platform" {
		t.Fatalf("review item queue = %s, want platform", item.Queue)
	}
	run, err := e.st.Queries().LatestScanRunForVersion(ctx, v.ID)
	if err != nil || run.Trigger != "manual" {
		t.Fatalf("latest run = %+v (%v); want the reinstate's own scan", run, err)
	}

	// The scan now passes: the second reinstate publishes the quarantined
	// version through the gate's verdict.
	*scores = map[scan.JudgeCategory]int{}
	if _, err := e.pipe.Reinstate(ctx, agent.ID, "second look"); err != nil {
		t.Fatalf("second reinstate: %v", err)
	}
	after := versionStatus(t, e, v.ID)
	if after.Status != string(registry.StatusPublished) {
		t.Fatalf("status after a publish verdict = %s, want published", after.Status)
	}
	if after.StatusReason == nil || !strings.Contains(*after.StatusReason, "second look") {
		t.Fatalf("status reason %v does not carry the reinstate's reason", after.StatusReason)
	}
	closed := reviewItem(t, e, item.ID)
	if closed.State != "superseded" || closed.Rationale == nil || !strings.Contains(*closed.Rationale, "second look") {
		t.Fatalf("review item = %s %v; want superseded with the reinstate's reason", closed.State, closed.Rationale)
	}
	if n := attestationCount(t, e, v.ID); n != 1 {
		t.Fatalf("attestations = %d, want the one signed at the first publish", n)
	}
}

// A quarantine the rescan placed stays in place when the scan the reinstate
// asked for is held again, with its review item open.
func TestReinstateLeavesAQuarantineTheGateStillHolds(t *testing.T) {
	e := newPipeEnv(t)
	ctx := context.Background()
	v, agent, scores := publishedWithJudge(t, e, "stillq")
	*scores = map[scan.JudgeCategory]int{scan.CatInjection: 3}
	if err := e.pipe.RescanSweep(ctx); err != nil {
		t.Fatal(err)
	}
	if got := versionStatus(t, e, v.ID).Status; got != string(registry.StatusQuarantined) {
		t.Fatalf("setup: status %s, want quarantined", got)
	}
	before := pendingItem(t, e, v.ID)

	if _, err := e.pipe.Reinstate(ctx, agent.ID, "appeal upheld"); err != nil {
		t.Fatalf("reinstate: %v", err)
	}
	if got := versionStatus(t, e, v.ID).Status; got != string(registry.StatusQuarantined) {
		t.Fatalf("status after a held verdict = %s, want quarantined", got)
	}
	if after := pendingItem(t, e, v.ID); after.ID != before.ID {
		t.Fatalf("the review item changed from %s to %s", before.ID, after.ID)
	}
}

// A quarantine placed by hand has no review item. A held verdict files one,
// so the version has a way out.
func TestReinstateGivesAHeldVersionAReviewItem(t *testing.T) {
	e := newPipeEnv(t)
	ctx := context.Background()
	v, agent, scores := publishedWithJudge(t, e, "byhand")
	if err := e.pipe.Quarantine(ctx, v.ID, "abuse report", staffEvent()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.Queries().GetPendingReviewItemForVersion(ctx, v.ID); err == nil {
		t.Fatal("setup: a quarantine by hand already has an item")
	}
	*scores = map[scan.JudgeCategory]int{scan.CatDeception: 3}
	if _, err := e.pipe.Reinstate(ctx, agent.ID, "appeal upheld"); err != nil {
		t.Fatal(err)
	}
	pendingItem(t, e, v.ID)
	if got := versionStatus(t, e, v.ID).Status; got != string(registry.StatusQuarantined) {
		t.Fatalf("status = %s, want quarantined", got)
	}
}

// With a queue, reinstate only queues the scans: nothing is published or
// moved until a worker runs them.
func TestReinstateQueuesTheScansAndMovesNothing(t *testing.T) {
	q := &handlerQueue{}
	e := newPipeEnv(t, func(d *scan.PipelineDeps) { d.Jobs = q })
	ctx := context.Background()
	v, agent, _ := publishedWithJudge(t, e, "queued")
	if _, err := e.pipe.Block(ctx, agent.ID, "confirmed malicious", staffEvent()); err != nil {
		t.Fatal(err)
	}
	asked, err := e.pipe.Reinstate(ctx, agent.ID, "appeal upheld")
	if err != nil || asked != 1 {
		t.Fatalf("asked %d, err %v; want 1", asked, err)
	}
	if strings.Join(q.kinds, ",") != scan.JobReinstateScan+"@sandbox" {
		t.Fatalf("enqueued %v, want the reinstate scan on the sandbox queue", q.kinds)
	}
	if got := versionStatus(t, e, v.ID).Status; got != string(registry.StatusBlocked) {
		t.Fatalf("status before the worker runs = %s, want blocked", got)
	}

	// The worker's handler does the rest.
	q2 := &handlerQueue{}
	e.pipe.RegisterHandlers(q2)
	raw, _ := json.Marshal(scan.ReinstateScanArgs{VersionID: v.ID, Reason: "appeal upheld"})
	if err := q2.handlers[scan.JobReinstateScan](ctx, queue.Job{Kind: scan.JobReinstateScan, Args: raw, Attempt: 1}); err != nil {
		t.Fatalf("reinstate job: %v", err)
	}
	if got := versionStatus(t, e, v.ID).Status; got != string(registry.StatusPublished) {
		t.Fatalf("status after the job = %s, want published", got)
	}
}

// A reinstate undone before its scan finishes publishes nothing: the agent was
// blocked again, and the old verdict does not outlive the act it served.
func TestAReinstateBlockedAgainBeforeItsScanPublishesNothing(t *testing.T) {
	e := newPipeEnv(t)
	ctx := context.Background()
	v, agent, _ := publishedWithJudge(t, e, "again")
	if _, err := e.pipe.Block(ctx, agent.ID, "confirmed malicious", staffEvent()); err != nil {
		t.Fatal(err)
	}
	if err := e.st.Queries().SetAgentQuarantineState(ctx, storegen.SetAgentQuarantineStateParams{ID: agent.ID, QuarantineState: "blocked"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.pipe.Reinstate(ctx, agent.ID, "appeal upheld"); err != nil {
		t.Fatalf("reinstate: %v", err)
	}
	if got := versionStatus(t, e, v.ID).Status; got != string(registry.StatusBlocked) {
		t.Fatalf("status = %s, want blocked: the agent is blocked", got)
	}
}

// A version admitted without a scan has no verdict to wait for: reinstate
// leaves it held.
func TestReinstateLeavesAnUnscannedVersionHeld(t *testing.T) {
	q := &handlerQueue{}
	e := newPipeEnv(t, func(d *scan.PipelineDeps) { d.Jobs = q })
	ctx := context.Background()
	v, agent, _ := publishedWithJudge(t, e, "unscanned")
	if _, err := e.pipe.Block(ctx, agent.ID, "confirmed malicious", staffEvent()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.Pool().Exec(ctx, `UPDATE agent_versions SET scan_status = 'skipped' WHERE id = $1`, v.ID); err != nil {
		t.Fatal(err)
	}
	asked, err := e.pipe.Reinstate(ctx, agent.ID, "appeal upheld")
	if err != nil || asked != 0 || len(q.kinds) != 0 {
		t.Fatalf("asked %d, enqueued %v, err %v; want nothing", asked, q.kinds, err)
	}
	if got := versionStatus(t, e, v.ID).Status; got != string(registry.StatusBlocked) {
		t.Fatalf("status = %s, want blocked", got)
	}
}
