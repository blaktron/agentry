package scan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/notify"
	"github.com/blaktron/agentry/internal/queue"
	"github.com/blaktron/agentry/internal/registry"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// Job kinds handled by the scan worker (§8.2, §8.7, §7).
const (
	JobScanVersion = "scan.version"
	JobRescanSweep = "scan.rescan_sweep"
	// JobAttestSweep signs every published version that has no
	// attestation (agentry#407).
	JobAttestSweep = "scan.attest_sweep"
	// JobScanReconcile is the §7 watchdog: sweep versions parked in
	// `scanning` past the 30-minute cap into review.
	JobScanReconcile = "scan.reconcile"
	// JobReattestSweep countersigns every attestation with a newly
	// registered signing key (§8.8, agentry#350). On the core queue: it
	// touches the database and the signer, never untrusted content.
	JobReattestSweep = "scan.reattest_sweep"
	// JobPublishApproved publishes and signs a version whose review item a
	// keyless role approved (agentry#479). On the core queue: it signs, and
	// touches no untrusted content.
	JobPublishApproved = "scan.publish_approved"
)

// PublishApprovedArgs names the approved review item to publish.
type PublishApprovedArgs struct {
	ItemID uuid.UUID `json:"itemId"`
}

// ScanJobArgs is the payload for a scan.version job.
type ScanJobArgs struct {
	VersionID uuid.UUID `json:"versionId"`
	Trigger   string    `json:"trigger"`
}

// RescanSweepArgs records why a sweep was scheduled (the ruleset semver whose
// arrival triggered it, §8.7).
type RescanSweepArgs struct {
	RulesetSemver string `json:"rulesetSemver,omitempty"`
}

// ReattestSweepArgs records which key scheduled the sweep and how many
// attestations lacked it. The sweep signs with whatever key the worker
// holds; the arguments are the log's.
type ReattestSweepArgs struct {
	KeyID   string `json:"keyId,omitempty"`
	Pending int64  `json:"pending,omitempty"`
}

// RegisterHandlers wires the pipeline's job handlers onto a queue client
// (§8.2). The worker role calls this then Work(); dev/tests can Drain().
func (p *Pipeline) RegisterHandlers(q queue.Client) {
	q.Register(JobScanVersion, func(ctx context.Context, job queue.Job) error {
		var args ScanJobArgs
		if err := json.Unmarshal(job.Args, &args); err != nil {
			return fmt.Errorf("scan worker: bad args: %w", err)
		}
		// Top of the §16.2 publish funnel for a submission the receiving
		// role handed off (agentry#507), counted once, not on each retry;
		// the synchronous path counts in VersionSubmitted.
		if args.Trigger == "publish" && job.Attempt <= 1 {
			p.mx.RecordPublishSubmitted(ctx)
		}
		return p.Scan(ctx, args.VersionID, args.Trigger)
	})
	q.Register(JobRescanSweep, func(ctx context.Context, job queue.Job) error {
		var args RescanSweepArgs
		_ = json.Unmarshal(job.Args, &args) // args are advisory
		if args.RulesetSemver != "" {
			p.log.Info("scan: rescan sweep starting", "ruleset", args.RulesetSemver)
		}
		return p.RescanSweep(ctx)
	})
	q.Register(JobRedoReviewQueue, func(ctx context.Context, _ queue.Job) error {
		return p.RedoReviewQueue(ctx)
	})
	q.Register(JobAttestSweep, func(ctx context.Context, _ queue.Job) error {
		sum, err := p.AttestSweep(ctx)
		if err != nil {
			return err
		}
		if sum.Failed > 0 {
			p.log.Error("attest sweep completed with versions it could not sign", "signed", sum.Signed, "failed", sum.Failed)
		} else {
			p.log.Info("attest sweep complete", "signed", sum.Signed)
		}
		return nil
	})
	q.Register(JobReattestSweep, func(ctx context.Context, job queue.Job) error {
		var args ReattestSweepArgs
		_ = json.Unmarshal(job.Args, &args) // args are advisory
		if args.KeyID != "" && p.signer != nil && args.KeyID != p.signer.KeyID() {
			// The worker signs with its own key; a sweep enqueued for another
			// key id (a split deployment mid-rotation) is still worth running
			// — every attestation should carry the key that signs today.
			p.log.Warn("scan: re-attestation sweep enqueued for another key id",
				"enqueuedFor", args.KeyID, "signingWith", p.signer.KeyID())
		}
		return p.ReattestSweep(ctx)
	})
	q.Register(JobMCPSweep, func(ctx context.Context, _ queue.Job) error {
		_, err := p.MCPSweep(ctx)
		return err
	})
	q.Register(JobPublishApproved, func(ctx context.Context, job queue.Job) error {
		var args PublishApprovedArgs
		if err := json.Unmarshal(job.Args, &args); err != nil {
			return fmt.Errorf("scan worker: bad args: %w", err)
		}
		return p.PublishApproved(ctx, args.ItemID)
	})
	q.Register(JobScanReconcile, func(ctx context.Context, _ queue.Job) error {
		moved, err := p.ReconcileStuckScans(ctx)
		if err != nil {
			return err
		}
		if moved > 0 {
			p.log.Warn("scan: watchdog routed stuck versions to review", "count", moved)
		}
		// Handed-off git-tag submissions whose archive was never stored
		// (agentry#508).
		if p.reg != nil {
			rejected, err := p.reg.ReconcileStuckSubmissions(ctx)
			if err != nil {
				return err
			}
			if rejected > 0 {
				p.log.Warn("scan: watchdog rejected git-tag submissions whose archive was never stored", "count", rejected)
			}
		}
		published, err := p.ReconcileApprovedReviews(ctx)
		if err != nil {
			return err
		}
		if published > 0 {
			p.log.Warn("scan: watchdog published approvals whose publish job never ran", "count", published)
		}
		return nil
	})
}

// QueuePipeline adapts the queue into registry.Pipeline: instead of scanning
// inline, it enqueues a scan.version job (§8.2, §13.3). Every role that takes
// submissions hands them off this way (api.Server.HandOffScans, agentry#507);
// the synchronous Pipeline remains for tests that drive a scan in-request.
type QueuePipeline struct {
	Q queue.Client
}

// VersionSubmitted implements registry.Pipeline by enqueueing a scan job.
// The enqueue error used to be discarded, which turned "the queue is down"
// into a version silently parked in `scanning` with nobody scanning it.
func (qp QueuePipeline) VersionSubmitted(ctx context.Context, versionID uuid.UUID) error {
	if _, err := qp.Q.Enqueue(ctx, JobScanVersion, "sandbox",
		ScanJobArgs{VersionID: versionID, Trigger: "publish"}); err != nil {
		return fmt.Errorf("scan: enqueue scan job for version %s: %w", versionID, err)
	}
	return nil
}

// RescanSummary reports what a sweep did. Failures are counted rather than
// swallowed: an unreadable archive for a *published* version is a storage
// integrity problem, and a sweep that logs it and returns nil looks
// indistinguishable from a clean run.
type RescanSummary struct {
	Scanned     int
	Quarantined int
	Failed      int
	// CachedStages counts stage results that did not have to be re-run — §8.7
	// results-cache hits, plus any stage an interrupted attempt had already
	// completed. The measure of what the cache saved.
	CachedStages int
}

// RescanSweep re-runs the scanners against published versions when a new
// ruleset ships (§8.7). New high/critical findings quarantine the version and
// draft an advisory. One unreadable version never stops the sweep — the rest
// of the catalogue still gets checked — but the count comes back to the caller
// so the worker can log it at error level and alerting can see it.
func (p *Pipeline) RescanSweep(ctx context.Context) error {
	sum, err := p.RescanSweepWithSummary(ctx)
	if err != nil {
		return err
	}
	if sum.Failed > 0 {
		// Not a returned error: the sweep did its job for everything it could
		// read. But this must be visible — see the restore runbook, where a
		// version row without its archive is the signal that a database
		// restore went back past a publish.
		p.log.Error("rescan sweep completed with unreadable versions",
			"scanned", sum.Scanned, "quarantined", sum.Quarantined, "failed", sum.Failed)
	} else {
		p.log.Info("rescan sweep complete",
			"scanned", sum.Scanned, "quarantined", sum.Quarantined, "cached_stages", sum.CachedStages)
	}
	return nil
}

// AttestSummary is what an attest sweep did.
type AttestSummary struct {
	Signed int
	Failed int
}

// AttestSweep signs every published version that has no attestation row,
// from its latest finished scan run: the report digest and judge model the
// attestation names are that run's, and the policy version is the agent's
// effective one at sweep time (the run's snapshot carries the policy
// itself, not its version). A version whose latest run has no report
// digest is skipped and counted as failed — signing an empty digest
// asserts nothing (§8.8) — and the log names it. Exactly once per
// version still holds: the insert's ON CONFLICT (version_id) does nothing
// for a row that appeared meanwhile.
func (p *Pipeline) AttestSweep(ctx context.Context) (AttestSummary, error) {
	var sum AttestSummary
	if p.signer == nil {
		return sum, nil
	}
	q := p.st.Queries()
	batch := p.sweepBatch()
	for {
		rows, err := q.ListPublishedVersionsWithoutAttestation(ctx, batch)
		if err != nil {
			return sum, fmt.Errorf("scan: attest list: %w", err)
		}
		if len(rows) == 0 {
			return sum, nil
		}
		progressed := false
		for _, v := range rows {
			if err := p.attestOne(ctx, q, v); err != nil {
				sum.Failed++
				p.log.Error("attest sweep: version left unattested", "version", v.ID, "err", err)
				continue
			}
			sum.Signed++
			progressed = true
		}
		if !progressed {
			// Every row in this page failed; the next page would be the
			// same rows. Stop rather than spin.
			return sum, nil
		}
	}
}

func (p *Pipeline) attestOne(ctx context.Context, q *storegen.Queries, v storegen.AgentVersion) error {
	run, err := q.LatestScanRunForVersion(ctx, v.ID)
	if err != nil {
		return fmt.Errorf("latest scan run: %w", err)
	}
	if run.ReportDigest == nil || *run.ReportDigest == "" {
		return fmt.Errorf("latest scan run %s has no report digest", run.ID)
	}
	agent, err := q.GetAgentByID(ctx, v.AgentID)
	if err != nil {
		return fmt.Errorf("agent: %w", err)
	}
	_, policyVer, err := p.effectivePolicy(ctx, agent)
	if err != nil {
		return err
	}
	judge := ""
	if run.JudgeModel != nil {
		judge = *run.JudgeModel
	}
	return p.sign(ctx, q, agent, v, run.ID, *run.ReportDigest, judge, policyVer)
}

// RescanSweepWithSummary is RescanSweep with the counts returned.
//
// Paging is keyset, not LIMIT/OFFSET. The sweep quarantines rows out of the
// very set it is paging over, so under OFFSET every version it acted on
// shifted an unscanned one into the gap — the sweep skipped exactly the
// neighbours of the versions it had just found problems with.
func (p *Pipeline) RescanSweepWithSummary(ctx context.Context) (RescanSummary, error) {
	batch := p.sweepBatch()
	var sum RescanSummary
	var after *uuid.UUID
	seen := map[uuid.UUID]bool{}
	for {
		rows, err := p.st.Queries().ListPublishedVersionsForRescan(ctx, storegen.ListPublishedVersionsForRescanParams{
			Limit: batch, After: after,
		})
		if err != nil {
			return sum, fmt.Errorf("scan: rescan list: %w", err)
		}
		if len(rows) == 0 {
			return sum, nil
		}
		for _, row := range rows {
			id := row.ID
			after = &id
			if seen[id] {
				continue // belt and braces: never scan one version twice
			}
			seen[id] = true

			sum.Scanned++
			res, err := p.rescanOne(ctx, id)
			if err != nil {
				sum.Failed++
				p.log.Warn("rescan version", "version", id, "err", err)
				continue
			}
			sum.CachedStages += res.cachedStages
			if res.quarantined {
				sum.Quarantined++
			}
		}
	}
}

type rescanOutcome struct {
	quarantined  bool
	cachedStages int
}

// rescanOne re-scans a single published version. A new high/critical finding
// (new: no person decided on it; high: at rescanSeverity, which weighs 0.2.2's
// re-ratings at medium) quarantines it, persists the run that found it, files
// a platform review item so the quarantine has a way OUT, drafts an advisory
// and notifies the author (§8.7).
func (p *Pipeline) rescanOne(ctx context.Context, versionID uuid.UUID) (rescanOutcome, error) {
	q := p.st.Queries()
	before, err := q.GetVersionByID(ctx, versionID)
	if err != nil {
		return rescanOutcome{}, err
	}
	if before.Status != string(registry.StatusPublished) {
		return rescanOutcome{}, nil
	}
	rj, err := p.rejudge(ctx, before)
	if err != nil {
		return rescanOutcome{}, err
	}
	agent, runID, result := rj.agent, rj.runID, rj.result
	out := rescanOutcome{cachedStages: len(result.Skipped)}

	// Only a finding no person has decided on quarantines. A version a
	// reviewer approved with the finding on its report, or a quarantine a
	// reviewer cleared, is not pulled again by every new ruleset, and a
	// re-rating does not pull what a person already approved at the lower
	// rating (agentry#781; the operator's decision of 2026-09-30, whichever
	// queue approved it). A finding is matched by scanner, file and line in
	// the same archive, so a finding with no file (S5's, per category) matches
	// any earlier one of its scanner: the bytes are the same, only the
	// reading is new. If the lookup fails, nothing counts as decided and the
	// rescan quarantines as before (fail toward review).
	seen := map[reviewedKey]bool{}
	decided, err := q.ListDecidedFindings(ctx, storegen.ListDecidedFindingsParams{
		VersionID: versionID, ExcludeRunID: runID,
	})
	if err != nil {
		p.log.ErrorContext(ctx, "rescan: decided findings unreadable; judging every finding as new",
			"version", versionID, "err", err)
	}
	for _, r := range decided {
		seen[reviewedKey{r.Scanner, r.FilePath, int(r.LineStart)}] = true
	}
	worst := SevInfo
	for _, f := range result.Findings {
		if seen[reviewedKey{f.Scanner, f.FilePath, f.LineStart}] {
			continue
		}
		sev := rescanSeverity(f)
		if confidenceRank(f.Confidence) >= confidenceRank(ConfMedium) && severityRank(sev) > severityRank(worst) {
			worst = sev
		}
	}
	if severityRank(worst) < severityRank(SevHigh) {
		return out, nil
	}

	reason := fmt.Sprintf("rescan found new %s finding", worst)
	if err := p.reg.Transition(ctx, versionID, registry.StatusQuarantined, reason,
		audit.Event{ActorKind: audit.ActorSystem}); err != nil {
		return out, err
	}
	out.quarantined = true

	// The way back out (§8.7: "platform reviewer resolves within SLA"). A
	// quarantine with no review item is a dead end — the version can only
	// leave quarantine through a decision, and nothing was asking for one.
	if err := p.st.WithTx(ctx, func(tx *storegen.Queries) error {
		return createReviewItem(ctx, tx, versionID, agent, "platform")
	}); err != nil {
		p.log.Error("rescan review item", "version", versionID, "err", err)
	}

	if err := p.PublishAdvisory(ctx, before.AgentID, before.Version, string(worst),
		fmt.Sprintf("Rescan of %s@%s surfaced a new %s-severity finding.", agent.Name, before.Version, worst),
		reason); err != nil {
		// The quarantine already landed, which is the protective action.
		// A missing advisory is a notification gap, not a safety gap —
		// log it loudly rather than unwinding the quarantine.
		p.log.Error("rescan advisory", "version", versionID, "err", err)
	}
	p.notifyAuthorQuarantined(ctx, before, agent, string(worst), reason)
	return out, nil
}

// rejudged is a version scanned again under this process's ruleset and the
// policy now in force, its run finished.
type rejudged struct {
	agent     storegen.GetAgentByIDRow
	runID     uuid.UUID
	result    RunResult
	policyVer int
}

// rejudge scans a version again as a rescan and performs no transition: the
// catalogue sweep and the redo of the review queue layer theirs on it. The
// run is persisted like any other (§8.7 quarantines must be explainable): the
// reviewer who has to act on it needs the findings.
func (p *Pipeline) rejudge(ctx context.Context, v storegen.AgentVersion) (rejudged, error) {
	agent, err := p.st.Queries().GetAgentByID(ctx, v.AgentID)
	if err != nil {
		return rejudged{}, fmt.Errorf("scan: rescan load agent: %w", err)
	}
	pol, policyVer, err := p.effectivePolicy(ctx, agent)
	if err != nil {
		return rejudged{}, err
	}
	runID, resume, err := p.resumeOrCreateRun(ctx, v, "rescan", pol)
	if err != nil {
		return rejudged{}, err
	}
	result, err := p.runOrchestrator(ctx, v, agent, pol, resume, runID, true)
	if err != nil {
		return rejudged{}, err
	}
	if result.Fatal != nil {
		return rejudged{}, result.Fatal
	}
	if err := p.finishRun(ctx, runID, result); err != nil {
		return rejudged{}, err
	}
	return rejudged{agent: agent, runID: runID, result: result, policyVer: policyVer}, nil
}

// sweepBatch is the page size of the sweeps (tests shrink it to force paging).
func (p *Pipeline) sweepBatch() int32 {
	if p.rescanBatch <= 0 {
		return 100
	}
	return p.rescanBatch
}

// rescanSeverity is what a finding weighs when a rescan decides whether to
// pull a published version. The findings ruleset 0.2.2 re-rated from medium
// to high count at their old rating here: they hold a submission for a
// person, but a new reading of one on a version already published does not
// quarantine it (the operator's decision of 2026-09-30, agentry#771). AI
// Review reads the same bytes differently from run to run, and on dev the
// 0.2.2 sweep pulled seven published versions for a probable undeclared
// capability no earlier run had read.
func rescanSeverity(f Finding) Severity {
	if f.Severity == SevHigh && reratedToHigh(f) {
		return SevMedium
	}
	return f.Severity
}

// reratedToHigh reports a finding that is high only by ruleset 0.2.2's
// re-rating (D16): S6's undeclared environment read, and AI Review's
// injection and undeclared-capability axes at score 2, in a release's own
// scan or a shipped pack's.
func reratedToHigh(f Finding) bool {
	if f.Scanner == scannerUndeclaredEnv {
		return true
	}
	cat := JudgeCategory(f.Scanner[strings.LastIndex(f.Scanner, "/")+1:])
	judged := strings.HasPrefix(f.Scanner, "S5/") || strings.HasPrefix(f.Scanner, KnowledgeStageID+"/S5/")
	if !judged || !highFromProbable[cat] {
		return false
	}
	switch s := f.Detail["score"].(type) {
	case int:
		return s < 3
	case float64: // a finding read back from its stored JSON
		return s < 3
	}
	return false
}

// reviewedKey matches a rescan's finding to one a person decided on: the
// scanner, the file and the line in the same archive.
type reviewedKey struct {
	scanner, file string
	line          int
}

// notifyAuthorQuarantined tells the submitter their published version was
// pulled (§8.7 "author notification"). Best-effort by design: a mail failure
// must never unwind a protective quarantine.
func (p *Pipeline) notifyAuthorQuarantined(ctx context.Context, v storegen.AgentVersion, agent storegen.GetAgentByIDRow, severity, reason string) {
	if p.notifier == nil {
		return
	}
	u, err := p.st.Queries().GetUserByID(ctx, v.SubmittedBy)
	if err != nil {
		p.log.Error("rescan: could not load author for notification", "version", v.ID, "err", err)
		return
	}
	if !notify.AllowsEmail(ctx, p.st.Queries(), p.log, u.ID, notify.KindQuarantine) {
		return // unverified address, or the author switched these off (#299, #190)
	}
	if err := p.notifier.AgentQuarantined(ctx, notify.QuarantineNotice{
		ToEmail:  u.Email,
		Agent:    agent.Namespace + "/" + agent.Name,
		Version:  v.Version,
		Severity: severity,
		Reason:   reason,
	}); err != nil {
		p.log.Error("rescan: author notification", "version", v.ID, "err", err)
	}
}

// Block disables every live version of an agent (§7 `blocked`: downloads
// return 410, only platform staff set or unset it). Setting
// agents.quarantine_state alone left published versions downloadable and made
// the download handler's 410 branch unreachable.
func (p *Pipeline) Block(ctx context.Context, agentID uuid.UUID, reason string, ev audit.Event) (int, error) {
	return p.transitionLiveVersions(ctx, agentID,
		[]string{
			string(registry.StatusPublished),
			string(registry.StatusQuarantined),
		},
		registry.StatusBlocked, reason, ev)
}

// Reinstate reverses a block or quarantine (§7). Blocked versions pass back
// through quarantined — the edge the state machine draws — and on to
// published. No re-signing happens: the attestation was issued once, on the
// original publish (§7).
func (p *Pipeline) Reinstate(ctx context.Context, agentID uuid.UUID, reason string, ev audit.Event) (int, error) {
	n, err := p.transitionLiveVersions(ctx, agentID,
		[]string{string(registry.StatusBlocked)}, registry.StatusQuarantined, reason, ev)
	if err != nil {
		return n, err
	}
	m, err := p.transitionLiveVersions(ctx, agentID,
		[]string{string(registry.StatusQuarantined)}, registry.StatusPublished, reason, ev)
	return n + m, err
}

// transitionLiveVersions moves every version of an agent in one of `from`
// into `to`, skipping edges the state machine forbids.
func (p *Pipeline) transitionLiveVersions(ctx context.Context, agentID uuid.UUID, from []string, to registry.Status, reason string, ev audit.Event) (int, error) {
	rows, err := p.st.Queries().ListVersionsByStatus(ctx, storegen.ListVersionsByStatusParams{
		AgentID: agentID, Statuses: from,
	})
	if err != nil {
		return 0, fmt.Errorf("scan: list versions for %s: %w", to, err)
	}
	moved := 0
	var errs []error
	for _, v := range rows {
		if err := p.reg.Transition(ctx, v.ID, to, reason, ev); err != nil {
			if errors.Is(err, registry.ErrBadTransition) {
				continue
			}
			errs = append(errs, fmt.Errorf("version %s: %w", v.ID, err))
			continue
		}
		moved++
	}
	return moved, errors.Join(errs...)
}
