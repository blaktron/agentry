package scan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

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
	// JobScanReconcile is the §7 watchdog: sweep versions parked in
	// `scanning` past the 30-minute cap into review.
	JobScanReconcile = "scan.reconcile"
	// JobReattestSweep countersigns every attestation with a newly
	// registered signing key (§8.8, agentry#350). On the core queue: it
	// touches the database and the signer, never untrusted content.
	JobReattestSweep = "scan.reattest_sweep"
)

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
	q.Register(JobScanReconcile, func(ctx context.Context, _ queue.Job) error {
		moved, err := p.ReconcileStuckScans(ctx)
		if err != nil {
			return err
		}
		if moved > 0 {
			p.log.Warn("scan: watchdog routed stuck versions to review", "count", moved)
		}
		return nil
	})
}

// QueuePipeline adapts the queue into registry.Pipeline: instead of scanning
// inline, it enqueues a scan.version job (the SaaS/worker path §13.3). Dev and
// tests use the synchronous Pipeline directly.
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

// RescanSweepWithSummary is RescanSweep with the counts returned.
//
// Paging is keyset, not LIMIT/OFFSET. The sweep quarantines rows out of the
// very set it is paging over, so under OFFSET every version it acted on
// shifted an unscanned one into the gap — the sweep skipped exactly the
// neighbours of the versions it had just found problems with.
func (p *Pipeline) RescanSweepWithSummary(ctx context.Context) (RescanSummary, error) {
	batch := p.rescanBatch
	if batch <= 0 {
		batch = 100
	}
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
// quarantines it, persists the run that found it, files a platform review item
// so the quarantine has a way OUT, drafts an advisory and notifies the author
// (§8.7).
func (p *Pipeline) rescanOne(ctx context.Context, versionID uuid.UUID) (rescanOutcome, error) {
	q := p.st.Queries()
	before, err := q.GetVersionByID(ctx, versionID)
	if err != nil {
		return rescanOutcome{}, err
	}
	if before.Status != string(registry.StatusPublished) {
		return rescanOutcome{}, nil
	}
	agent, err := q.GetAgentByID(ctx, before.AgentID)
	if err != nil {
		return rescanOutcome{}, fmt.Errorf("scan: rescan load agent: %w", err)
	}
	pol, _, err := p.effectivePolicy(ctx, agent)
	if err != nil {
		return rescanOutcome{}, err
	}

	// A rescan persists its run like any other (§8.7 quarantines must be
	// explainable): the reviewer who has to clear this needs the findings.
	runID, resume, err := p.resumeOrCreateRun(ctx, before, "rescan", pol)
	if err != nil {
		return rescanOutcome{}, err
	}
	result, err := p.runOrchestrator(ctx, before, agent, pol, resume, runID, true)
	if err != nil {
		return rescanOutcome{}, err
	}
	if result.Fatal != nil {
		return rescanOutcome{}, result.Fatal
	}
	if err := p.finishRun(ctx, runID, result); err != nil {
		return rescanOutcome{}, err
	}
	out := rescanOutcome{cachedStages: len(result.Skipped)}

	worst := SevInfo
	for _, f := range result.Findings {
		if confidenceRank(f.Confidence) >= confidenceRank(ConfMedium) && severityRank(f.Severity) > severityRank(worst) {
			worst = f.Severity
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
