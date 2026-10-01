package scan

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/logevent"
	"github.com/blaktron/agentry/internal/registry"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// JobRedoReviewQueue judges every version waiting in the review queue again
// under a newly registered ruleset and publishes what now passes the gate
// (agentry#772; the operator's D19 of 2026-09-30). Enqueued beside the
// catalogue sweep, which covers published versions only. On the sandbox
// queue: it scans untrusted content.
const JobRedoReviewQueue = "scan.redo_review_queue"

// RedoSummary reports what a redo of the review queue did.
type RedoSummary struct {
	// Rescanned counts the held versions judged again under this ruleset.
	Rescanned int
	// Published counts those the gate now published.
	Published int
	// Held counts those that stay in the queue, their report refreshed.
	Held int
	// Failed counts those that could not be judged again; they stay held.
	Failed int
}

// errReviewerDecided is a redo that reached a version a person decided on
// meanwhile: the person's decision stands and the redo publishes nothing.
var errReviewerDecided = errors.New("scan: a reviewer decided this version while the redo judged it")

// RedoReviewQueue judges every version in needs_review whose item is still
// pending again under this process's ruleset and the policy now in force.
// The gate's own Evaluate decides, through the same orchestrator a
// submission runs: a version it now publishes is signed and published, its
// review item superseded; one it would still hold, or would reject, stays
// held for the person already asked, with the new run as its report. The
// redo publishes past nothing but the severity table: a forced review (no
// judge ran, a stage failed, content went unread, the policy requires a
// person, wildcard egress) holds it as at submission. Versions a finished
// run of this ruleset already judged are not listed, so a second start on
// the same ruleset does nothing.
func (p *Pipeline) RedoReviewQueue(ctx context.Context) (RedoSummary, error) {
	var sum RedoSummary
	batch := p.rescanBatch
	if batch <= 0 {
		batch = 100
	}
	var after *uuid.UUID
	for {
		ids, err := p.st.Queries().ListHeldVersionsForRedo(ctx, storegen.ListHeldVersionsForRedoParams{
			RulesetReleaseID: p.rulesetID, After: after, RowLimit: batch,
		})
		if err != nil {
			return sum, fmt.Errorf("scan: review queue list: %w", err)
		}
		if len(ids) == 0 {
			return sum, nil
		}
		for _, id := range ids {
			after = &id
			sum.Rescanned++
			published, err := p.redoOne(ctx, id)
			switch {
			case errors.Is(err, errReviewerDecided):
				sum.Held++
			case err != nil:
				sum.Failed++
				p.log.WarnContext(ctx, "review queue redo: version left held", "version", id, "err", err)
			case published:
				sum.Published++
			default:
				sum.Held++
			}
		}
	}
}

// redoOne judges one held version again and publishes it if the gate now
// would. It reports whether it published.
func (p *Pipeline) redoOne(ctx context.Context, versionID uuid.UUID) (bool, error) {
	q := p.st.Queries()
	v, err := q.GetVersionByID(ctx, versionID)
	if err != nil {
		return false, err
	}
	if registry.Status(v.Status) != registry.StatusNeedsReview {
		return false, nil
	}
	agent, err := q.GetAgentByID(ctx, v.AgentID)
	if err != nil {
		return false, fmt.Errorf("scan: redo load agent: %w", err)
	}
	pol, policyVer, err := p.effectivePolicy(ctx, agent)
	if err != nil {
		// Held as it is: a policy that will not parse is never a reason to
		// judge by a looser one (§8.6).
		return false, err
	}
	runID, resume, err := p.resumeOrCreateRun(ctx, v, "rescan", pol)
	if err != nil {
		return false, err
	}
	result, err := p.runOrchestrator(ctx, v, agent, pol, resume, runID, true)
	if err != nil {
		return false, err
	}
	if result.Fatal != nil {
		return false, result.Fatal
	}
	if err := p.finishRun(ctx, runID, result); err != nil {
		return false, err
	}
	if result.Decision.Outcome != OutcomePublish {
		// Still held, or now rejected: the person already asked decides,
		// with this run on the report. The redo only ever takes a version
		// out of the queue by publishing it.
		return false, nil
	}
	if err := p.publishFromQueue(ctx, agent, v, runID, result, policyVer); err != nil {
		return false, err
	}
	return true, nil
}

// publishFromQueue publishes a held version the gate now passes: under the
// version's row lock, it supersedes the pending review item (refusing if a
// reviewer decided first), signs from the redo's run, and moves the version
// needs_review → published, in one transaction. The transition's reason and
// the item's rationale name the ruleset, so the record says the gate
// published it, not a person.
func (p *Pipeline) publishFromQueue(ctx context.Context, agent storegen.GetAgentByIDRow, v storegen.AgentVersion, runID uuid.UUID, result RunResult, policyVer int) error {
	reason := fmt.Sprintf("Ruleset %s judged the review queue again: %s", p.rulesetVer, result.Decision.Reason)
	var res registry.TransitionResult
	err := p.st.WithTx(ctx, func(q *storegen.Queries) error {
		row, err := q.GetVersionForUpdate(ctx, v.ID)
		if err != nil {
			return fmt.Errorf("scan: lock version: %w", err)
		}
		if registry.Status(row.Status) != registry.StatusNeedsReview {
			return fmt.Errorf("%w: %s is %s", errReviewerDecided, row.Version, row.Status)
		}
		itemID, err := q.SupersedePendingReviewItem(ctx, storegen.SupersedePendingReviewItemParams{
			VersionID: v.ID, Rationale: &reason,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return errReviewerDecided
		}
		if err != nil {
			return fmt.Errorf("scan: supersede review item: %w", err)
		}
		if err := p.aud.Write(ctx, q, audit.Event{
			ActorKind: audit.ActorSystem, Action: audit.ActionReviewDecision,
			TargetKind: "review_item", TargetID: itemID,
			Detail: map[string]any{
				"decision": "superseded", "version_id": v.ID.String(), "target": string(registry.StatusPublished),
				"ruleset": p.rulesetVer, "run_id": runID.String(),
			},
		}); err != nil {
			return err
		}
		if err := p.sign(ctx, q, agent, v, runID, result.ReportDigest, result.JudgeModel, policyVer); err != nil {
			return err
		}
		r, err := p.reg.TransitionInTx(ctx, q, v.ID, registry.StatusPublished, reason, audit.Event{ActorKind: audit.ActorSystem})
		if err != nil {
			return err
		}
		res = r
		return nil
	})
	if err != nil {
		return err
	}
	p.log.InfoContext(ctx, "gate: verdict", logevent.GateVerdict.Attr(),
		"outcome", string(result.Decision.Outcome), "version", v.ID, "agent", agent.ID, "run", runID,
		"worst_severity", string(result.Decision.WorstSeverity), "findings", len(result.Findings),
		"reason", reason, "ruleset", p.rulesetVer)
	p.reg.EmitTransition(ctx, res)
	p.indexReadme(ctx, agent.ID, v)
	return nil
}
