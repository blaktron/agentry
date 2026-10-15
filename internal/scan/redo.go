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
// Enqueued beside the
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
	// Moved counts those that left the queue by another route while they
	// were judged: a reviewer's decision, a yank. That route's result stands.
	Moved int
	// Failed counts those that could not be judged again; they stay held,
	// with their earlier report, until a later ruleset's redo or a person.
	Failed int
}

// errReviewItemDecided is a redo that found the version's review item
// decided by a person after it listed it.
var errReviewItemDecided = errors.New("scan: the review item was decided while the redo judged its version")

// RedoReviewQueue runs the redo and logs what it did, at error level when a
// version could not be judged again.
func (p *Pipeline) RedoReviewQueue(ctx context.Context) error {
	sum, err := p.RedoReviewQueueWithSummary(ctx)
	if err != nil {
		return err
	}
	attrs := []any{"ruleset", p.rulesetVer, "rescanned", sum.Rescanned, "published", sum.Published,
		"held", sum.Held, "moved", sum.Moved, "failed", sum.Failed}
	if sum.Failed > 0 {
		p.log.Error("review queue redo completed with versions it could not judge again", attrs...)
	} else {
		p.log.Info("review queue redo complete", attrs...)
	}
	return nil
}

// RedoReviewQueueWithSummary judges every version in needs_review whose
// item is still pending again under this process's ruleset and the policy
// now in force, through the orchestrator and the gate a submission runs. A
// version the gate now publishes is signed and published, its review item
// superseded; one it would still hold, or would reject, stays held for the
// person already asked, with the new run as its report. Only the gate's own
// verdict on the new run publishes, so a forced review in that run (no judge
// ran, a stage failed, content went unread, the policy requires a person,
// wildcard egress) holds the version. A version a finished run of this
// ruleset already judged is not listed, so a second start on the same
// ruleset, or a redelivered job, does nothing.
func (p *Pipeline) RedoReviewQueueWithSummary(ctx context.Context) (RedoSummary, error) {
	var sum RedoSummary
	var after *uuid.UUID
	for {
		ids, err := p.st.Queries().ListHeldVersionsForRedo(ctx, storegen.ListHeldVersionsForRedoParams{
			RulesetReleaseID: p.rulesetID, After: after, RowLimit: p.sweepBatch(),
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
			case errors.Is(err, errReviewItemDecided), errors.Is(err, registry.ErrVersionMoved):
				sum.Moved++
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
	v, err := p.st.Queries().GetVersionByID(ctx, versionID)
	if err != nil {
		return false, fmt.Errorf("scan: redo load version: %w", err)
	}
	if registry.Status(v.Status) != registry.StatusNeedsReview {
		return false, fmt.Errorf("%w: %s is %s", registry.ErrVersionMoved, v.Version, v.Status)
	}
	// A policy that will not parse leaves the version held: it is never a
	// reason to judge by a looser one.
	rj, err := p.rejudge(ctx, v)
	if err != nil {
		return false, err
	}
	if rj.result.Decision.Outcome != OutcomePublish {
		// Still held, or now rejected: the person already asked decides,
		// with this run on the report. The redo only ever takes a version
		// out of the queue by publishing it.
		return false, nil
	}
	if err := p.publishFromQueue(ctx, v, rj); err != nil {
		return false, err
	}
	return true, nil
}

// publishFromQueue publishes a held version the gate now passes, as a
// submission is published (publishUnderLock), from needs_review: inside the
// same transaction it supersedes the pending review item, or stops if a
// person decided it first. The transition's reason and the item's rationale
// name the ruleset, so the record says the gate published it, not a person.
// Like a rescan, it emits no scan.completed and counts no verdict in the
// publish funnel, which counted this version's verdict when it was held; the
// transition's version.published event announces the publish.
func (p *Pipeline) publishFromQueue(ctx context.Context, v storegen.AgentVersion, rj rejudged) error {
	reason := fmt.Sprintf("Ruleset %s judged the review queue again: %s", p.rulesetVer, rj.result.Decision.Reason)
	err := p.publishUnderLock(ctx, rj.agent, v, registry.StatusNeedsReview, rj.runID, rj.result, rj.policyVer, reason,
		func(q *storegen.Queries) error {
			itemID, err := q.SupersedePendingReviewItem(ctx, storegen.SupersedePendingReviewItemParams{
				VersionID: v.ID, Rationale: &reason,
			})
			if errors.Is(err, pgx.ErrNoRows) {
				return errReviewItemDecided
			}
			if err != nil {
				return fmt.Errorf("scan: supersede review item: %w", err)
			}
			return p.aud.Write(ctx, q, audit.Event{
				ActorKind: audit.ActorSystem, Action: audit.ActionReviewDecision,
				TargetKind: "review_item", TargetID: itemID,
				Detail: map[string]any{
					"decision": "superseded", "version_id": v.ID.String(), "target": string(registry.StatusPublished),
					"ruleset": p.rulesetVer, "run_id": rj.runID.String(),
				},
			})
		})
	if err != nil {
		return err
	}
	p.log.InfoContext(ctx, "gate: verdict", logevent.GateVerdict.Attr(),
		"outcome", string(rj.result.Decision.Outcome), "version", v.ID, "agent", rj.agent.ID, "run", rj.runID,
		"worst_severity", string(rj.result.Decision.WorstSeverity), "findings", len(rj.result.Findings),
		"reason", reason, "ruleset", p.rulesetVer)
	return nil
}
