package scan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/logevent"
	"github.com/blaktron/agentry/internal/registry"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// JobReinstateScan judges one version that a platform reinstate released
// from a block or a quarantine. On the sandbox queue: it scans untrusted
// content.
const JobReinstateScan = "scan.reinstate_version"

// ReinstateScanArgs names the version to judge again and carries the
// reinstate's reason, which the record of the outcome quotes.
type ReinstateScanArgs struct {
	VersionID uuid.UUID `json:"versionId"`
	Reason    string    `json:"reason"`
}

// errReinstateWithdrawn is a reinstate's scan finishing after the agent was
// blocked or quarantined again: the reinstate is no longer in force, so its
// verdict publishes nothing.
var errReinstateWithdrawn = errors.New("scan: the agent was held again before the reinstate's scan finished")

// Reinstate is the platform's reinstate: it asks for a fresh scan of every
// blocked or quarantined version of the agent and returns how many it asked
// for. It publishes nothing itself. A version returns to published only
// when the gate's verdict on its new scan is publish (reinstateOne); every
// other version stays held for a person. A version admitted without a scan
// has no verdict to wait for and is left as it is. The scans run where the
// queue's sandbox worker is; a pipeline with no queue runs them here.
func (p *Pipeline) Reinstate(ctx context.Context, agentID uuid.UUID, reason string) (int, error) {
	rows, err := p.st.Queries().ListVersionsByStatus(ctx, storegen.ListVersionsByStatusParams{
		AgentID: agentID,
		Statuses: []string{
			string(registry.StatusBlocked),
			string(registry.StatusQuarantined),
		},
	})
	if err != nil {
		return 0, fmt.Errorf("scan: list versions to reinstate: %w", err)
	}
	asked := 0
	var errs []error
	for _, v := range rows {
		if v.ScanStatus == registry.ScanStatusSkipped {
			p.log.InfoContext(ctx, "reinstate: version admitted unscanned stays held; it has no scan to judge",
				"version", v.ID, "agent", agentID, "status", v.Status)
			continue
		}
		args := ReinstateScanArgs{VersionID: v.ID, Reason: reason}
		if p.jobs == nil {
			if err := p.reinstateOne(ctx, args); err != nil {
				errs = append(errs, fmt.Errorf("version %s: %w", v.ID, err))
				continue
			}
		} else if _, err := p.jobs.Enqueue(ctx, JobReinstateScan, "sandbox", args); err != nil {
			errs = append(errs, fmt.Errorf("version %s: enqueue: %w", v.ID, err))
			continue
		}
		asked++
	}
	return asked, errors.Join(errs...)
}

// reinstateOne judges one held version again, through the orchestrator and
// the gate a submission runs, under this process's ruleset and the policy now
// in force. The gate's verdict decides:
//
//   - publish: the version is published as a submission is (publishUnderLock),
//     signed if it carries no attestation yet, and its pending review item is
//     closed with the reinstate's reason. A blocked version passes through
//     quarantined in the same transaction, the edge the state machine draws.
//   - anything else, or a scan that could not finish: the version stays
//     held. A blocked version moves to quarantined once a verdict exists,
//     and every held version has a pending platform review item, so a person
//     decides it with the new run as its report.
//
// A scan that fails returns its error and is tried again by the queue; the
// version stays as it was. A version that moved on meanwhile (a reviewer
// published it, it was yanked) keeps the result of that route.
func (p *Pipeline) reinstateOne(ctx context.Context, args ReinstateScanArgs) error {
	v, err := p.st.Queries().GetVersionByID(ctx, args.VersionID)
	if err != nil {
		return fmt.Errorf("scan: reinstate load version: %w", err)
	}
	from := registry.Status(v.Status)
	if (from != registry.StatusBlocked && from != registry.StatusQuarantined) || v.ScanStatus == registry.ScanStatusSkipped {
		p.log.InfoContext(ctx, "reinstate: version is not held; nothing to judge", "version", v.ID, "status", v.Status)
		return nil
	}
	rj, err := p.rejudgeAs(ctx, v, "manual")
	if err != nil {
		return err
	}
	if rj.result.Decision.Outcome == OutcomePublish {
		err = p.publishAfterReinstate(ctx, v, from, rj, args.Reason)
	} else {
		err = p.holdAfterReinstate(ctx, v, from, rj, args.Reason)
	}
	switch {
	case errors.Is(err, errReinstateWithdrawn), errors.Is(err, registry.ErrVersionMoved):
		p.log.WarnContext(ctx, "reinstate: version not changed", "version", v.ID, "agent", rj.agent.ID, "err", err)
		return nil
	case err != nil:
		return err
	}
	return nil
}

// publishAfterReinstate publishes a held version the gate now passes, and
// closes its pending review item with the reinstate's reason, in the same
// transaction. The agent's flag is read under its row lock: a reinstate
// that was undone by a later block or quarantine publishes nothing.
func (p *Pipeline) publishAfterReinstate(ctx context.Context, v storegen.AgentVersion, from registry.Status, rj rejudged, reinstateReason string) error {
	reason := fmt.Sprintf("Reinstated (%s); the gate published it: %s", reinstateReason, rj.result.Decision.Reason)
	sys := audit.Event{ActorKind: audit.ActorSystem}
	err := p.publishUnderLock(ctx, rj.agent, v, from, rj.runID, rj.result, rj.policyVer, reason,
		func(q *storegen.Queries) error {
			a, err := q.GetAgentForUpdate(ctx, v.AgentID)
			if err != nil {
				return fmt.Errorf("scan: lock agent: %w", err)
			}
			if a.QuarantineState != "none" {
				return fmt.Errorf("%w: it is %s", errReinstateWithdrawn, a.QuarantineState)
			}
			if from == registry.StatusBlocked {
				if _, err := p.reg.TransitionInTx(ctx, q, v.ID, registry.StatusQuarantined, reason, sys); err != nil {
					return err
				}
			}
			itemID, err := q.SupersedePendingReviewItem(ctx, storegen.SupersedePendingReviewItemParams{
				VersionID: v.ID, Rationale: &reason,
			})
			if errors.Is(err, pgx.ErrNoRows) {
				return nil // a quarantine placed by hand has no item
			}
			if err != nil {
				return fmt.Errorf("scan: close review item: %w", err)
			}
			return p.aud.Write(ctx, q, audit.Event{
				ActorKind: audit.ActorSystem, Action: audit.ActionReviewDecision,
				TargetKind: "review_item", TargetID: itemID,
				Detail: map[string]any{
					"decision": "superseded", "version_id": v.ID.String(), "target": string(registry.StatusPublished),
					"reason": reinstateReason, "run_id": rj.runID.String(),
				},
			})
		})
	if err != nil {
		return err
	}
	p.logReinstateVerdict(ctx, v, rj, reason)
	return nil
}

// holdAfterReinstate keeps a version the gate would not publish held for a
// person: a blocked one moves to quarantined (the verdict exists now), and
// every one has a pending platform review item to be decided against the new
// run.
func (p *Pipeline) holdAfterReinstate(ctx context.Context, v storegen.AgentVersion, from registry.Status, rj rejudged, reinstateReason string) error {
	reason := fmt.Sprintf("Reinstated (%s); the gate would not publish it: %s", reinstateReason, rj.result.Decision.Reason)
	if from == registry.StatusBlocked {
		if err := p.reg.TransitionFrom(ctx, v.ID, registry.StatusBlocked, registry.StatusQuarantined, reason,
			audit.Event{ActorKind: audit.ActorSystem}, registry.TransitionCause{}); err != nil {
			return err
		}
	}
	if err := p.st.WithTx(ctx, func(q *storegen.Queries) error {
		return createReviewItem(ctx, q, v.ID, rj.agent, "platform")
	}); err != nil {
		return err
	}
	p.logReinstateVerdict(ctx, v, rj, reason)
	return nil
}

func (p *Pipeline) logReinstateVerdict(ctx context.Context, v storegen.AgentVersion, rj rejudged, reason string) {
	p.log.InfoContext(ctx, "gate: verdict", logevent.GateVerdict.Attr(),
		"outcome", string(rj.result.Decision.Outcome), "version", v.ID, "agent", rj.agent.ID, "run", rj.runID,
		"worst_severity", string(rj.result.Decision.WorstSeverity), "findings", len(rj.result.Findings),
		"reason", reason, "trigger", "reinstate")
}

// reinstateJob is the queue handler for JobReinstateScan.
func (p *Pipeline) reinstateJob(ctx context.Context, raw json.RawMessage) error {
	var args ReinstateScanArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return fmt.Errorf("scan worker: bad args: %w", err)
	}
	return p.reinstateOne(ctx, args)
}
