package scan

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"github.com/PLACEHOLDER_ORG/agentry/internal/audit"
	"github.com/PLACEHOLDER_ORG/agentry/internal/queue"
	"github.com/PLACEHOLDER_ORG/agentry/internal/registry"
	storegen "github.com/PLACEHOLDER_ORG/agentry/internal/store/gen"
)

// Job kinds handled by the scan worker (§8.2, §8.7).
const (
	JobScanVersion = "scan.version"
	JobRescanSweep = "scan.rescan_sweep"
)

// ScanJobArgs is the payload for a scan.version job.
type ScanJobArgs struct {
	VersionID uuid.UUID `json:"versionId"`
	Trigger   string    `json:"trigger"`
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
	q.Register(JobRescanSweep, func(ctx context.Context, _ queue.Job) error {
		return p.RescanSweep(ctx)
	})
}

// QueuePipeline adapts the queue into registry.Pipeline: instead of scanning
// inline, it enqueues a scan.version job (the SaaS/worker path §13.3). Dev and
// tests use the synchronous Pipeline directly.
type QueuePipeline struct {
	Q queue.Client
}

// VersionSubmitted implements registry.Pipeline by enqueueing a scan job.
func (qp QueuePipeline) VersionSubmitted(ctx context.Context, versionID uuid.UUID) {
	_, _ = qp.Q.Enqueue(ctx, JobScanVersion, "sandbox", ScanJobArgs{VersionID: versionID, Trigger: "publish"})
}

// RescanSweep re-runs the deterministic scanners against published versions
// when a new ruleset ships (§8.7). New high/critical findings quarantine the
// version and draft an advisory. Cheap because archives are content-addressed
// and small; a results cache (digest, scanner, ruleset) is the optimization
// left for scale.
func (p *Pipeline) RescanSweep(ctx context.Context) error {
	const batch = 100
	offset := int32(0)
	for {
		rows, err := p.st.Queries().ListPublishedVersionsForRescan(ctx, storegen.ListPublishedVersionsForRescanParams{
			Limit: batch, Offset: offset,
		})
		if err != nil {
			return fmt.Errorf("scan: rescan list: %w", err)
		}
		if len(rows) == 0 {
			return nil
		}
		for _, row := range rows {
			if err := p.rescanOne(ctx, row.ID); err != nil {
				p.log.Warn("rescan version", "version", row.ID, "err", err)
			}
		}
		offset += batch
	}
}

// rescanOne re-scans a single published version; a new high/critical finding
// quarantines it and drafts an advisory (§8.7).
func (p *Pipeline) rescanOne(ctx context.Context, versionID uuid.UUID) error {
	// Reuse the full Scan pipeline in "rescan" mode but do NOT let it
	// transition a published version to published again; instead inspect the
	// resulting run for new high/critical findings.
	before, _ := p.st.Queries().GetVersionByID(ctx, versionID)
	if before.Status != "published" {
		return nil
	}
	// Run scanners without state transition by scanning into a fresh run and
	// checking severity; the transition to quarantined is explicit here.
	result, err := p.scanForRescan(ctx, versionID)
	if err != nil {
		return err
	}
	worst := SevInfo
	for _, f := range result.Findings {
		if confidenceRank(f.Confidence) >= confidenceRank(ConfMedium) && severityRank(f.Severity) > severityRank(worst) {
			worst = f.Severity
		}
	}
	if severityRank(worst) >= severityRank(SevHigh) {
		agent, _ := p.st.Queries().GetAgentByID(ctx, before.AgentID)
		if err := p.reg.Transition(ctx, versionID, registry.StatusQuarantined,
			fmt.Sprintf("rescan found new %s finding", worst), audit.Event{ActorKind: audit.ActorSystem}); err != nil {
			return err
		}
		_ = p.PublishAdvisory(ctx, before.AgentID, before.Version, string(worst),
			fmt.Sprintf("Rescan of %s@%s surfaced a new %s-severity finding.", agent.Name, before.Version, worst), "")
	}
	return nil
}
