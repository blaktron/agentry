package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/google/uuid"

	"github.com/PLACEHOLDER_ORG/agentry/internal/audit"
	"github.com/PLACEHOLDER_ORG/agentry/internal/registry"
	"github.com/PLACEHOLDER_ORG/agentry/internal/store"
	storegen "github.com/PLACEHOLDER_ORG/agentry/internal/store/gen"
)

// Pipeline is the M4 implementation of registry.Pipeline (§8): it fetches the
// version's archive, runs the orchestrator, persists the scan run + findings,
// drives the §7 state machine per the gate decision, and signs on publish.
// It replaces the M3 dev stub. Runs synchronously from a queue handler (or
// inline in dev/tests).
type Pipeline struct {
	st          *store.Store
	reg         *registry.Service
	blobs       registry.BlobStore
	orch        *Orchestrator
	signer      Signer
	aud         *audit.Writer
	log         *slog.Logger
	registryURL string
	rulesetID   uuid.UUID
	rulesetVer  string
}

// PipelineDeps bundles the pipeline's collaborators.
type PipelineDeps struct {
	Store        *store.Store
	Registry     *registry.Service
	Blobs        registry.BlobStore
	Orchestrator *Orchestrator
	Signer       Signer
	Audit        *audit.Writer
	Log          *slog.Logger
	RegistryURL  string
	RulesetID    uuid.UUID
	RulesetVer   string
}

// NewPipeline assembles the pipeline.
func NewPipeline(d PipelineDeps) *Pipeline {
	log := d.Log
	if log == nil {
		log = slog.Default()
	}
	return &Pipeline{
		st: d.Store, reg: d.Registry, blobs: d.Blobs, orch: d.Orchestrator,
		signer: d.Signer, aud: d.Audit, log: log, registryURL: d.RegistryURL,
		rulesetID: d.RulesetID, rulesetVer: d.RulesetVer,
	}
}

// VersionSubmitted implements registry.Pipeline: run the scan for a version
// that just entered `scanning`. Idempotent — safe to call again after a crash.
func (p *Pipeline) VersionSubmitted(ctx context.Context, versionID uuid.UUID) {
	if err := p.Scan(ctx, versionID, "publish"); err != nil {
		p.log.Error("pipeline: scan failed", "version", versionID, "err", err)
		// Fail closed: leave the version in scanning; a rescan or manual
		// retry re-runs. The state machine never advances on error.
	}
}

// Scan runs the full pipeline for one version, persists the run, and drives
// the state machine per the gate (§7, §8.5).
func (p *Pipeline) Scan(ctx context.Context, versionID uuid.UUID, trigger string) error {
	q := p.st.Queries()
	v, err := q.GetVersionByID(ctx, versionID)
	if err != nil {
		return fmt.Errorf("scan: load version: %w", err)
	}
	agent, err := q.GetAgentByID(ctx, v.AgentID)
	if err != nil {
		return fmt.Errorf("scan: load agent: %w", err)
	}
	result, policyVer, err := p.runOrchestrator(ctx, v, agent)
	if err != nil {
		return err
	}
	runID := newUUID()
	effPolicy, _ := p.effectivePolicy(ctx, agent)
	policySnapshot, _ := json.Marshal(effPolicy)
	if _, err := q.CreateScanRun(ctx, storegen.CreateScanRunParams{
		ID: runID, VersionID: versionID, Trigger: trigger,
		RulesetReleaseID: p.rulesetID, PolicySnapshot: policySnapshot,
		JudgeModel: strptr(p.orch.judge.Name()),
	}); err != nil {
		return fmt.Errorf("scan: create run: %w", err)
	}
	if err := p.persist(ctx, runID, result); err != nil {
		return err
	}
	return p.applyDecision(ctx, agent, v, runID, result, policyVer)
}

// runOrchestrator materializes the archive and runs the scanner DAG,
// returning the result and effective policy version. It performs no DB writes
// or state transitions — Scan and RescanSweep layer those on differently.
func (p *Pipeline) runOrchestrator(ctx context.Context, v storegen.AgentVersion, agent storegen.GetAgentByIDRow) (RunResult, int, error) {
	q := p.st.Queries()

	workDir, err := os.MkdirTemp("", "agentry-scan-*")
	if err != nil {
		return RunResult{}, 0, err
	}
	defer func() { _ = os.RemoveAll(workDir) }()
	extractDir := workDir + "/cur"
	if err := os.MkdirAll(extractDir, 0o750); err != nil {
		return RunResult{}, 0, err
	}
	if v.ArchiveKey == nil {
		return RunResult{}, 0, fmt.Errorf("scan: version has no archive")
	}
	blob, err := p.blobs.Get(ctx, *v.ArchiveKey)
	if err != nil {
		return RunResult{}, 0, fmt.Errorf("scan: fetch archive: %w", err)
	}
	var compSize int64
	if v.ArchiveSize != nil {
		compSize = *v.ArchiveSize
	}
	if err := Extract(blob, extractDir, compSize, DefaultLimits()); err != nil {
		_ = blob.Close()
		return RunResult{}, 0, fmt.Errorf("scan: extract: %w", err)
	}
	_ = blob.Close()

	var prevManifest []byte
	if prev, err := q.GetPreviousPublishedVersion(ctx, storegen.GetPreviousPublishedVersionParams{AgentID: v.AgentID, ID: v.ID}); err == nil {
		prevManifest = prev.Manifest
	}
	accountAge := -1
	if u, err := q.GetUserByID(ctx, v.SubmittedBy); err == nil {
		accountAge = int(time.Since(u.CreatedAt).Hours() / 24)
	}
	recent, _ := q.CountRecentVersionsBySubmitter(ctx, v.SubmittedBy)

	effPolicy, policyVer := p.effectivePolicy(ctx, agent)
	result := p.orch.Run(ctx, RunParams{
		Input: Input{
			Dir: extractDir, ManifestJSON: v.Manifest, Kind: agent.Kind,
			PrevManifestJSON: prevManifest, AccountAgeDays: accountAge,
			RecentPublishCount: int(recent),
		},
		Policy: effPolicy, Public: agent.Visibility == "public", AgentName: agent.Name,
	})
	return result, policyVer, nil
}

// scanForRescan runs the scanners for a rescan without transitioning the
// version (§8.7); rescanOne inspects the result.
func (p *Pipeline) scanForRescan(ctx context.Context, versionID uuid.UUID) (RunResult, error) {
	q := p.st.Queries()
	v, err := q.GetVersionByID(ctx, versionID)
	if err != nil {
		return RunResult{}, err
	}
	agent, err := q.GetAgentByID(ctx, v.AgentID)
	if err != nil {
		return RunResult{}, err
	}
	result, _, err := p.runOrchestrator(ctx, v, agent)
	return result, err
}

func (p *Pipeline) persist(ctx context.Context, runID uuid.UUID, result RunResult) error {
	return p.st.WithTx(ctx, func(q *storegen.Queries) error {
		for _, f := range result.Findings {
			detail, _ := json.Marshal(f.Detail)
			var linePtr *int32
			var lineEnd *int32
			if f.LineStart > 0 {
				ls := int32(f.LineStart)
				le := int32(f.LineEnd)
				linePtr, lineEnd = &ls, &le
			}
			var filePtr, excerptPtr *string
			if f.FilePath != "" {
				filePtr = &f.FilePath
			}
			if f.Excerpt != "" {
				excerptPtr = &f.Excerpt
			}
			if _, err := q.InsertFinding(ctx, storegen.InsertFindingParams{
				ID: newUUID(), ScanRunID: runID, Scanner: f.Scanner,
				Severity: string(f.Severity), Confidence: string(f.Confidence),
				Title: f.Title, FilePath: filePtr, LineStart: linePtr, LineEnd: lineEnd,
				Excerpt: excerptPtr, Detail: detail,
			}); err != nil {
				return err
			}
		}
		status := "passed"
		if len(result.Findings) > 0 {
			status = "findings"
		}
		if len(result.Report.StageErrors) > 0 {
			status = "error"
		}
		return q.FinishScanRun(ctx, storegen.FinishScanRunParams{
			ID: runID, Status: status, ReportDigest: strptr(result.ReportDigest),
		})
	})
}

// applyDecision maps the gate outcome onto §7 transitions and, on publish,
// signs the attestation.
func (p *Pipeline) applyDecision(ctx context.Context, agent storegen.GetAgentByIDRow, v storegen.AgentVersion, runID uuid.UUID, result RunResult, policyVer int) error {
	sysEvent := audit.Event{ActorKind: audit.ActorSystem}
	switch result.Decision.Outcome {
	case OutcomePublish:
		if err := p.reg.Transition(ctx, v.ID, registry.StatusPublished, result.Decision.Reason, sysEvent); err != nil {
			return err
		}
		return p.sign(ctx, agent, v, runID, result, policyVer)

	case OutcomeRejected:
		return p.reg.Transition(ctx, v.ID, registry.StatusRejected, result.Decision.Reason, sysEvent)

	case OutcomeNeedsReview:
		if err := p.reg.Transition(ctx, v.ID, registry.StatusNeedsReview, result.Decision.Reason, sysEvent); err != nil {
			return err
		}
		return p.st.WithTx(ctx, func(q *storegen.Queries) error {
			var orgID *uuid.UUID
			if agent.NamespaceKind == "org" && result.Decision.Queue == "org" {
				orgID = &agent.NamespaceID
			}
			_, err := q.CreateReviewItem(ctx, storegen.CreateReviewItemParams{
				ID: newUUID(), VersionID: v.ID, Queue: result.Decision.Queue, OrgID: orgID,
			})
			return err
		})
	}
	return nil
}

// sign builds and stores the DSSE attestation on → published (§8.8).
func (p *Pipeline) sign(ctx context.Context, agent storegen.GetAgentByIDRow, v storegen.AgentVersion, runID uuid.UUID, result RunResult, policyVer int) error {
	if p.signer == nil {
		p.log.Warn("pipeline: no signer configured; skipping attestation")
		return nil
	}
	digest := ""
	if v.ArchiveDigest != nil {
		digest = *v.ArchiveDigest
	}
	stmt := BuildStatement(
		p.registryURL, agent.Namespace+"/"+agent.Name, v.Version, digest, v.CommitSha, v.Source,
		ScanRunRef{ID: runID.String(), RulesetVer: p.rulesetVer, ReportDigest: result.ReportDigest, JudgeModel: result.JudgeModel},
		policyVer,
	)
	env, err := p.signer.Sign(stmt)
	if err != nil {
		return fmt.Errorf("scan: sign: %w", err)
	}
	envJSON, err := json.Marshal(env)
	if err != nil {
		return err
	}
	_, err = p.st.Queries().CreateAttestation(ctx, storegen.CreateAttestationParams{
		ID: newUUID(), VersionID: v.ID, PredicateType: PredicateType,
		DsseEnvelope: envJSON, KeyID: p.signer.KeyID(),
	})
	return err
}

// effectivePolicy resolves baseline ← org overlay (§8.6).
func (p *Pipeline) effectivePolicy(ctx context.Context, agent storegen.GetAgentByIDRow) (Policy, int) {
	q := p.st.Queries()
	baseline := DefaultBaseline()
	version := 1
	if row, err := q.GetBaselinePolicy(ctx); err == nil {
		if parsed, err := ParsePolicy(row.Document); err == nil {
			baseline = parsed
			version = int(row.Version)
		}
	}
	if agent.NamespaceKind == "org" {
		if row, err := q.GetPolicyForOrg(ctx, &agent.NamespaceID); err == nil {
			if org, err := ParsePolicy(row.Document); err == nil {
				return Merge(baseline, org), version + int(row.Version)
			}
		}
	}
	return baseline, version
}

func newUUID() uuid.UUID {
	id, err := uuid.NewV7()
	if err != nil {
		panic(err)
	}
	return id
}

func strptr(s string) *string { return &s }

// ApproveOrReject moves a needs_review version to published or rejected after
// a reviewer decision (§8.6). On approve→published it signs the attestation,
// mirroring the auto-publish path. The review-item state and audit are
// written by the caller; this owns the §7 transition + signing.
func (p *Pipeline) ApproveOrReject(ctx context.Context, versionID uuid.UUID, target registry.Status, rationale string) error {
	sysEvent := audit.Event{ActorKind: audit.ActorSystem}
	if err := p.reg.Transition(ctx, versionID, target, "review: "+rationale, sysEvent); err != nil {
		return err
	}
	if target != registry.StatusPublished {
		return nil
	}
	q := p.st.Queries()
	v, err := q.GetVersionByID(ctx, versionID)
	if err != nil {
		return err
	}
	agent, err := q.GetAgentByID(ctx, v.AgentID)
	if err != nil {
		return err
	}
	run, err := q.LatestScanRunForVersion(ctx, versionID)
	if err != nil {
		return err
	}
	reportDigest := ""
	if run.ReportDigest != nil {
		reportDigest = *run.ReportDigest
	}
	judge := ""
	if run.JudgeModel != nil {
		judge = *run.JudgeModel
	}
	_, policyVer := p.effectivePolicy(ctx, agent)
	return p.sign(ctx, agent, v, run.ID, RunResult{
		ReportDigest: reportDigest,
		JudgeModel:   judge,
	}, policyVer)
}

// Quarantine/Block/Reinstate implement the T&S platform actions (§7).
func (p *Pipeline) Quarantine(ctx context.Context, versionID uuid.UUID, reason string, ev audit.Event) error {
	return p.reg.Transition(ctx, versionID, registry.StatusQuarantined, reason, ev)
}

// PublishAdvisory records a security advisory for an agent (§8.7).
func (p *Pipeline) PublishAdvisory(ctx context.Context, agentID uuid.UUID, affected, severity, summary, detail string) error {
	_, err := p.st.Queries().CreateAdvisory(ctx, storegen.CreateAdvisoryParams{
		ID: newUUID(), AgentID: agentID, AffectedVersions: affected,
		Severity: severity, Summary: summary, Detail: strptrOrNil(detail),
	})
	return err
}

func strptrOrNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// SetOrchestratorForTest replaces the orchestrator. It exists so tests can
// simulate "the ruleset learned something after this version was published"
// (§8.7) without shipping two rule bundles. Not for production use.
func (p *Pipeline) SetOrchestratorForTest(o *Orchestrator) { p.orch = o }
