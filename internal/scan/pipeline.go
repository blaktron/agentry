package scan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/logevent"
	"github.com/blaktron/agentry/internal/metrics"
	"github.com/blaktron/agentry/internal/notify"
	"github.com/blaktron/agentry/internal/queue"
	"github.com/blaktron/agentry/internal/registry"
	"github.com/blaktron/agentry/internal/store"
	storegen "github.com/blaktron/agentry/internal/store/gen"
	"github.com/blaktron/agentry/internal/webhook"
)

// Pipeline is the M4 implementation of registry.Pipeline (§8): it fetches the
// version's archive, runs the orchestrator, persists the scan run + findings,
// drives the §7 state machine per the gate decision, and signs on publish.
// It replaces the M3 dev stub. Runs synchronously from a queue handler (or
// inline in dev/tests).
// ErrNoSigningKey is returned when a process that holds no signing key is
// asked to sign (agentry#479): the api and git roles run without the key,
// and a version is never published without its attestation (agentry#407),
// so the transition that needed the signature does not happen there.
var ErrNoSigningKey = errors.New("scan: this process holds no signing key; the worker signs")

// ErrAlreadyDecided is returned when a decision reaches a review item that
// is no longer pending (a second reviewer acting on a stale page).
var ErrAlreadyDecided = errors.New("scan: review item already decided")

type Pipeline struct {
	st          *store.Store
	reg         *registry.Service
	blobs       registry.BlobStore
	orch        *Orchestrator
	signer      Signer
	aud         *audit.Writer
	notifier    notify.Notifier
	log         *slog.Logger
	registryURL string
	rulesetID   uuid.UUID
	rulesetVer  string
	// rescanBatch is the sweep page size (tests shrink it to force paging).
	rescanBatch int32
	// gitHistory is the S2 history seam; nil = history not scanned.
	gitHistory GitHistory
	// drafts answers a version's claimed draft (DraftProvenance); nil =
	// no version is a Drafter revision (the core alone).
	drafts DraftProvenance
	// mx records the §16.2 publish funnel. nil is a working no-op.
	mx *metrics.Metrics
	// osv and mcpCache are S7's vulnerability database and scanned-server
	// registry, kept here for the daily sweep (agentry#177).
	osv      OSVClient
	mcpCache MCPScanCache
	// jobs carries a keyless role's approvals to the worker (agentry#479).
	jobs queue.Client
}

// SetMetrics wires the §16.2 instrument set onto the pipeline and the
// orchestrator it drives.
func (p *Pipeline) SetMetrics(m *metrics.Metrics) {
	p.mx = m
	if p.orch != nil {
		p.orch.SetMetrics(m)
	}
}

// SetMCPScanning wires S7's vulnerability database and scanned-server
// registry onto the orchestrator (agentry#177).
func (p *Pipeline) SetMCPScanning(client OSVClient, cache MCPScanCache) {
	p.osv, p.mcpCache = client, cache
	if p.orch != nil {
		p.orch.SetMCPScanning(client, cache)
	}
}

// MCPScanningEnabled reports whether the sweep has a vulnerability database
// to ask — the wiring check agentry#184 exists for.
func (p *Pipeline) MCPScanningEnabled() bool { return osvEnabled(p.osv) && p.mcpCache != nil }

// SetNotifier overrides the author-notification transport (§8.7).
func (p *Pipeline) SetNotifier(n notify.Notifier) {
	if n != nil {
		p.notifier = n
	}
}

// PipelineDeps bundles the pipeline's collaborators.
// GitHistory is the repository seam S2's history scan reads through
// (agentry#54); the git and all roles provide gitsrv.RepoStore, a worker
// without repo storage leaves it nil and S2 reports "not scanned".
type GitHistory interface {
	HistoryPatch(ctx context.Context, repoID uuid.UUID, commit string) (io.ReadCloser, error)
}

// SetGitHistory wires the history seam.
func (p *Pipeline) SetGitHistory(h GitHistory) { p.gitHistory = h }

type PipelineDeps struct {
	Store        *store.Store
	Registry     *registry.Service
	Blobs        registry.BlobStore
	Orchestrator *Orchestrator
	Signer       Signer
	Audit        *audit.Writer
	// Notifier reaches the author when their published agent is quarantined
	// (§8.7). Defaults to the log notifier.
	Notifier    notify.Notifier
	Log         *slog.Logger
	RegistryURL string
	RulesetID   uuid.UUID
	RulesetVer  string
	// Jobs is the queue a keyless role hands an approval to (agentry#479):
	// with no Signer, an approve → published is published and signed by the
	// worker's publish job, not in the request.
	Jobs queue.Client
}

// StuckScanCap is the §7 timeout: a version in `scanning` longer than this
// had its scan die, and the watchdog routes it to review.
const StuckScanCap = 30 * time.Minute

// NewPipeline assembles the pipeline.
func NewPipeline(d PipelineDeps) *Pipeline {
	log := d.Log
	if log == nil {
		log = slog.Default()
	}
	notifier := d.Notifier
	if notifier == nil {
		notifier = notify.LogNotifier{Log: log}
	}
	return &Pipeline{
		st: d.Store, reg: d.Registry, blobs: d.Blobs, orch: d.Orchestrator,
		signer: d.Signer, aud: d.Audit, notifier: notifier, log: log,
		registryURL: d.RegistryURL, rulesetID: d.RulesetID, rulesetVer: d.RulesetVer,
		rescanBatch: 100, jobs: d.Jobs,
	}
}

// VersionSubmitted implements registry.Pipeline: run the scan for a version
// that just entered `scanning`. Idempotent — safe to call again after a crash.
func (p *Pipeline) VersionSubmitted(ctx context.Context, versionID uuid.UUID) error {
	// Top of the §16.2 publish funnel. Counted here rather than in the
	// registry so that the submitted count and the verdict counts come from
	// the same object and cannot drift apart; a submission handed to the
	// queue (QueuePipeline) is counted by the scan.version handler instead.
	p.mx.RecordPublishSubmitted(ctx)
	if err := p.Scan(ctx, versionID, "publish"); err != nil {
		p.log.Error("pipeline: scan failed", "version", versionID, "err", err)
		// Fail closed: the version stays in scanning and the watchdog routes
		// it to review at the §7 cap. Returning the error lets the submitter
		// learn that now instead of guessing from a stalled status.
		return err
	}
	return nil
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
	// A version admitted without a scan (M21) is never scanned after the
	// fact: a run on it would put a report on a version whose verdict is
	// "unscanned" and make the two say different things. The sweeps leave
	// it out by their queries; a scan asked for by name stops here.
	if v.ScanStatus == registry.ScanStatusSkipped {
		p.log.Info("scan: version admitted unscanned; not scanned", "version", versionID, "trigger", trigger)
		return nil
	}
	// A publish scan is for a version in `scanning`. Queue delivery is
	// at-least-once (agentry#507), so a scan.version job can arrive again
	// after its version was published, held or rejected; running it would
	// judge the version a second time and could file a review item against
	// a decided version. Rescans use their own triggers and are not stopped.
	if trigger == "publish" && registry.Status(v.Status) != registry.StatusScanning {
		p.log.Info("scan: publish scan for a version no longer scanning; nothing to do",
			"version", versionID, "status", v.Status)
		return nil
	}

	effPolicy, policyVer, err := p.effectivePolicy(ctx, agent)
	if err != nil {
		// A policy we cannot parse is not a policy we may ignore. Falling
		// back to the platform baseline would silently LOOSEN an org that
		// asked to be tightened (§8.6), so the version goes to a human.
		p.log.Error("scan: effective policy unusable; failing to review",
			"version", versionID, "err", err)
		return p.FailToReview(ctx, v, agent, trigger, "policy", err)
	}

	runID, resume, err := p.resumeOrCreateRun(ctx, v, trigger, effPolicy)
	if err != nil {
		return err
	}

	result, err := p.runOrchestrator(ctx, &v, agent, effPolicy, resume, runID, false)
	if err != nil {
		return err
	}
	if result.Fatal != nil {
		return p.FailToReview(ctx, v, agent, trigger, "report", result.Fatal)
	}
	if err := p.finishRun(ctx, runID, result); err != nil {
		return err
	}
	return p.applyDecision(ctx, agent, v, runID, result, policyVer)
}

// resumeOrCreateRun reuses an interrupted run for this version+trigger and
// reports which of its stages are already done (§8.2: "stage results keyed by
// (scan_run_id, scanner)"). At-least-once queue delivery means a retried scan
// job used to create a second run and a second copy of every finding.
func (p *Pipeline) resumeOrCreateRun(ctx context.Context, v storegen.AgentVersion, trigger string, pol Policy) (uuid.UUID, Resume, error) {
	q := p.st.Queries()
	prior, err := q.RunningScanRunForVersion(ctx, storegen.RunningScanRunForVersionParams{
		VersionID: v.ID, Trigger: trigger, RulesetReleaseID: p.rulesetID,
	})
	if err == nil {
		resume, rerr := p.resumeFromRun(ctx, prior.ID)
		if rerr != nil {
			return uuid.Nil, Resume{}, rerr
		}
		p.log.Info("scan: resuming interrupted run", "run", prior.ID, "version", v.ID,
			"completed_stages", len(resume.Skip))
		return prior.ID, resume, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, Resume{}, fmt.Errorf("scan: look up running run: %w", err)
	}

	snapshot, err := json.Marshal(pol)
	if err != nil {
		return uuid.Nil, Resume{}, fmt.Errorf("scan: policy snapshot: %w", err)
	}
	runID := newUUID()
	if _, err := q.CreateScanRun(ctx, storegen.CreateScanRunParams{
		ID: runID, VersionID: v.ID, Trigger: trigger,
		RulesetReleaseID: p.rulesetID, PolicySnapshot: snapshot,
		JudgeModel: strptr(judgeModelOf(p.orch.judge)),
	}); err != nil {
		return uuid.Nil, Resume{}, fmt.Errorf("scan: create run: %w", err)
	}
	return runID, Resume{}, nil
}

// resumeFromRun collects the stages a previous attempt finished cleanly and
// the findings they already wrote.
func (p *Pipeline) resumeFromRun(ctx context.Context, runID uuid.UUID) (Resume, error) {
	q := p.st.Queries()
	stages, err := q.ListStageResults(ctx, runID)
	if err != nil {
		return Resume{}, fmt.Errorf("scan: list stage results: %w", err)
	}
	skip := map[string]bool{}
	var knowledge []ShippedPackScan
	for _, s := range stages {
		// Only clean stages are skippable; an errored stage must run again.
		if s.Status != "ok" {
			continue
		}
		if s.Scanner == KnowledgeStageID {
			// A clean SK whose record will not read runs again rather than
			// leave the report without what it read.
			var rec []ShippedPackScan
			if DecodeKnowledgeRecord(s.Detail, &rec) != nil || len(rec) == 0 {
				continue
			}
			knowledge = rec
		}
		skip[s.Scanner] = true
	}
	if len(skip) == 0 {
		return Resume{}, nil
	}
	rows, err := q.ListFindings(ctx, runID)
	if err != nil {
		return Resume{}, fmt.Errorf("scan: list findings: %w", err)
	}
	var prior []Finding
	for _, row := range rows {
		if skip[stageOf(row.Scanner)] {
			prior = append(prior, findingFromRow(row))
		}
	}
	return Resume{Skip: skip, Findings: prior, Knowledge: knowledge}, nil
}

// runOrchestrator materializes the archive and runs the scanner DAG,
// persisting each stage's findings as it completes. It performs no state
// transitions — Scan and the rescan path layer those on differently.
func (p *Pipeline) runOrchestrator(
	ctx context.Context,
	v *storegen.AgentVersion,
	agent storegen.GetAgentByIDRow,
	pol Policy,
	resume Resume,
	runID uuid.UUID,
	useCache bool,
) (RunResult, error) {
	q := p.st.Queries()

	workDir, err := os.MkdirTemp("", "agentry-scan-*")
	if err != nil {
		return RunResult{}, err
	}
	defer func() { _ = os.RemoveAll(workDir) }()
	extractDir := workDir + "/cur"
	if err := os.MkdirAll(extractDir, 0o750); err != nil {
		return RunResult{}, err
	}
	if v.ArchiveKey == nil {
		return RunResult{}, fmt.Errorf("scan: version has no archive")
	}
	blob, err := p.blobs.Get(ctx, *v.ArchiveKey)
	if err != nil {
		return RunResult{}, fmt.Errorf("scan: fetch archive: %w", err)
	}
	var compSize int64
	if v.ArchiveSize != nil {
		compSize = *v.ArchiveSize
	}
	if err := Extract(blob, extractDir, compSize, DefaultLimits()); err != nil {
		_ = blob.Close()
		return RunResult{}, fmt.Errorf("scan: extract: %w", err)
	}
	_ = blob.Close()

	// S9's baseline. Absence is normal (first-ever publish, §8.3 S9); a
	// database error is NOT, and treating the two alike silently skipped the
	// rug-pull diff — the single most documented real-world attack shape.
	//
	// The previous version's ARCHIVE is materialized too, not just its
	// manifest: postmark-mcp changed no manifest field at all, so a
	// manifest-only diff would have cleared it (§8.3 S9, DEV-026).
	var prevManifest []byte
	var prevVersion, prevDir string
	var baseline *storegen.AgentVersion
	prev, err := q.GetPreviousPublishedVersion(ctx, storegen.GetPreviousPublishedVersionParams{
		AgentID: v.AgentID, ID: v.ID,
	})
	switch {
	case err == nil:
		prevManifest, prevVersion = prev.Manifest, prev.Version
		prevDir = p.materializePrevArchive(ctx, workDir, prev)
		baseline = &prev
	case errors.Is(err, pgx.ErrNoRows):
		// First publish: S9 is skipped by design and S8 weighs more.
	default:
		return RunResult{}, fmt.Errorf("scan: previous published version: %w", err)
	}

	// A Drafter revision of the baseline, proved by the extension against
	// the files extracted above, is read by S9 with the benefit of the
	// doubt (plan drafter-revisions.md §6; agentry#794).
	revision, err := p.draftRevision(ctx, v, agent, extractDir, baseline, prevDir)
	if err != nil {
		return RunResult{}, err
	}

	// S8's anti-typosquat compare needs names to compare against; without the
	// live top-N it silently matched nothing on every scan (§8.3 S8, T-10).
	popular, err := q.ListPopularAgentNames(ctx, popularAgentSampleSize)
	if err != nil {
		return RunResult{}, fmt.Errorf("scan: popular agent names: %w", err)
	}

	// S8's publisher-behaviour signals. Same reasoning: a lookup failure must
	// not read as "a brand-new account with no publish history".
	u, err := q.GetUserByID(ctx, v.SubmittedBy)
	if err != nil {
		return RunResult{}, fmt.Errorf("scan: submitter: %w", err)
	}
	accountAge := int(time.Since(u.CreatedAt).Hours() / 24)
	recent, err := q.CountRecentVersionsBySubmitter(ctx, v.SubmittedBy)
	if err != nil {
		return RunResult{}, fmt.Errorf("scan: submitter publish velocity: %w", err)
	}
	clusterAccounts, clusterVersions := 0, 0
	if v.SubmitterIpHash != nil && *v.SubmitterIpHash != "" {
		cl, err := q.CountIPClusterSubmissions(ctx, v.SubmitterIpHash)
		if err != nil {
			return RunResult{}, fmt.Errorf("scan: ip cluster: %w", err)
		}
		clusterAccounts, clusterVersions = int(cl.Accounts), int(cl.Versions)
	}

	digest := ""
	if v.ArchiveDigest != nil {
		digest = *v.ArchiveDigest
	}
	if useCache && digest != "" {
		resume = p.mergeCachedStages(ctx, digest, resume)
	}

	// Persisting per stage (rather than in one bulk write at the end) is what
	// makes a retried scan job resumable: the run's completed stages and their
	// findings are already durable when the process dies mid-DAG.
	var sinkMu sync.Mutex
	var sinkErrs []error
	onStage := func(res StageResult) {
		sinkMu.Lock()
		defer sinkMu.Unlock()
		if err := p.persistStage(ctx, runID, res); err != nil {
			sinkErrs = append(sinkErrs, err)
		}
		if digest != "" && res.Err == nil && !res.NoCache && cacheable(res.Scanner) {
			p.storeCachedStage(ctx, digest, res)
		}
	}

	result := p.orch.Run(ctx, RunParams{
		Input: Input{
			Dir: extractDir, ManifestJSON: v.Manifest,
			Version: v.Version, Summary: agent.Summary,
			PrevManifestJSON: prevManifest, PrevVersion: prevVersion,
			PrevArchiveDir: prevDir, AccountAgeDays: accountAge,
			RecentPublishCount: int(recent),
			IPClusterAccounts:  clusterAccounts, IPClusterVersions: clusterVersions,
			SubmitterIsStaff: u.PlatformStaff,
			Source:           v.Source,
			DraftRevision:    revision,
			History:          p.historyReader(agent.RepoID, v.CommitSha),
		},
		Policy: pol, Public: agent.Visibility == "public", AgentName: agent.Name,
		PopularAgentNames: popular,
		NamespaceIsOrg:    agent.NamespaceKind == "org",
		Resume:            resume,
		OnStage:           onStage,
	})
	// The version ↔ declared-server join the daily sweep maps alerts
	// through (agentry#177). Recorded whatever the outcome: a version in
	// review still declares the servers it declares.
	p.recordVersionMCPServers(ctx, v.ID, v.Manifest)
	sinkMu.Lock()
	defer sinkMu.Unlock()
	if len(sinkErrs) > 0 {
		return RunResult{}, fmt.Errorf("scan: persist stage results: %w", errors.Join(sinkErrs...))
	}
	return result, nil
}

// recordVersionMCPServers replaces the version's rows in
// agent_version_mcp_servers with the servers its manifest declares.
func (p *Pipeline) recordVersionMCPServers(ctx context.Context, versionID uuid.UUID, manifestJSON []byte) {
	q := p.st.Queries()
	if err := q.DeleteVersionMCPServers(ctx, versionID); err != nil {
		p.log.Warn("scan: clear version mcp servers", "version", versionID, "err", err)
		return
	}
	for _, d := range DeclaredMCPServers(manifestJSON) {
		if err := q.InsertVersionMCPServer(ctx, storegen.InsertVersionMCPServerParams{
			VersionID: versionID, Ecosystem: d.Ecosystem, Package: d.Package, Version: d.Version,
		}); err != nil {
			p.log.Warn("scan: record version mcp server", "version", versionID, "err", err)
		}
	}
}

// storeMCPScanCache is the MCPScanCache over mcp_server_scans.
type storeMCPScanCache struct{ st *store.Store }

// NewStoreMCPScanCache returns the store-backed registry of scanned MCP
// server versions.
func NewStoreMCPScanCache(st *store.Store) MCPScanCache { return storeMCPScanCache{st: st} }

func (c storeMCPScanCache) Get(ctx context.Context, eco, pkg, ver string) (*MCPScanRecord, error) {
	row, err := c.st.Queries().GetMCPServerScan(ctx, storegen.GetMCPServerScanParams{Ecosystem: eco, Package: pkg, Version: ver})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return mcpScanRecordFromRow(row), nil
}

func (c storeMCPScanCache) Put(ctx context.Context, rec MCPScanRecord) error {
	advs, err := json.Marshal(rec.Advisories)
	if err != nil {
		return err
	}
	if rec.Advisories == nil {
		advs = []byte("[]")
	}
	var maxSev, lastErr *string
	if rec.MaxSeverity != "" {
		maxSev = &rec.MaxSeverity
	}
	if rec.LastError != "" {
		lastErr = &rec.LastError
	}
	_, err = c.st.Queries().UpsertMCPServerScan(ctx, storegen.UpsertMCPServerScanParams{
		Ecosystem: rec.Ecosystem, Package: rec.Package, Version: rec.Version,
		Status: rec.Status, MaxSeverity: maxSev, Advisories: advs, LastError: lastErr,
	})
	return err
}

// mcpScanRecordFromRow converts a registry row.
func mcpScanRecordFromRow(row storegen.McpServerScan) *MCPScanRecord {
	rec := &MCPScanRecord{
		Ecosystem: row.Ecosystem, Package: row.Package, Version: row.Version, Status: row.Status,
		FirstSeen: row.FirstSeenAt, LastChecked: row.LastCheckedAt,
	}
	if row.MaxSeverity != nil {
		rec.MaxSeverity = *row.MaxSeverity
	}
	if row.LastError != nil {
		rec.LastError = *row.LastError
	}
	_ = json.Unmarshal(row.Advisories, &rec.Advisories)
	return rec
}

// persistStage writes one stage's findings and its (scan_run_id, scanner)
// result row in a single transaction, so a stage is never recorded complete
// without its findings.
func (p *Pipeline) persistStage(ctx context.Context, runID uuid.UUID, res StageResult) error {
	if res.Skipped {
		return nil
	}
	status := "ok"
	detail := map[string]any{"findings": len(res.Findings)}
	if len(res.Knowledge) > 0 {
		// SK's record of what it read: the report's shipped-pack section,
		// kept so a resumed run reports it as a fresh one would.
		detail[knowledgeRecordKey] = res.Knowledge
	}
	if res.Err != nil {
		status = "error"
		detail["error"] = res.Err.Error()
	}
	detailJSON, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	return p.st.WithTx(ctx, func(q *storegen.Queries) error {
		// Replace, don't accumulate: a stage that runs again (a redelivered
		// job, or an errored stage re-attempted) must not leave the reviewer
		// reading two copies of the same finding.
		if err := q.DeleteFindingsForScanner(ctx, storegen.DeleteFindingsForScannerParams{
			ScanRunID: runID, Scanner: res.Scanner,
		}); err != nil {
			return err
		}
		for _, f := range res.Findings {
			if err := insertFinding(ctx, q, runID, f); err != nil {
				return err
			}
		}
		return q.UpsertStageResult(ctx, storegen.UpsertStageResultParams{
			ScanRunID: runID, Scanner: res.Scanner, Status: status, Detail: detailJSON,
		})
	})
}

// assemblyScanner tags the findings S10 adds while assembling the report
// rather than any single stage — today the S0/pipeline-error that a stage
// failure produces (§7 fail-closed).
const assemblyScanner = "S0"

func insertFinding(ctx context.Context, q *storegen.Queries, runID uuid.UUID, f Finding) error {
	detail, err := json.Marshal(f.Detail)
	if err != nil {
		return err
	}
	var linePtr, lineEnd *int32
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
	_, err = q.InsertFinding(ctx, storegen.InsertFindingParams{
		ID: newUUID(), ScanRunID: runID, Scanner: f.Scanner,
		Severity: string(f.Severity), Confidence: string(f.Confidence),
		Title: f.Title, FilePath: filePtr, LineStart: linePtr, LineEnd: lineEnd,
		Excerpt: excerptPtr, Detail: detail,
	})
	return err
}

// findingFromRow rebuilds a pipeline finding from its persisted row, so a
// resumed run reports and gates on the same set a fresh one would.
func findingFromRow(row storegen.Finding) Finding {
	f := Finding{
		Scanner: row.Scanner, Severity: Severity(row.Severity),
		Confidence: Confidence(row.Confidence), Title: row.Title,
	}
	if row.FilePath != nil {
		f.FilePath = *row.FilePath
	}
	if row.LineStart != nil {
		f.LineStart = int(*row.LineStart)
	}
	if row.LineEnd != nil {
		f.LineEnd = int(*row.LineEnd)
	}
	if row.Excerpt != nil {
		f.Excerpt = *row.Excerpt
	}
	if len(row.Detail) > 0 {
		var d map[string]any
		if json.Unmarshal(row.Detail, &d) == nil {
			f.Detail = d
		}
	}
	return f
}

// stageOf maps a finding's scanner id back to the stage that produced it:
// stages tag findings as "S4/inj-override-001" or "S5/C1_injection".
func stageOf(scanner string) string {
	for i := 0; i < len(scanner); i++ {
		if scanner[i] == '/' {
			return scanner[:i]
		}
	}
	return scanner
}

// finishRun closes the scan run: the assembly-time findings, then status,
// report digest and judge prompt hash.
func (p *Pipeline) finishRun(ctx context.Context, runID uuid.UUID, result RunResult) error {
	status := "passed"
	if len(result.Findings) > 0 {
		status = "findings"
	}
	if len(result.Report.StageErrors) > 0 {
		status = "error"
	}
	var promptHash *string
	if result.JudgePromptHash != "" {
		promptHash = &result.JudgePromptHash
	}
	var promptTokens, completionTokens *int32
	if u := result.JudgeUsage; u != nil {
		pt, ct := int32(u.PromptTokens), int32(u.CompletionTokens) //nolint:gosec // a judge reply is bounded well below MaxInt32
		promptTokens, completionTokens = &pt, &ct
	}
	err := p.st.WithTx(ctx, func(q *storegen.Queries) error {
		// The S0/pipeline-error finding is added by S10 while assembling the
		// report, not by any stage, so no per-stage write covers it. It is
		// the finding that explains why a version with a failed stage went to
		// review at all — losing it would leave that decision unexplained.
		if err := q.DeleteFindingsForScanner(ctx, storegen.DeleteFindingsForScannerParams{
			ScanRunID: runID, Scanner: assemblyScanner,
		}); err != nil {
			return err
		}
		for _, f := range result.Findings {
			if stageOf(f.Scanner) != assemblyScanner {
				continue
			}
			if err := insertFinding(ctx, q, runID, f); err != nil {
				return err
			}
		}
		return q.FinishScanRun(ctx, storegen.FinishScanRunParams{
			ID: runID, Status: status, ReportDigest: strptr(result.ReportDigest),
			JudgeModel:      strptr(result.JudgeModel),
			JudgePromptHash: promptHash, JudgePromptTokens: promptTokens, JudgeCompletionTokens: completionTokens,
		})
	})
	if err == nil && result.JudgeUsage != nil {
		// Counted once the run row holds them, so the metric and the rows agree.
		p.mx.RecordJudgeTokens(ctx, result.JudgeUsage.PromptTokens, result.JudgeUsage.CompletionTokens)
	}
	return err
}

// applyDecision maps the gate outcome onto §7 transitions and, on publish,
// signs the attestation.
func (p *Pipeline) applyDecision(ctx context.Context, agent storegen.GetAgentByIDRow, v storegen.AgentVersion, runID uuid.UUID, result RunResult, policyVer int) error {
	// §9.3 catalog (agentry#56): the scan finished, whatever the gate says
	// next; subscribers that want the outcome also get the version.* event.
	counts := map[string]int{}
	for _, f := range result.Findings {
		counts[string(f.Severity)]++
	}
	p.reg.EmitAgentEvent(ctx, agent.ID, webhook.EventScanCompleted, map[string]any{
		"version": v.Version, "versionId": v.ID.String(), "runId": runID.String(), "reportDigest": result.ReportDigest,
		"findings": counts, "reason": result.Decision.Reason, "outcome": string(result.Decision.Outcome),
	})
	sysEvent := audit.Event{ActorKind: audit.ActorSystem}
	// The gate's decision, named for the log contract (docs/logging.md):
	// one line per verdict where it is acted on, and a second, `gate.error`,
	// when the platform's own failure is what sent the version to review.
	p.log.InfoContext(ctx, "gate: verdict", logevent.GateVerdict.Attr(),
		"outcome", string(result.Decision.Outcome), "version", v.ID, "agent", agent.ID, "run", runID,
		"worst_severity", string(result.Decision.WorstSeverity), "findings", len(result.Findings), "reason", result.Decision.Reason)
	if len(result.Report.StageErrors) > 0 {
		p.log.WarnContext(ctx, "gate: stage errors routed the version to review", logevent.GateError.Attr(),
			"version", v.ID, "run", runID, "stage_errors", result.Report.StageErrors)
	}
	// §16.2 publish funnel: one verdict per version, recorded where the
	// decision is acted on rather than where it is computed (the orchestrator
	// can run more than once for a version — rescans, resumes).
	// The verdict applies to the version the scan was of — one still in
	// `scanning`. A scan that outlived the watchdog's cap finds its version
	// already handed to a reviewer (needs_review, a review item filed, the
	// author told); its late verdict must not publish or reject over that,
	// so every transition here holds the row and requires `scanning`
	// (registry.TransitionFrom, agentry#343). A moved version keeps its
	// run and its findings on record and gets nothing else from this call.
	moved := func(err error) error {
		if errors.Is(err, registry.ErrVersionMoved) {
			p.log.WarnContext(ctx, "gate: verdict reached a version that had moved; not applied",
				"version", v.ID, "agent", agent.ID, "run", runID, "outcome", string(result.Decision.Outcome), "err", err)
			return nil
		}
		return err
	}
	switch result.Decision.Outcome {
	case OutcomePublish:
		p.mx.RecordVerdict(ctx, metrics.VerdictClean)
		return moved(p.publishUnderLock(ctx, agent, v, registry.StatusScanning, runID, result, policyVer, result.Decision.Reason, nil))

	case OutcomeRejected:
		p.mx.RecordVerdict(ctx, metrics.VerdictBlocked)
		return moved(p.reg.TransitionFrom(ctx, v.ID, registry.StatusScanning, registry.StatusRejected, result.Decision.Reason, sysEvent, registry.TransitionCause{}))

	case OutcomeNeedsReview:
		p.mx.RecordVerdict(ctx, metrics.VerdictReview)
		// A stage error is the platform's own fault: the transition says so
		// (registry.TransitionCause), which is what an extension that
		// charged for the submission refunds on.
		cause := registry.TransitionCause{PipelineError: len(result.Report.StageErrors) > 0, ScanRunID: runID}
		if err := p.reg.TransitionFrom(ctx, v.ID, registry.StatusScanning, registry.StatusNeedsReview, result.Decision.Reason, sysEvent, cause); err != nil {
			return moved(err)
		}
		if err := p.st.WithTx(ctx, func(q *storegen.Queries) error {
			return createReviewItem(ctx, q, v.ID, agent, result.Decision.Queue)
		}); err != nil {
			return err
		}
		p.notifyHeldForReview(ctx, agent, v, result.Decision.Reason)
		return nil
	}
	return nil
}

// publishUnderLock publishes a version the gate passed, from the run that
// judged it. The attestation and the transition to `published` are one
// transaction under the version's row lock. When the transition came first
// and the signature last, a signing failure (a KMS outage, the empty-digest
// refusal) left a published, unattested version, and the retry's fresh run
// found the row moved and swallowed the verdict — "scanned, N findings,
// signed" false for it forever (security review 2026-09-20 §5.4). Signing
// before the transition, outside a transaction, would sign a version the
// watchdog had meanwhile held for review. So: lock the row, refuse a version
// no longer in `from` (registry.ErrVersionMoved), run the route's own step
// (inTx, nil for a submission), sign, transition, commit — a failure
// anywhere leaves the version where it was with no attestation, and the
// queue's retry finishes the job. The attest sweep backfills anything that
// still slips through. A submission publishes from `scanning`; a new
// ruleset's redo of the review queue from `needs_review` (agentry#772).
func (p *Pipeline) publishUnderLock(ctx context.Context, agent storegen.GetAgentByIDRow, v storegen.AgentVersion,
	from registry.Status, runID uuid.UUID, result RunResult, policyVer int, reason string,
	inTx func(q *storegen.Queries) error,
) error {
	var res registry.TransitionResult
	err := p.st.WithTx(ctx, func(q *storegen.Queries) error {
		row, err := q.GetVersionForUpdate(ctx, v.ID)
		if err != nil {
			return fmt.Errorf("scan: lock version: %w", err)
		}
		if registry.Status(row.Status) != from {
			return fmt.Errorf("%w: %s is %s, the decision was made from %s", registry.ErrVersionMoved, row.Version, row.Status, from)
		}
		if inTx != nil {
			if err := inTx(q); err != nil {
				return err
			}
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
	res.Cause = registry.TransitionCause{}
	p.reg.EmitTransition(ctx, res)
	p.indexReadme(ctx, agent.ID, v)
	return nil
}

// notifyHeldForReview tells a version's author the gate held it for a
// human (§8.7; agentry#274): the one outcome an author would otherwise
// learn only by looking. Sent on a fresh submission's transition to
// needs_review — the gate's own verdict and the pipeline-error route
// alike — never on a rescan, whose review item concerns a version the
// author already has published. Best-effort, like the decision mail: the
// review item is the record, and it is already written.
func (p *Pipeline) notifyHeldForReview(ctx context.Context, agent storegen.GetAgentByIDRow, v storegen.AgentVersion, reason string) {
	if p.notifier == nil {
		return
	}
	q := p.st.Queries()
	author, err := q.GetUserByID(ctx, v.SubmittedBy)
	if err != nil {
		p.log.Error("held-for-review notification: load author", "version", v.ID, "err", err)
		return
	}
	if !notify.AllowsEmail(ctx, q, p.log, author.ID, notify.KindReviewDecision) {
		return // unverified address, or the author switched review mails off (#299, #190)
	}
	// The transition's reason rides as the rationale: the gate's verdict
	// ("wildcard egress: review"), or what stopped the scan, which is what
	// happened rather than a gate that could not decide.
	if err := p.notifier.ReviewDecided(ctx, notify.ReviewNotice{
		ToEmail:   author.Email,
		Agent:     agent.Namespace + "/" + agent.Name,
		Version:   v.Version,
		Decision:  string(registry.StatusNeedsReview),
		Rationale: reason,
	}); err != nil {
		p.log.Error("held-for-review notification", "version", v.ID, "err", err)
	}
}

// indexReadme denormalizes the just-published version's README onto the agent
// row so the §10.4 weight-C part of search_tsv has text to index.
//
// Best-effort by design: an agent whose README could not be read is still
// published, just less findable. Failing the publish over a search-index
// detail would turn a cosmetic problem into an outage of the thing the
// registry is for. Runs after the transition so it only ever indexes text
// that is actually resolvable.
func (p *Pipeline) indexReadme(ctx context.Context, agentID uuid.UUID, v storegen.AgentVersion) {
	if v.ArchiveKey == nil || p.blobs == nil {
		return
	}
	raw, err := ExtractREADME(ctx, p.blobs, *v.ArchiveKey, v.ArchiveSize)
	if err != nil {
		if !errors.Is(err, ErrNoReadme) {
			p.log.Warn("scan: readme index skipped", "version", v.ID, "err", err)
		}
		// An agent that had a README and then removed it should stop being
		// found by its old text, so an absent README clears the column rather
		// than leaving the previous version's prose indexed.
		raw = nil
	}
	if err := p.st.Queries().SetAgentReadmeText(ctx, storegen.SetAgentReadmeTextParams{
		ID: agentID, ReadmeText: ReadmeIndexText(raw),
	}); err != nil {
		p.log.Warn("scan: readme index write failed", "agent", agentID, "err", err)
	}
}

// createReviewItem files a version for human review on the right queue
// (§8.6). org_id is set only for the org queue, which is the only queue that
// has an owner to scope to. Re-filing an already-pending item is a no-op.
func createReviewItem(ctx context.Context, q *storegen.Queries, versionID uuid.UUID, agent storegen.GetAgentByIDRow, queue string) error {
	if queue != "org" {
		queue = "platform"
	}
	var orgID *uuid.UUID
	if queue == "org" && agent.NamespaceKind == "org" {
		id := agent.NamespaceID
		orgID = &id
	}
	if queue == "org" && orgID == nil {
		// Defensive: an org-queue item with no org is undecidable. The gate
		// no longer produces one; if anything ever does, it lands where a
		// human can actually see it.
		queue = "platform"
	}
	_, err := q.CreateReviewItem(ctx, storegen.CreateReviewItemParams{
		ID: newUUID(), VersionID: versionID, Queue: queue, OrgID: orgID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil // already pending for this version
	}
	return err
}

// FailToReview implements the §7 fail-closed rule: a version whose scan could
// not complete is recorded as an errored run with an S0/pipeline-error
// finding and routed to human review — never silently published, and never
// left parked in `scanning`. Idempotent.
func (p *Pipeline) FailToReview(ctx context.Context, v storegen.AgentVersion, agent storegen.GetAgentByIDRow, trigger, kind string, cause error) error {
	if trigger != "publish" && trigger != "rescan" && trigger != "manual" {
		trigger = "manual"
	}
	snapshot, err := json.Marshal(DefaultBaseline())
	if err != nil {
		return err
	}
	runID := newUUID()
	q := p.st.Queries()
	if _, err := q.CreateScanRun(ctx, storegen.CreateScanRunParams{
		ID: runID, VersionID: v.ID, Trigger: trigger,
		RulesetReleaseID: p.rulesetID, PolicySnapshot: snapshot,
		JudgeModel: strptr(judgeModelOf(p.orch.judge)),
	}); err != nil {
		return fmt.Errorf("scan: create failure run: %w", err)
	}
	reason := "The pipeline could not complete this scan (" + kind + "), so the version went to human review."
	p.log.WarnContext(ctx, "gate: pipeline failure routed the version to review", logevent.GateError.Attr(),
		"version", v.ID, "agent", agent.ID, "run", runID, "kind", kind, "trigger", trigger, "err", cause)
	finding := Finding{
		Scanner: "S0/pipeline-error", Severity: SevMedium, Confidence: ConfHigh,
		Title:  "Pipeline could not complete — routed to human review",
		Detail: map[string]any{"stage": kind, "error": cause.Error()},
	}
	if err := p.st.WithTx(ctx, func(tx *storegen.Queries) error {
		if err := insertFinding(ctx, tx, runID, finding); err != nil {
			return err
		}
		return tx.FinishScanRun(ctx, storegen.FinishScanRunParams{ID: runID, Status: "error"})
	}); err != nil {
		return err
	}

	// Only versions still in flight move; a rescan failure must not drag a
	// published version backwards.
	// The row is held for the check (registry.TransitionFrom): a version
	// another route moved first — the watchdog, or a verdict that landed
	// while this was under way — stays where that route put it, and this
	// call still files the run's finding (agentry#343).
	held := false
	if registry.Status(v.Status) == registry.StatusScanning {
		err := p.reg.TransitionFrom(ctx, v.ID, registry.StatusScanning, registry.StatusNeedsReview, reason,
			audit.Event{ActorKind: audit.ActorSystem},
			registry.TransitionCause{PipelineError: true, ScanRunID: runID})
		switch {
		case errors.Is(err, registry.ErrVersionMoved):
			p.log.WarnContext(ctx, "gate: pipeline failure reached a version that had moved; not re-routed",
				"version", v.ID, "run", runID, "err", err)
		case err != nil:
			return err
		default:
			held = true
		}
	}
	queue := "platform"
	if agent.NamespaceKind == "org" {
		queue = "org"
	}
	if err := p.st.WithTx(ctx, func(tx *storegen.Queries) error {
		return createReviewItem(ctx, tx, v.ID, agent, queue)
	}); err != nil {
		return err
	}
	if held {
		p.notifyHeldForReview(ctx, agent, v, reason)
	}
	return nil
}

// ReconcileStuckScans is the §7 watchdog: versions that entered `scanning`
// and never came out (terminally failed job, worker killed mid-DAG) are
// routed to review with an S0/pipeline-error finding once they pass the
// 30-minute cap. Without it a lost scan job parked a version forever, visible
// to nobody. Returns how many it moved.
func (p *Pipeline) ReconcileStuckScans(ctx context.Context) (int, error) {
	cutoff := time.Now().Add(-StuckScanCap)
	rows, err := p.st.Queries().ListStuckScanningVersions(ctx, storegen.ListStuckScanningVersionsParams{
		UpdatedAt: cutoff, Limit: 200,
	})
	if err != nil {
		return 0, fmt.Errorf("scan: list stuck scans: %w", err)
	}
	moved := 0
	for _, v := range rows {
		agent, err := p.st.Queries().GetAgentByID(ctx, v.AgentID)
		if err != nil {
			p.log.Error("scan: watchdog agent lookup", "version", v.ID, "err", err)
			continue
		}
		cause := fmt.Errorf("this version stayed in scanning past the %s cap, so the watchdog routed it to human review", StuckScanCap)
		if err := p.FailToReview(ctx, v, agent, "publish", "timeout", cause); err != nil {
			p.log.Error("scan: watchdog could not fail version to review", "version", v.ID, "err", err)
			continue
		}
		p.log.Warn("scan: stuck version routed to review", "version", v.ID, "agent", agent.Name)
		moved++
	}
	return moved, nil
}

// sign builds and stores the DSSE attestation on → published (§8.8). Signing
// happens exactly once per version (§7): quarantine/reinstate and a re-review
// that republishes never re-issue it.
func (p *Pipeline) sign(ctx context.Context, q *storegen.Queries, agent storegen.GetAgentByIDRow, v storegen.AgentVersion, runID uuid.UUID, reportDigest, judgeModel string, policyVer int) error {
	if _, err := q.GetAttestation(ctx, v.ID); err == nil {
		return nil // already signed (§7: exactly once)
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("scan: attestation lookup: %w", err)
	}
	if p.signer == nil {
		// A process without the key never publishes a version that has no
		// attestation: the transaction this runs in rolls back (agentry#479).
		// Publishing is the worker's, which holds the key.
		return ErrNoSigningKey
	}
	if reportDigest == "" {
		// The attestation's whole claim is "this report describes these
		// bytes". Signing an empty digest asserts nothing while looking
		// exactly like a valid attestation (§8.8).
		return fmt.Errorf("scan: refusing to sign version %s with an empty report digest", v.ID)
	}
	digest := ""
	if v.ArchiveDigest != nil {
		digest = *v.ArchiveDigest
	}
	stmt := BuildStatement(
		p.registryURL, agent.Namespace+"/"+agent.Name, v.Version, digest, v.CommitSha, v.Source,
		ScanRunRef{ID: runID.String(), RulesetVer: p.rulesetVer, ReportDigest: reportDigest, JudgeModel: judgeModel},
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
	_, err = q.CreateAttestation(ctx, storegen.CreateAttestationParams{
		ID: newUUID(), VersionID: v.ID, PredicateType: PredicateType,
		DsseEnvelope: envJSON, KeyID: p.signer.KeyID(),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil // raced with another writer; the row exists
	}
	return err
}

// effectivePolicy resolves baseline ← org overlay (§8.6). An org document
// that will not parse is an error, not a reason to fall back to the looser
// platform baseline: org policies may only TIGHTEN, so a silent fallback
// hands the org the opposite of what it configured.
func (p *Pipeline) effectivePolicy(ctx context.Context, agent storegen.GetAgentByIDRow) (Policy, int, error) {
	return effectivePolicyFor(ctx, p.st.Queries(), agent.NamespaceKind, agent.NamespaceID)
}

func effectivePolicyFor(ctx context.Context, q *storegen.Queries, namespaceKind string, namespaceID uuid.UUID) (Policy, int, error) {
	baseline := DefaultBaseline()
	version := 1
	row, err := q.GetBaselinePolicy(ctx)
	switch {
	case err == nil:
		parsed, perr := ParsePolicy(row.Document)
		if perr != nil {
			return Policy{}, 0, fmt.Errorf("scan: platform baseline policy: %w", perr)
		}
		baseline, version = parsed, int(row.Version)
	case errors.Is(err, pgx.ErrNoRows):
		// No stored baseline: the compiled-in default is the baseline.
	default:
		return Policy{}, 0, fmt.Errorf("scan: load baseline policy: %w", err)
	}

	if namespaceKind != "org" {
		return baseline, version, nil
	}
	orgRow, err := q.GetPolicyForOrg(ctx, &namespaceID)
	switch {
	case err == nil:
		org, perr := ParsePolicy(orgRow.Document)
		if perr != nil {
			return Policy{}, 0, fmt.Errorf("scan: org policy: %w", perr)
		}
		return Merge(baseline, org), version + int(orgRow.Version), nil
	case errors.Is(err, pgx.ErrNoRows):
		return baseline, version, nil
	default:
		return Policy{}, 0, fmt.Errorf("scan: load org policy: %w", err)
	}
}

func newUUID() uuid.UUID {
	id, err := uuid.NewV7()
	if err != nil {
		panic(err)
	}
	return id
}

func strptr(s string) *string { return &s }

// ReviewDecision is one reviewer verdict on a review item (§8.6).
type ReviewDecision struct {
	ItemID    uuid.UUID
	VersionID uuid.UUID
	// Target is the §7 state the decision moves the version to.
	Target registry.Status
	// State is the review_items state ("approved" | "rejected").
	State     string
	Rationale string
	DecidedBy uuid.UUID
	// SelfDecision marks platform staff deciding a version they submitted
	// (agentry#912): allowed, and recorded in the audit event's detail so
	// it stays visible after the fact.
	SelfDecision bool
	// Audit is the caller's audit event (actor, request context); the action
	// and target are filled in here.
	Audit audit.Event
}

// DecideReview records a reviewer's verdict AND performs the §7 transition in
// one transaction, signing on approve→published.
//
// These used to be two commits. A transient failure between them left the
// item marked decided while the version stayed in needs_review — and the
// handler's "already decided" guard then refused every retry, so the version
// was stuck with no way forward but a manual database edit.
//
// A process that holds no signing key (the api role, agentry#479) cannot
// publish a version that has no attestation yet. It records the verdict and
// hands the publish to the worker (JobPublishApproved), which transitions
// and signs in one transaction; until then the version stays in
// needs_review, and the watchdog finishes an approval whose job was lost.
// A version that already carries its attestation (a quarantined one being
// reinstated) is published here as before: nothing needs signing.
//
// handedOff reports that the publish was handed to the worker, so the
// caller does not announce a publication that has not happened yet.
func (p *Pipeline) DecideReview(ctx context.Context, in ReviewDecision) (handedOff bool, err error) {
	var trans registry.TransitionResult
	handOff := false
	err = p.st.WithTx(ctx, func(q *storegen.Queries) error {
		v, err := q.GetVersionByID(ctx, in.VersionID)
		if err != nil {
			return err
		}
		agent, err := q.GetAgentByID(ctx, v.AgentID)
		if err != nil {
			return err
		}
		if in.Target == registry.StatusPublished && p.signer == nil {
			if _, aerr := q.GetAttestation(ctx, v.ID); errors.Is(aerr, pgx.ErrNoRows) {
				if registry.Status(v.Status) != registry.StatusNeedsReview {
					// Only a held submission is handed off; anything else
					// unsigned needs the key here, and this process has none.
					return ErrNoSigningKey
				}
				// Refuse now what the worker could not sign later, so the
				// verdict is not committed with nothing able to act on it
				// and the reviewer can retry, as before the hand-off.
				if run, rerr := q.LatestFinishedScanRunForVersion(ctx, v.ID); rerr != nil {
					return fmt.Errorf("scan: latest run for review decision: %w", rerr)
				} else if run.ReportDigest == nil || *run.ReportDigest == "" {
					return fmt.Errorf("scan: version %s has no finished scan report to sign", v.ID)
				}
				handOff = true
			} else if aerr != nil {
				return fmt.Errorf("scan: attestation lookup: %w", aerr)
			}
		}
		n, err := q.DecideReviewItem(ctx, storegen.DecideReviewItemParams{
			ID: in.ItemID, State: in.State, DecidedBy: &in.DecidedBy, Rationale: &in.Rationale,
		})
		if err != nil {
			return err
		}
		if n == 0 {
			return fmt.Errorf("%w: the review item was already decided", ErrAlreadyDecided)
		}
		e := in.Audit
		e.Action = audit.ActionReviewDecision
		e.TargetKind, e.TargetID = "review_item", in.ItemID
		e.Detail = map[string]any{
			"decision": in.State, "version_id": in.VersionID.String(), "target": string(in.Target),
		}
		if in.SelfDecision {
			e.Detail["self_decision"] = true
		}
		if err := p.aud.Write(ctx, q, e); err != nil {
			return err
		}
		if handOff {
			// The worker transitions and signs (PublishApproved); the mark is
			// what it and the watchdog act on.
			return q.SetReviewPublishPending(ctx, storegen.SetReviewPublishPendingParams{ID: in.ItemID, PublishPending: true})
		}
		trans, err = p.reg.TransitionInTx(ctx, q, in.VersionID, in.Target, "review: "+in.Rationale, audit.Event{
			ActorKind: audit.ActorSystem,
		})
		if err != nil {
			return err
		}
		if in.Target != registry.StatusPublished {
			return nil
		}
		// Signing is part of the same unit of work: a published version
		// without an attestation is not something to reconcile later.
		return p.signReviewed(ctx, q, agent, v)
	})
	if err != nil {
		return false, err
	}
	if handOff {
		if p.jobs == nil {
			p.log.Error("review: approval recorded but no queue to hand the publish to; the watchdog will publish it",
				"item", in.ItemID, "version", in.VersionID)
			return true, nil
		}
		if _, err := p.jobs.Enqueue(ctx, JobPublishApproved, "core", PublishApprovedArgs{ItemID: in.ItemID}); err != nil {
			// The verdict is committed and the item is marked: the
			// watchdog publishes it.
			p.log.Error("review: could not enqueue the publish; the watchdog will publish it",
				"item", in.ItemID, "version", in.VersionID, "err", err)
		}
		return true, nil
	}
	p.reg.EmitTransition(ctx, trans)
	return false, nil
}

// signReviewed signs a version a reviewer published, from its latest
// finished scan run (the one the review bundle showed), inside the caller's
// transaction. A run still going, a new ruleset's redo of the queue
// (agentry#772), has no report to sign and is not what the reviewer read.
func (p *Pipeline) signReviewed(ctx context.Context, q *storegen.Queries, agent storegen.GetAgentByIDRow, v storegen.AgentVersion) error {
	run, err := q.LatestFinishedScanRunForVersion(ctx, v.ID)
	if err != nil {
		return fmt.Errorf("scan: latest run for review decision: %w", err)
	}
	reportDigest := ""
	if run.ReportDigest != nil {
		reportDigest = *run.ReportDigest
	}
	judge := ""
	if run.JudgeModel != nil {
		judge = *run.JudgeModel
	}
	_, policyVer, err := effectivePolicyFor(ctx, q, agent.NamespaceKind, agent.NamespaceID)
	if err != nil {
		return err
	}
	return p.sign(ctx, q, agent, v, run.ID, reportDigest, judge, policyVer)
}

// PublishApproved publishes and signs, in one transaction, a version whose
// review item a keyless role approved (agentry#479). It runs where the key
// is: the worker's publish job, or the watchdog. Idempotent: an item that is
// not approved, or a version no longer in needs_review, is left alone, so a
// redelivered job or a job racing the watchdog does nothing the second time.
func (p *Pipeline) PublishApproved(ctx context.Context, itemID uuid.UUID) error {
	if p.signer == nil {
		return ErrNoSigningKey
	}
	var trans registry.TransitionResult
	published := false
	err := p.st.WithTx(ctx, func(q *storegen.Queries) error {
		item, err := q.GetReviewItem(ctx, itemID)
		if err != nil {
			return fmt.Errorf("scan: review item: %w", err)
		}
		if !item.PublishPending || item.State != "approved" {
			return nil
		}
		v, err := q.GetVersionForUpdate(ctx, item.VersionID)
		if err != nil {
			return fmt.Errorf("scan: lock version: %w", err)
		}
		done := storegen.SetReviewPublishPendingParams{ID: itemID, PublishPending: false}
		if registry.Status(v.Status) != registry.StatusNeedsReview {
			// Moved on without this job (yanked, say): nothing to publish.
			return q.SetReviewPublishPending(ctx, done)
		}
		agent, err := q.GetAgentByID(ctx, v.AgentID)
		if err != nil {
			return err
		}
		rationale := ""
		if item.Rationale != nil {
			rationale = *item.Rationale
		}
		trans, err = p.reg.TransitionInTx(ctx, q, v.ID, registry.StatusPublished, "review: "+rationale, audit.Event{
			ActorKind: audit.ActorSystem,
		})
		if err != nil {
			return err
		}
		published = true
		if err := p.signReviewed(ctx, q, agent, v); err != nil {
			return err
		}
		return q.SetReviewPublishPending(ctx, done)
	})
	if err != nil {
		return err
	}
	if published {
		p.reg.EmitTransition(ctx, trans)
	}
	return nil
}

// approvalGrace is how long an approval waits for its publish job before the
// watchdog publishes it itself.
const approvalGrace = time.Minute

// ReconcileApprovedReviews publishes every approval a keyless role handed
// off whose publish never happened (a lost enqueue, a job that ran out of
// attempts). Run by the watchdog in the worker; a process without the key
// does nothing.
func (p *Pipeline) ReconcileApprovedReviews(ctx context.Context) (int, error) {
	if p.signer == nil {
		return 0, nil
	}
	ids, err := p.st.Queries().ListApprovedReviewsAwaitingPublish(ctx,
		pgtype.Interval{Microseconds: approvalGrace.Microseconds(), Valid: true})
	if err != nil {
		return 0, fmt.Errorf("scan: approvals awaiting publish: %w", err)
	}
	done := 0
	for _, id := range ids {
		if err := p.PublishApproved(ctx, id); err != nil {
			p.log.Error("watchdog: could not publish an approved version", "item", id, "err", err)
			continue
		}
		done++
	}
	return done, nil
}

// Quarantine/Block/Reinstate implement the T&S platform actions (§7).
func (p *Pipeline) Quarantine(ctx context.Context, versionID uuid.UUID, reason string, ev audit.Event) error {
	return p.reg.Transition(ctx, versionID, registry.StatusQuarantined, reason, ev)
}

// PublishAdvisory records a security advisory for an agent (§8.7) and
// announces it on the org's webhooks.
func (p *Pipeline) PublishAdvisory(ctx context.Context, agentID uuid.UUID, affected, severity, summary, detail string) error {
	adv, err := p.st.Queries().CreateAdvisory(ctx, storegen.CreateAdvisoryParams{
		ID: newUUID(), AgentID: agentID, AffectedVersions: affected,
		Severity: severity, Summary: summary, Detail: strptrOrNil(detail),
	})
	if err != nil {
		return err
	}
	p.reg.EmitAgentEvent(ctx, agentID, webhook.EventAdvisoryPublished, map[string]any{
		"advisoryId": adv.ID.String(), "affectedVersions": affected,
		"severity": severity, "summary": summary,
	})
	p.notifyAdvisoryPublished(ctx, agentID, affected, severity, summary)
	return nil
}

// notifyAdvisoryPublished mails the agent's author (§8.7 lists the advisory
// alongside the webhook and the author notification). Best-effort: the
// advisory is the record that matters, and it is already written.
//
// §7 is explicit that installed copies are never reached, so the advisory and
// this mail ARE the notification path — which is why a failure here is logged
// at error rather than swallowed.
func (p *Pipeline) notifyAdvisoryPublished(ctx context.Context, agentID uuid.UUID, affected, severity, summary string) {
	if p.notifier == nil {
		return
	}
	q := p.st.Queries()
	agent, err := q.GetAgentByID(ctx, agentID)
	if err != nil {
		p.log.Error("advisory notification: load agent", "agent", agentID, "err", err)
		return
	}
	// The author of the latest published version is the person who can act on
	// this; an agent with nothing published has no one to tell.
	if agent.LatestPublishedVersionID == nil {
		return
	}
	v, err := q.GetVersionByID(ctx, *agent.LatestPublishedVersionID)
	if err != nil {
		p.log.Error("advisory notification: load version", "agent", agentID, "err", err)
		return
	}
	u, err := q.GetUserByID(ctx, v.SubmittedBy)
	if err != nil {
		p.log.Error("advisory notification: load author", "agent", agentID, "err", err)
		return
	}
	if !notify.AllowsEmail(ctx, q, p.log, u.ID, notify.KindAdvisory) {
		return // unverified address, or the author switched these off (#299, #190)
	}
	if err := p.notifier.AdvisoryPublished(ctx, notify.AdvisoryNotice{
		ToEmail:          u.Email,
		Agent:            agent.Namespace + "/" + agent.Name,
		Severity:         severity,
		Summary:          summary,
		AffectedVersions: affected,
	}); err != nil {
		p.log.Error("advisory notification", "agent", agentID, "err", err)
	}
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

// SetRulesetForTest points the pipeline at another ruleset release, so a
// test can register "the next ruleset" without shipping a second bundle
// (agentry#772). Not for production use.
func (p *Pipeline) SetRulesetForTest(id uuid.UUID, semver string) {
	p.rulesetID, p.rulesetVer = id, semver
}

// SetRescanBatchForTest shrinks the sweep page size so paging behaviour is
// exercisable without publishing hundreds of versions. Not for production use.
func (p *Pipeline) SetRescanBatchForTest(n int32) { p.rescanBatch = n }

// historyReader returns the S2 history stream for a git-tag version, or nil
// when this role has no repository access.
func (p *Pipeline) historyReader(repoID uuid.UUID, commit string) func(ctx context.Context) (io.ReadCloser, error) {
	if p.gitHistory == nil || commit == "" {
		return nil
	}
	return func(ctx context.Context) (io.ReadCloser, error) {
		return p.gitHistory.HistoryPatch(ctx, repoID, commit)
	}
}
