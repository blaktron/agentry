package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/auth"
	"github.com/blaktron/agentry/internal/entitlements"
	storegen "github.com/blaktron/agentry/internal/store/gen"
	"github.com/blaktron/agentry/pkg/manifest"
)

// Status is a publication state (§7). The state machine lives on
// agent_versions.status; every transition is audited and executed under
// SELECT … FOR UPDATE (single writer).
type Status string

// Publication states (§7).
const (
	StatusSubmitted   Status = "submitted"
	StatusScanning    Status = "scanning"
	StatusNeedsReview Status = "needs_review"
	// StatusApproved is RESERVED and never written (DEV-046, agentry#32):
	// review collapses approval and publication into one
	// needs_review → published transition so the §7 "no path to published
	// skips the gate" property is one edge, and no version can be stranded
	// between the two. It stays in the enum because narrowing it is a
	// breaking API change; readers must tolerate it and will not see it.
	StatusApproved    Status = "approved"
	StatusPublished   Status = "published"
	StatusRejected    Status = "rejected"
	StatusYanked      Status = "yanked"
	StatusQuarantined Status = "quarantined"
	StatusBlocked     Status = "blocked"
)

// allowedTransitions encodes the §7 diagram. Keys are from-states.
//
// submitted → published is the one edge that does not pass the gate
// (M21, agentry#368; plan organization-subscriptions §4, D16): it is
// taken only by a version an organization's administrator chose to have
// admitted unscanned — scan_status = skipped, which SubmitVersion sets
// before the edge and TransitionInTx checks under the row lock — and such
// a version exists only on a private agent of the organization's, which
// cannot become public while it is published. For public content the §7
// property is unchanged: nothing reaches published except from scanning,
// needs_review or quarantined (TestNoPathToPublishedSkipsTheGateForAPublicAgent).
var allowedTransitions = map[Status][]Status{
	StatusSubmitted:   {StatusScanning, StatusPublished},
	StatusScanning:    {StatusPublished, StatusNeedsReview, StatusRejected},
	StatusNeedsReview: {StatusPublished, StatusRejected},
	// published → blocked is not drawn in the §7 diagram, which reaches
	// blocked only via quarantined. T&S confirming a malicious PUBLISHED
	// package needs one atomic step, not a quarantine it must immediately
	// supersede — see DEVIATIONS DEV-014.
	StatusPublished:   {StatusQuarantined, StatusYanked, StatusBlocked},
	StatusQuarantined: {StatusPublished, StatusYanked, StatusBlocked},
	StatusBlocked:     {StatusQuarantined}, // platform reinstate path
	// rejected, yanked terminal for v1 (yank is permanent; fix = new version)
}

func transitionAllowed(from, to Status) bool {
	for _, t := range allowedTransitions[from] {
		if t == to {
			return true
		}
	}
	return false
}

// The scan statuses a version carries (agent_versions.scan_status, M21):
// admitted through the pipeline, or skipped — no run, no findings, no
// attestation, the verdict "unscanned".
const (
	ScanStatusPipeline = "pipeline"
	ScanStatusSkipped  = "skipped"
)

// skipsTheGate says whether an edge reaches published without the gate.
// One does; it is open only to a version marked skipped, and the marking
// is SubmitVersion's alone, for an agent whose administrator set the
// flag. Every other edge into published is the gate's.
func skipsTheGate(from, to Status) bool {
	return from == StatusSubmitted && to == StatusPublished
}

// ErrUnscannedOnPublic reports a version admitted unscanned about to be
// published on an agent that is not a private one of an organization's —
// the state DEV-115 rules out at every layer.
var ErrUnscannedOnPublic = errors.New("registry: an unscanned version is published only on a private organization agent")

// unscannedMayPublish locks the agent's row and says whether a version
// admitted unscanned may be published on it now: the agent is private and
// an organization's; and on the gate-skipping edge the flag is still set,
// so a flag cleared or a visibility changed since the submission began is
// seen here, not after. The lock is held to the end of the caller's
// transaction, which is what keeps UpdateAgent's own locked decision and
// this one from crossing.
func unscannedMayPublish(ctx context.Context, q *storegen.Queries, agentID uuid.UUID, from Status) error {
	a, err := q.GetAgentForUpdate(ctx, agentID)
	if err != nil {
		return fmt.Errorf("registry: lock agent: %w", err)
	}
	if a.Visibility != "private" || a.NamespaceKind != "org" || (from == StatusSubmitted && !a.PipelineSkip) {
		return ErrUnscannedOnPublic
	}
	return nil
}

// publishUnscanned admits a submitted version without a scan (M21): one
// transaction that marks the version skipped and takes the
// gate-skipping edge, the agent's row locked and re-read inside it. It
// reports whether the version was published; false with no error means
// the agent was no longer one that may skip — the flag cleared, the
// agent made public — and the caller sends the version through the
// pipeline instead.
func (s *Service) publishUnscanned(ctx context.Context, versionID uuid.UUID, reason string, actorEvent audit.Event) (bool, error) {
	var res TransitionResult
	err := s.st.WithTx(ctx, func(q *storegen.Queries) error {
		n, err := q.MarkVersionScanSkipped(ctx, versionID)
		if err != nil {
			return fmt.Errorf("registry: mark version unscanned: %w", err)
		}
		if n != 1 {
			// Not submitted any more: something moved it, and the
			// gate's own edges are the only way on from here.
			return fmt.Errorf("%w: the version is no longer submitted", ErrBadTransition)
		}
		var terr error
		res, terr = s.TransitionInTx(ctx, q, versionID, StatusPublished, reason, actorEvent)
		return terr
	})
	if errors.Is(err, ErrUnscannedOnPublic) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	s.EmitTransition(ctx, res)
	return true, nil
}

// ErrBadTransition reports a §7 state-machine violation.
var ErrBadTransition = errors.New("registry: illegal state transition")

// ErrVersionMoved reports that a transition's precondition failed: the
// version was no longer in the state the caller decided from (a decision
// reached late, after the watchdog routed the version to review —
// agentry#343). The caller's decision is stale, not wrong; it stops.
var ErrVersionMoved = errors.New("registry: version moved before the transition")

// Version aliases the row type.
type Version = storegen.AgentVersion

// Pipeline is what happens after a version enters the machine. M3 wires the
// dev-mode auto-approve stub; M4 replaces it with the scan orchestrator.
// Implementations run AFTER the submission transaction commits.
//
// The error return is load-bearing: a hand-off that fails (queue down, scan
// crashed) leaves the version parked in `scanning`, and a seam that cannot
// report that made the failure invisible to the submitter and to the logs.
type Pipeline interface {
	VersionSubmitted(ctx context.Context, versionID uuid.UUID) error
}

// SetPipeline wires the post-submission pipeline.
func (s *Service) SetPipeline(p Pipeline) { s.pipeline = p }

// ErrScanNotScheduled reports that a version was recorded but its scan could
// not be started. The version stays in `scanning`; the pipeline watchdog
// routes it to review once it passes the §7 30-minute cap.
var ErrScanNotScheduled = errors.New("registry: version recorded but its scan could not be scheduled")

// TransitionResult describes a committed §7 transition. Event is the §9.3
// webhook name for the edge, or "" when the edge has no external event.
type TransitionResult struct {
	AgentID   uuid.UUID
	VersionID uuid.UUID
	Version   string
	From      Status
	To        Status
	Reason    string
	Event     string
	// Cause is what the pipeline said about a transition it made (zero for
	// every other actor), carried onto the event.
	Cause TransitionCause
}

// TransitionCause is the pipeline's account of a transition it made. A
// PipelineError is the platform's own fault — a stage error, a fatal
// report, a scan that never finished — routing the version to review with
// an S0/pipeline-error finding; an extension that charged for the
// submission refunds on it (plan subscription-tiers §5.4).
type TransitionCause struct {
	PipelineError bool
	ScanRunID     uuid.UUID
}

// Transition moves a version to a new status with full §7 enforcement:
// row lock, edge validation, audit, and latest-published maintenance.
func (s *Service) Transition(ctx context.Context, versionID uuid.UUID, to Status, reason string, actorEvent audit.Event) error {
	return s.TransitionWith(ctx, versionID, to, reason, actorEvent, TransitionCause{})
}

// TransitionWith is Transition with the pipeline's cause on the event.
func (s *Service) TransitionWith(ctx context.Context, versionID uuid.UUID, to Status, reason string, actorEvent audit.Event, cause TransitionCause) error {
	return s.transitionWith(ctx, versionID, "", to, reason, actorEvent, cause)
}

// TransitionFrom is TransitionWith with a precondition: the version must
// still be in `from` under the row lock, or nothing moves and
// ErrVersionMoved says so. A decision made about a version in one state
// must not be applied to it in another — a scan's verdict reaching a
// version the watchdog has since handed to a reviewer (agentry#343).
func (s *Service) TransitionFrom(ctx context.Context, versionID uuid.UUID, from, to Status, reason string, actorEvent audit.Event, cause TransitionCause) error {
	return s.transitionWith(ctx, versionID, from, to, reason, actorEvent, cause)
}

func (s *Service) transitionWith(ctx context.Context, versionID uuid.UUID, expectFrom, to Status, reason string, actorEvent audit.Event, cause TransitionCause) error {
	var res TransitionResult
	err := s.st.WithTx(ctx, func(q *storegen.Queries) error {
		if expectFrom != "" {
			row, err := q.GetVersionForUpdate(ctx, versionID)
			if err != nil {
				return fmt.Errorf("registry: lock version: %w", err)
			}
			if Status(row.Status) != expectFrom {
				return fmt.Errorf("%w: %s is %s, the decision was made from %s", ErrVersionMoved, row.Version, row.Status, expectFrom)
			}
		}
		var terr error
		res, terr = s.TransitionInTx(ctx, q, versionID, to, reason, actorEvent)
		return terr
	})
	if err != nil {
		return err
	}
	res.Cause = cause
	s.EmitTransition(ctx, res)
	return nil
}

// TransitionInTx is Transition's body, executed inside a transaction the
// caller owns. It exists so a decision that must be atomic with its
// transition — a review verdict, say — commits as one unit instead of
// leaving the two halves able to disagree. Callers MUST pass the returned
// result to EmitTransition after their transaction commits.
func (s *Service) TransitionInTx(ctx context.Context, q *storegen.Queries, versionID uuid.UUID, to Status, reason string, actorEvent audit.Event) (TransitionResult, error) {
	row, err := q.GetVersionForUpdate(ctx, versionID)
	if err != nil {
		return TransitionResult{}, fmt.Errorf("registry: lock version: %w", err)
	}
	from := Status(row.Status)
	res := TransitionResult{
		AgentID: row.AgentID, VersionID: row.ID, Version: row.Version, From: from, To: to, Reason: reason,
		Event: transitionEvent(from, to),
	}
	if !transitionAllowed(from, to) {
		return TransitionResult{}, fmt.Errorf("%w: %s → %s", ErrBadTransition, from, to)
	}
	if skipsTheGate(from, to) && row.ScanStatus != ScanStatusSkipped {
		// The gate-skipping edge is for a version admitted unscanned and
		// nothing else: a submitted version that was not so marked goes
		// through scanning like every other.
		return TransitionResult{}, fmt.Errorf("%w: %s → %s without a skipped scan", ErrBadTransition, from, to)
	}
	if to == StatusPublished && row.ScanStatus == ScanStatusSkipped {
		// A version admitted unscanned is published only on a private
		// agent of an organization's — on the gate-skipping edge, and on
		// a reinstate from quarantine alike — read here under the
		// agent's row lock, so a visibility change racing this transition
		// cannot put an unscanned version on a public agent (DEV-115).
		if err := unscannedMayPublish(ctx, q, row.AgentID, from); err != nil {
			return TransitionResult{}, err
		}
	}
	var reasonPtr, yankPtr *string
	if reason != "" {
		reasonPtr = &reason
		if to == StatusYanked {
			yankPtr = &reason
		}
	}
	if err := q.SetVersionStatus(ctx, storegen.SetVersionStatusParams{
		ID: versionID, Status: string(to), StatusReason: reasonPtr, YankReason: yankPtr,
	}); err != nil {
		return TransitionResult{}, err
	}
	// A version that leaves `published` is no longer an installable
	// dependency risk: its open MCP dependency alerts close with the new
	// state as the reason (agentry#177, D6).
	if from == StatusPublished && to != StatusPublished {
		r := "version-" + string(to)
		if _, err := q.ResolveMCPDependencyAlertsForVersion(ctx, storegen.ResolveMCPDependencyAlertsForVersionParams{
			VersionID: versionID, ResolvedReason: &r,
		}); err != nil {
			return TransitionResult{}, fmt.Errorf("resolve dependency alerts: %w", err)
		}
	}
	// Maintain agents.latest_published_version_id on entry/exit of
	// published (§4.2 denormalized pointer).
	if to == StatusPublished || from == StatusPublished {
		if err := q.RecomputeAgentLatestPublished(ctx, row.AgentID); err != nil {
			return TransitionResult{}, err
		}
	}
	// A publish is what makes a release's modes true of the agent (DEV-088,
	// agentry#162): the row's modes follow the manifest just published, the
	// same denormalisation as the pointer above. Yanks and blocks leave it;
	// the next publish sets it again. A snapshot with no modes (the
	// withdrawn kind) sets nothing.
	var publishedModes []string
	if to == StatusPublished {
		if m, err := manifest.Parse(row.Manifest); err == nil {
			for _, mode := range m.SupportedModes() {
				publishedModes = append(publishedModes, string(mode))
			}
		}
		if len(publishedModes) > 0 {
			if err := q.UpdateAgentSettings(ctx, storegen.UpdateAgentSettingsParams{ID: row.AgentID, Modes: publishedModes}); err != nil {
				return TransitionResult{}, fmt.Errorf("registry: agent modes on publish: %w", err)
			}
		}
	}
	e := actorEvent
	e.Action = audit.ActionVersionTransition
	e.TargetKind, e.TargetID = "agent_version", versionID
	e.Detail = map[string]any{"from": string(from), "to": string(to), "reason": reason, "version": row.Version}
	if publishedModes != nil {
		e.Detail["modes"] = publishedModes
	}
	if err := s.aud.Write(ctx, q, e); err != nil {
		return TransitionResult{}, err
	}
	return res, nil
}

// EmitTransition fans a committed transition out to the event sink (§9.3).
// Best-effort: the sink logs its own errors and never affects the transition.
func (s *Service) EmitTransition(ctx context.Context, res TransitionResult) {
	if s.eventSink == nil || res.Event == "" {
		return
	}
	payload := map[string]any{
		"version": res.Version, "versionId": res.VersionID.String(),
		"from": string(res.From), "to": string(res.To), "reason": res.Reason,
	}
	if res.Cause.PipelineError {
		payload["pipelineError"] = true
		payload["scanRunId"] = res.Cause.ScanRunID.String()
	}
	s.eventSink(ctx, res.AgentID, res.Event, payload)
}

// EmitAgentEvent publishes a non-transition agent event (§9.3) — today the
// advisory the rescan path drafts, which had no way to reach subscribers.
func (s *Service) EmitAgentEvent(ctx context.Context, agentID uuid.UUID, event string, payload map[string]any) {
	if s.eventSink == nil || event == "" {
		return
	}
	s.eventSink(ctx, agentID, event, payload)
}

// transitionEvent maps a state-machine edge to the §9.3 webhook event, or ""
// when the edge has no external event.
func transitionEvent(from, to Status) string {
	switch to {
	case StatusPublished:
		if from == StatusQuarantined {
			return "agent.reinstated"
		}
		return "version.published"
	case StatusRejected:
		return "version.rejected"
	case StatusNeedsReview:
		return "version.needs_review"
	case StatusYanked:
		return "version.yanked"
	case StatusQuarantined:
		return "agent.quarantined"
	default:
		return ""
	}
}

// SubmitInput carries one publication submission (§6.5). Workspace is a
// directory holding the exact tree to publish; the handler prepares it from
// `git archive` (git-tag source) or the uploaded archive (cli-upload).
type SubmitInput struct {
	Source        string // git-tag | cli-upload
	Tag           string // git-tag source: the vX.Y.Z tag
	CommitSHA     string
	Workspace     string
	ClaimedDigest string // cli-upload: client digest to cross-check (may be empty)
	// DraftRun is the hosted draft a cli-upload says it was published from
	// (plan drafter-revisions.md §6; agentry#794). A claim only: the scan
	// asks the extension's DraftProvenance whether it holds, and the client
	// is never believed.
	DraftRun *uuid.UUID
}

// skipsPipeline says whether a submission to the agent is admitted
// without a scan (M21): the administrator's flag is set, the agent is a
// private one of an organization's, and the organization's tier includes
// unscanned agents now. A resolver that cannot answer is "no": the
// version is scanned.
func (s *Service) skipsPipeline(ctx context.Context, a Agent) bool {
	if !a.PipelineSkip || a.Visibility != "private" || a.NamespaceKind != "org" {
		return false
	}
	f, err := s.Entitlements().Features(ctx, entitlements.ForOrg(a.NamespaceID))
	if err != nil {
		s.logger().Error("registry: unscanned agents: features", "agent", a.Namespace+"/"+a.Name, "err", err)
		return false
	}
	return f.UnscannedAgents
}

// The §19 publish-velocity quota and the archive quotas both come from the
// entitlements Resolver (§14.2). subjectFor maps an agent onto the subject
// whose plan governs it: the owning org, or the user whose personal namespace
// holds it.
func subjectFor(a Agent) entitlements.Subject {
	if a.NamespaceKind == "org" {
		return entitlements.ForOrg(a.NamespaceID)
	}
	return entitlements.ForUser(a.NamespaceID)
}

// ErrValidation carries manifest/validation failures to the API layer.
type ErrValidation struct{ Issues []error }

func (e *ErrValidation) Error() string {
	msgs := make([]string, 0, len(e.Issues))
	for _, i := range e.Issues {
		msgs = append(msgs, i.Error())
	}
	return "registry: validation failed: " + strings.Join(msgs, "; ")
}

// SubmitVersion validates, archives, records, and hands the version to the
// pipeline: §6.5 steps 1–4 then §7 submitted→scanning.
func (s *Service) SubmitVersion(ctx context.Context, p *auth.Principal, a Agent, in SubmitInput, actorEvent audit.Event) (Version, error) {
	if p == nil || p.Anonymous {
		return Version{}, auth.ErrUnauthorized
	}
	// A retired agent takes no submission until it is restored
	// (agentry#942, D2), whichever door the submission came through.
	if a.RetiredAt != nil {
		return Version{}, ErrRetired
	}
	// A git-tag submission on a role that hands the archive write off
	// (the git role, agentry#508) builds the archive for its digest and
	// leaves the store to the worker.
	deferStore := s.archiveHandOff != nil && in.Source == SourceGitTag
	if s.blobs == nil && !deferStore {
		return Version{}, errors.New("registry: no blob store configured")
	}

	// §19 quotas for this agent's owner, resolved once and used for both the
	// publish-velocity check and the archive limits below.
	lim, err := s.Entitlements().Limits(ctx, subjectFor(a))
	if err != nil {
		return Version{}, fmt.Errorf("registry: entitlements: %w", err)
	}

	// Publish-velocity quota (§19).
	today, err := s.st.Queries().CountVersionsToday(ctx, a.ID)
	if err != nil {
		return Version{}, err
	}
	if today >= lim.VersionsPerDay {
		return Version{}, fmt.Errorf("%w: daily version quota reached", ErrDenied)
	}

	// Inventory the workspace and validate the manifest against it.
	files, err := WalkWorkspace(in.Workspace)
	if err != nil {
		return Version{}, fmt.Errorf("registry: walk workspace: %w", err)
	}
	rawManifest, err := os.ReadFile(in.Workspace + "/agent.yaml") //nolint:gosec // server-created workspace
	if err != nil {
		return Version{}, &ErrValidation{Issues: []error{errors.New("the submission has no agent.yaml")}}
	}
	m, err := manifest.Parse(rawManifest)
	if err != nil {
		return Version{}, &ErrValidation{Issues: []error{err}}
	}
	existing, err := s.existingVersions(ctx, a.ID)
	if err != nil {
		return Version{}, err
	}
	// V8's archive quotas come from the resolver too, so an org on a larger
	// plan gets a larger archive without a second source of truth.
	quotas := manifest.Quotas{
		MaxArchiveBytes:   lim.Archive.MaxBytes,
		MaxFiles:          lim.Archive.MaxFiles,
		MaxFileBytes:      lim.Archive.MaxFileBytes,
		MaxImageFileBytes: lim.Archive.MaxImageFileBytes,
		MaxTextBytes:      lim.Archive.MaxTextBytes,
	}
	issues := manifest.ValidateInContext(m, manifest.Context{
		Namespace:        a.Namespace,
		Name:             a.Name,
		TagVersion:       in.Tag,
		ExistingVersions: existing,
		Public:           a.Visibility == "public",
		Files:            files,
		Quotas:           &quotas,
		// V9 reads the skill entrypoint out of the server-created
		// workspace; the path was validated repo-relative by V4.
		ReadFile: func(p string) ([]byte, error) {
			return os.ReadFile(filepath.Join(in.Workspace, filepath.FromSlash(p))) //nolint:gosec // validated repo-relative path in a server-created workspace
		},
	})
	if blocking := manifest.Blocking(issues); len(blocking) > 0 {
		return Version{}, &ErrValidation{Issues: blocking}
	}

	canonical, err := manifest.CanonicalJSON(m)
	if err != nil {
		return Version{}, err
	}

	// 2FA before public publish (§12.1, §19). Checked here rather than in a
	// handler so it covers BOTH sources: the CLI upload and the git-tag
	// auto-publish that a push triggers without any API call.
	if err := s.checkPublicPublish2FA(ctx, p, a); err != nil {
		return Version{}, err
	}
	// Policy knobs that reject at V-validation time (§8.6): blocked
	// capabilities, disallowed licenses, missing evals.
	if s.policyGate != nil {
		if issues := s.policyGate.CheckSubmission(ctx, PolicySubmission{
			NamespaceKind: a.NamespaceKind,
			NamespaceID:   a.NamespaceID,
			Public:        a.Visibility == "public",
			License:       m.License,
			ManifestJSON:  canonical,
			Files:         files,
		}); len(issues) > 0 {
			return Version{}, &ErrValidation{Issues: issues}
		}
	}

	// Admission (admission.go): after every core gate, before anything is
	// stored. From here on, a failure hands the ticket back.
	ticket, err := s.admit(ctx, Admission{
		Kind: AdmissionKindVersionSubmit, Subject: subjectFor(a), Submitter: p.UserID,
		AgentID: a.ID, Visibility: a.Visibility, Source: in.Source,
	})
	if err != nil {
		return Version{}, err
	}
	admitted := false
	defer func() {
		if !admitted {
			s.void(ctx, ticket)
		}
	}()

	// Deterministic archive from the allowlist (§6.5 steps 2–3).
	include := manifest.ResolveInclude(m.Publish.Include, files)
	// Stage through a temp buffer file: the key depends on the digest.
	tmp, err := os.CreateTemp("", "agentry-archive-*")
	if err != nil {
		return Version{}, err
	}
	defer func() { _ = os.Remove(tmp.Name()); _ = tmp.Close() }()
	info, err := stageArchive(in.Workspace, include, tmp)
	if err != nil {
		return Version{}, err
	}

	// cli-upload: never trust client packing (§6.5) — the server-built
	// digest is authoritative; a claimed digest must agree.
	if in.ClaimedDigest != "" && in.ClaimedDigest != info.Digest {
		return Version{}, &ErrValidation{Issues: []error{
			fmt.Errorf("client archive digest %s does not match server-built %s", in.ClaimedDigest, info.Digest)}}
	}

	key := ArchiveKey(info.Digest)
	if !deferStore {
		if _, err := tmp.Seek(0, io.SeekStart); err != nil {
			return Version{}, err
		}
		if err := s.blobs.Put(ctx, key, tmp); err != nil {
			return Version{}, fmt.Errorf("registry: store archive: %w", err)
		}
	}

	// The contract a person consents to: the capabilities and the names of
	// the knowledge packs the release ships (plan knowledge.md §4.6).
	caps, err := json.Marshal(m.Contract())
	if err != nil {
		return Version{}, err
	}

	versionID := newUUID()
	err = s.st.WithTx(ctx, func(q *storegen.Queries) error {
		// The agent as it is now, under its row lock: a delete or a retire
		// that landed after this submission resolved the agent must not
		// have a version arrive behind it (agentry#942). Tombstone takes
		// the same lock and counts in-flight versions under it.
		locked, err := q.GetAgentForUpdate(ctx, a.ID)
		if err != nil {
			return fmt.Errorf("registry: lock agent: %w", err)
		}
		if locked.DeletedAt != nil {
			return ErrNotFound
		}
		if locked.RetiredAt != nil {
			return ErrRetired
		}
		// The submitting address, keyed and month-rotated (agentry#27):
		// the middleware resolved it once onto the context, for the API
		// upload and the git push alike.
		var ipHash *string
		if h := IPClusterHash(s.ipClusterSecret, auth.ClientIPFrom(ctx), time.Now()); h != "" {
			ipHash = &h
		}
		v, err := q.CreateAgentVersion(ctx, storegen.CreateAgentVersionParams{
			ID: versionID, AgentID: a.ID, Version: m.Version,
			CommitSha: in.CommitSHA, Manifest: canonical, Capabilities: caps,
			Channel: string(m.EffectiveChannel()), SubmittedBy: p.UserID, Source: in.Source,
			SubmitterIpHash: ipHash, DraftRun: in.DraftRun,
		})
		if err != nil {
			return err
		}
		if err := q.SetVersionArchive(ctx, storegen.SetVersionArchiveParams{
			ID: v.ID, ArchiveDigest: &info.Digest, ArchiveKey: &key, ArchiveSize: &info.Size,
		}); err != nil {
			return err
		}
		e := actorEvent
		e.Action = audit.ActionVersionSubmit
		if a.NamespaceKind == "org" {
			e.OrgID = a.NamespaceID
		}
		e.TargetKind, e.TargetID = "agent_version", v.ID
		e.Detail = map[string]any{
			"agent": a.Namespace + "/" + a.Name, "version": m.Version,
			"source": in.Source, "digest": info.Digest, "channel": string(m.EffectiveChannel()),
		}
		return s.aud.Write(ctx, q, e)
	})
	if err != nil {
		if isUniqueViolationErr(err) {
			return Version{}, fmt.Errorf("%w: version %s already exists; versions are immutable", ErrDenied, m.Version)
		}
		return Version{}, err
	}
	admitted = true // the row is committed; the ticket is spent

	// §9.3 catalog (agentry#56): the submission itself is an event, before
	// any scan outcome.
	submitted := map[string]any{
		"version": m.Version, "source": in.Source, "channel": string(m.EffectiveChannel()),
	}
	if ticket.ID != "" {
		// The admission ticket lets the Admitter tie its debit to the
		// version the core created for it (plan subscription-tiers §5.1).
		submitted["admissionTicket"] = ticket.ID
		submitted["versionId"] = versionID.String()
	}
	sysEvent := actorEvent

	if deferStore {
		// The row records the digest and key; the object is not there yet.
		// The worker rebuilds the archive from the recorded commit, checks
		// it against the digest, stores it, and enters the machine
		// (StoreTagArchive). Until then the version is `submitted`, and a
		// store job that never succeeds is the watchdog's
		// (ReconcileStuckSubmissions). The submission event goes out now,
		// from here: it ties the admission ticket to the version, so a
		// version the watchdog rejects is refunded like any other
		// pipeline error.
		s.EmitAgentEvent(ctx, a.ID, "version.submitted", submitted)
		if err := s.archiveHandOff.StoreTagArchive(ctx, StoreTagArchiveArgs{VersionID: versionID}); err != nil {
			s.logger().Error("registry: archive hand-off failed; version left in submitted",
				"version", versionID, "agent", a.Namespace+"/"+a.Name, "err", err)
			v, gerr := s.st.Queries().GetVersionByID(ctx, versionID)
			if gerr != nil {
				return Version{}, gerr
			}
			return v, fmt.Errorf("%w: %v", ErrScanNotScheduled, err)
		}
		return s.st.Queries().GetVersionByID(ctx, versionID)
	}
	return s.enterPipeline(ctx, a, versionID, submitted, sysEvent, s.pipeline)
}

// enterPipeline takes a recorded version whose archive is in the store
// into the machine: published unscanned when its agent skips the pipeline,
// otherwise submitted → scanning and handed to the pipeline. submitted is
// the version.submitted event's payload, or nil when the event already
// went out (a handed-off git-tag submission, emitted where it was
// recorded).
func (s *Service) enterPipeline(ctx context.Context, a Agent, versionID uuid.UUID, submitted map[string]any, sysEvent audit.Event, pipeline Pipeline) (Version, error) {
	// An agent its organization's administrator took off the pipeline
	// (M21, D16): the version is published as submitted, marked skipped
	// first so the one gate-skipping edge will take it, with no scan run
	// and no attestation, and served everywhere as unscanned. Only while
	// the agent is still private, still an organization's, and the tier
	// still includes it — each read again here, since the flag was set
	// earlier and any of them may have changed; otherwise the version
	// goes through the pipeline like every other (fail closed).
	if s.skipsPipeline(ctx, a) {
		published, err := s.publishUnscanned(ctx, versionID, "published unscanned (pipeline: skip)", sysEvent)
		if err != nil {
			return Version{}, err
		}
		if published {
			if submitted != nil {
				submitted["scanStatus"] = ScanStatusSkipped
				s.EmitAgentEvent(ctx, a.ID, "version.submitted", submitted)
			}
			return s.st.Queries().GetVersionByID(ctx, versionID)
		}
		// The agent stopped being one that may skip between the
		// caller's read and the lock: through the pipeline it goes.
	}

	// Enter the machine (§7): submitted → scanning, then hand off.
	if err := s.Transition(ctx, versionID, StatusScanning, "archive built", sysEvent); err != nil {
		return Version{}, err
	}
	if submitted != nil {
		s.EmitAgentEvent(ctx, a.ID, "version.submitted", submitted)
	}
	if pipeline != nil {
		if perr := pipeline.VersionSubmitted(ctx, versionID); perr != nil {
			// The version row is committed and sitting in `scanning`; there is
			// nothing to roll back. Report it instead of returning a 202 that
			// promises a scan nobody scheduled — the watchdog will route it to
			// review at the §7 cap.
			s.logger().Error("registry: pipeline hand-off failed; version left in scanning",
				"version", versionID, "agent", a.Namespace+"/"+a.Name, "err", perr)
			v, gerr := s.st.Queries().GetVersionByID(ctx, versionID)
			if gerr != nil {
				return Version{}, gerr
			}
			return v, fmt.Errorf("%w: %v", ErrScanNotScheduled, perr)
		}
	}

	return s.st.Queries().GetVersionByID(ctx, versionID)
}

// checkPublicPublish2FA enforces §12.1/§19: publishing to a public namespace
// requires TOTP on the submitting account. Enabled by the api/worker wiring
// outside dev mode (DEV-016) — a dev instance has no enrollment flow to
// satisfy, and config validation already forbids devMode in a prod env.
func (s *Service) checkPublicPublish2FA(ctx context.Context, p *auth.Principal, a Agent) error {
	if !s.require2FAPublic || a.Visibility != "public" {
		return nil
	}
	u, err := s.st.Queries().GetUserByID(ctx, p.UserID)
	if err != nil {
		// Fail closed: we could not establish that 2FA is on.
		return fmt.Errorf("registry: verify two-factor enrollment: %w", err)
	}
	// Native TOTP, or a second factor the directory service asserted at
	// sign-in (users.idp_mfa_at, agentry#23): either is evidence.
	if !u.TotpEnabled && u.IdpMfaAt == nil {
		return fmt.Errorf("%w: a public namespace needs two-factor authentication on the account — native TOTP, or a second factor the sign-in provider asserts", ErrTwoFactorRequired)
	}
	return nil
}

// stageArchive builds the deterministic archive into dst and returns its
// identity. BuildArchive runs on its own goroutine because it writes to a
// pipe; the two rules that keep that safe are (a) the reader end is ALWAYS
// closed with an error, so a builder parked in pw.Write is released rather
// than blocking forever on a dst write failure, and (b) we wait for the
// builder before returning, so no goroutine outlives this call.
func stageArchive(root string, include []manifest.FileInfo, dst io.Writer) (ArchiveInfo, error) {
	pr, pw := io.Pipe()
	type built struct {
		info ArchiveInfo
		err  error
	}
	done := make(chan built, 1)
	go func() {
		info, err := BuildArchive(root, include, pw)
		_ = pw.CloseWithError(err)
		done <- built{info: info, err: err}
	}()

	_, copyErr := io.Copy(dst, pr)
	// Unblock the builder unconditionally: on a copy failure it is otherwise
	// asleep in pw.Write with nobody left to read (B-18).
	if copyErr != nil {
		_ = pr.CloseWithError(copyErr)
	} else {
		_ = pr.Close()
	}
	b := <-done

	// The build error is the more informative one when both fire: a copy
	// failure is usually just the pipe reporting the build's own abort.
	if b.err != nil {
		return ArchiveInfo{}, fmt.Errorf("registry: build archive: %w", b.err)
	}
	if copyErr != nil {
		return ArchiveInfo{}, fmt.Errorf("registry: stage archive: %w", copyErr)
	}
	return b.info, nil
}

// SubmitTag prepares a workspace from a repo tag and submits it (git-tag
// source; used by POST /versions {tag} and the post-receive auto-publish).
func (s *Service) SubmitTag(ctx context.Context, p *auth.Principal, a Agent, tag string, actorEvent audit.Event) (Version, error) {
	if s.gitArchiver == nil {
		return Version{}, errors.New("registry: git-tag submissions unavailable on this role (no repo storage)")
	}
	ws, err := os.MkdirTemp("", "agentry-ws-*")
	if err != nil {
		return Version{}, err
	}
	defer func() { _ = os.RemoveAll(ws) }()
	commit, err := s.gitArchiver.MaterializeTag(ctx, a.RepoID, tag, ws)
	if err != nil {
		return Version{}, &ErrValidation{Issues: []error{fmt.Errorf("tag %s: %v", tag, err)}}
	}
	return s.SubmitVersion(ctx, p, a, SubmitInput{
		Source: SourceGitTag, Tag: tag, CommitSHA: commit, Workspace: ws,
	}, actorEvent)
}

// existingVersions groups every recorded version string by channel (V3:
// version strings are burned forever, any status).
func (s *Service) existingVersions(ctx context.Context, agentID uuid.UUID) (map[manifest.Channel][]string, error) {
	rows, err := s.st.Queries().ListVersions(ctx, agentID)
	if err != nil {
		return nil, err
	}
	out := map[manifest.Channel][]string{}
	for _, r := range rows {
		ch := manifest.Channel(r.Channel)
		out[ch] = append(out[ch], r.Version)
	}
	return out, nil
}

// (The M3 DevAutoApprovePipeline stub lived here until 2026-08-31: M4's
// real pipeline is wired in dev mode too, which orphaned it — workspace
// ANALYSIS.md M7, in blaktron/agentry-notes.)

func isUniqueViolationErr(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
