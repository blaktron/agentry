package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

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
	StatusApproved    Status = "approved"
	StatusPublished   Status = "published"
	StatusRejected    Status = "rejected"
	StatusYanked      Status = "yanked"
	StatusQuarantined Status = "quarantined"
	StatusBlocked     Status = "blocked"
)

// allowedTransitions encodes the §7 diagram. Keys are from-states.
var allowedTransitions = map[Status][]Status{
	StatusSubmitted:   {StatusScanning},
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

// ErrBadTransition reports a §7 state-machine violation.
var ErrBadTransition = errors.New("registry: illegal state transition")

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
	AgentID uuid.UUID
	Version string
	From    Status
	To      Status
	Event   string
}

// Transition moves a version to a new status with full §7 enforcement:
// row lock, edge validation, audit, and latest-published maintenance.
func (s *Service) Transition(ctx context.Context, versionID uuid.UUID, to Status, reason string, actorEvent audit.Event) error {
	var res TransitionResult
	err := s.st.WithTx(ctx, func(q *storegen.Queries) error {
		var terr error
		res, terr = s.TransitionInTx(ctx, q, versionID, to, reason, actorEvent)
		return terr
	})
	if err != nil {
		return err
	}
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
		AgentID: row.AgentID, Version: row.Version, From: from, To: to,
		Event: transitionEvent(from, to),
	}
	if !transitionAllowed(from, to) {
		return TransitionResult{}, fmt.Errorf("%w: %s → %s", ErrBadTransition, from, to)
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
	// Maintain agents.latest_published_version_id on entry/exit of
	// published (§4.2 denormalized pointer).
	if to == StatusPublished || from == StatusPublished {
		if err := q.RecomputeAgentLatestPublished(ctx, row.AgentID); err != nil {
			return TransitionResult{}, err
		}
	}
	e := actorEvent
	e.Action = audit.ActionVersionTransition
	e.TargetKind, e.TargetID = "agent_version", versionID
	e.Detail = map[string]any{"from": string(from), "to": string(to), "reason": reason, "version": row.Version}
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
	s.eventSink(ctx, res.AgentID, res.Event, map[string]any{
		"version": res.Version, "from": string(res.From), "to": string(res.To),
	})
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
	if s.blobs == nil {
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
		return Version{}, &ErrValidation{Issues: []error{errors.New("agent.yaml missing (V1)")}}
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
	}
	issues := manifest.ValidateInContext(m, manifest.Context{
		Namespace:        a.Namespace,
		Name:             a.Name,
		TagVersion:       in.Tag,
		ExistingVersions: existing,
		Public:           a.Visibility == "public",
		Files:            files,
		Quotas:           &quotas,
	})
	if blocking := manifest.Blocking(issues); len(blocking) > 0 {
		return Version{}, &ErrValidation{Issues: blocking}
	}
	if string(m.Kind) != a.Kind {
		return Version{}, &ErrValidation{Issues: []error{fmt.Errorf("manifest kind %q does not match agent kind %q", m.Kind, a.Kind)}}
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
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return Version{}, err
	}
	if err := s.blobs.Put(ctx, key, tmp); err != nil {
		return Version{}, fmt.Errorf("registry: store archive: %w", err)
	}

	caps, err := json.Marshal(m.Capabilities)
	if err != nil {
		return Version{}, err
	}

	versionID := newUUID()
	err = s.st.WithTx(ctx, func(q *storegen.Queries) error {
		v, err := q.CreateAgentVersion(ctx, storegen.CreateAgentVersionParams{
			ID: versionID, AgentID: a.ID, Version: m.Version,
			CommitSha: in.CommitSHA, Manifest: canonical, Capabilities: caps,
			Channel: string(m.EffectiveChannel()), SubmittedBy: p.UserID, Source: in.Source,
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
			return Version{}, fmt.Errorf("%w: version %s already exists (immutable, §5.5)", ErrDenied, m.Version)
		}
		return Version{}, err
	}

	// Enter the machine (§7): submitted → scanning, then hand off.
	sysEvent := actorEvent
	if err := s.Transition(ctx, versionID, StatusScanning, "archive built", sysEvent); err != nil {
		return Version{}, err
	}
	if s.pipeline != nil {
		if perr := s.pipeline.VersionSubmitted(ctx, versionID); perr != nil {
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
	if !u.TotpEnabled {
		return fmt.Errorf("%w: two-factor authentication must be enabled before publishing to a public namespace (§12.1, §19)", ErrTwoFactorRequired)
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
		Source: "git-tag", Tag: tag, CommitSHA: commit, Workspace: ws,
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
