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

	"github.com/PLACEHOLDER_ORG/agentry/internal/audit"
	"github.com/PLACEHOLDER_ORG/agentry/internal/auth"
	storegen "github.com/PLACEHOLDER_ORG/agentry/internal/store/gen"
	"github.com/PLACEHOLDER_ORG/agentry/pkg/manifest"
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
	StatusPublished:   {StatusQuarantined, StatusYanked},
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
type Pipeline interface {
	VersionSubmitted(ctx context.Context, versionID uuid.UUID)
}

// SetPipeline wires the post-submission pipeline.
func (s *Service) SetPipeline(p Pipeline) { s.pipeline = p }

// Transition moves a version to a new status with full §7 enforcement:
// row lock, edge validation, audit, and latest-published maintenance.
func (s *Service) Transition(ctx context.Context, versionID uuid.UUID, to Status, reason string, actorEvent audit.Event) error {
	return s.st.WithTx(ctx, func(q *storegen.Queries) error {
		row, err := q.GetVersionForUpdate(ctx, versionID)
		if err != nil {
			return fmt.Errorf("registry: lock version: %w", err)
		}
		from := Status(row.Status)
		if !transitionAllowed(from, to) {
			return fmt.Errorf("%w: %s → %s", ErrBadTransition, from, to)
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
			return err
		}
		// Maintain agents.latest_published_version_id on entry/exit of
		// published (§4.2 denormalized pointer).
		if to == StatusPublished || from == StatusPublished {
			if err := q.RecomputeAgentLatestPublished(ctx, row.AgentID); err != nil {
				return err
			}
		}
		e := actorEvent
		e.Action = audit.ActionVersionTransition
		e.TargetKind, e.TargetID = "agent_version", versionID
		e.Detail = map[string]any{"from": string(from), "to": string(to), "reason": reason, "version": row.Version}
		return s.aud.Write(ctx, q, e)
	})
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

// MaxVersionsPerDay is the §19 publish-velocity quota.
const MaxVersionsPerDay = 20

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

	// Publish-velocity quota (§19).
	today, err := s.st.Queries().CountVersionsToday(ctx, a.ID)
	if err != nil {
		return Version{}, err
	}
	if today >= MaxVersionsPerDay {
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
	issues := manifest.ValidateInContext(m, manifest.Context{
		Namespace:        a.Namespace,
		Name:             a.Name,
		TagVersion:       in.Tag,
		ExistingVersions: existing,
		Public:           a.Visibility == "public",
		Files:            files,
	})
	if blocking := manifest.Blocking(issues); len(blocking) > 0 {
		return Version{}, &ErrValidation{Issues: blocking}
	}
	if string(m.Kind) != a.Kind {
		return Version{}, &ErrValidation{Issues: []error{fmt.Errorf("manifest kind %q does not match agent kind %q", m.Kind, a.Kind)}}
	}

	// Deterministic archive from the allowlist (§6.5 steps 2–3).
	include := manifest.ResolveInclude(m.Publish.Include, files)
	pr, pw := io.Pipe()
	infoCh := make(chan ArchiveInfo, 1)
	errCh := make(chan error, 1)
	go func() {
		info, err := BuildArchive(in.Workspace, include, pw)
		_ = pw.CloseWithError(err)
		infoCh <- info
		errCh <- err
	}()
	// Stage through a temp buffer file: the key depends on the digest.
	tmp, err := os.CreateTemp("", "agentry-archive-*")
	if err != nil {
		return Version{}, err
	}
	defer func() { _ = os.Remove(tmp.Name()); _ = tmp.Close() }()
	if _, err := io.Copy(tmp, pr); err != nil {
		return Version{}, fmt.Errorf("registry: stage archive: %w", err)
	}
	if err := <-errCh; err != nil {
		return Version{}, fmt.Errorf("registry: build archive: %w", err)
	}
	info := <-infoCh

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

	canonical, err := manifest.CanonicalJSON(m)
	if err != nil {
		return Version{}, err
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
		s.pipeline.VersionSubmitted(ctx, versionID)
	}

	return s.st.Queries().GetVersionByID(ctx, versionID)
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

// DevAutoApprovePipeline is the M3 stub (§18.2 M3): in dev mode every scan
// "passes" immediately. It exists so the state machine is exercised end to
// end; M4 replaces it with the real orchestrator. It NEVER runs outside dev
// mode — construction enforces it.
type DevAutoApprovePipeline struct {
	Svc *Service
}

// VersionSubmitted implements Pipeline.
func (d DevAutoApprovePipeline) VersionSubmitted(ctx context.Context, versionID uuid.UUID) {
	err := d.Svc.Transition(ctx, versionID, StatusPublished, "dev-mode auto-approve stub (M3)", audit.Event{
		ActorKind: audit.ActorSystem,
	})
	if err != nil {
		// The version stays in scanning; operators see it via status.
		fmt.Fprintf(os.Stderr, "dev pipeline: %v\n", err)
	}
}

func isUniqueViolationErr(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
