package registry

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/blaktron/agentry/internal/audit"
	storegen "github.com/blaktron/agentry/internal/store/gen"
	"github.com/blaktron/agentry/pkg/manifest"
)

// A git-tag submission on a split deployment (agentry#508).
//
// The git role terminates untrusted git traffic and holds no object-store
// credential: the chart gives the store's Secret to the api and worker pods
// only. So on that role a tag submission does everything but the store
// write. It materializes the tag, validates, runs the gates and admission,
// builds the deterministic archive for its digest, and records the version
// with that digest and key. Then it hands StoreTagArchive to a worker. The
// worker holds the git volume and the store credential. It rebuilds the
// archive from the commit the git role recorded, refuses it unless the
// digest matches (archives are byte-reproducible, §9), writes it once, and
// only then takes the version into the machine. Until then the version is
// `submitted`: the row comes before the object here, where every other
// door stores first. ReconcileStuckSubmissions is the watchdog for a store
// that never happens.

// SourceGitTag is the version source of a tag submission (a push's
// auto-publish, or POST /versions {tag}).
const SourceGitTag = "git-tag"

// JobStoreTagArchive is the worker's job that stores a git-tag
// submission's archive and enters the version into the machine.
const JobStoreTagArchive = "registry.store_tag_archive"

// StuckSubmissionCap is how long a handed-off submission may stay
// `submitted` before the watchdog rejects it. The same bound as a scan's
// (§7): the store job's own retries are over well before it.
const StuckSubmissionCap = 30 * time.Minute

// StoreTagArchiveArgs are the job's arguments. AdmissionTicket rides along
// so the version.submitted event the worker emits carries it, as it would
// have from the submitting process (plan subscription-tiers §5.1).
type StoreTagArchiveArgs struct {
	VersionID       uuid.UUID `json:"versionId"`
	AdmissionTicket string    `json:"admissionTicket,omitempty"`
}

// ArchiveHandOff enqueues JobStoreTagArchive. The git role sets it
// (api.Server.DeferTagArchives); a role that holds the store writes the
// archive itself.
type ArchiveHandOff interface {
	StoreTagArchive(ctx context.Context, args StoreTagArchiveArgs) error
}

// SetArchiveHandOff makes this process hand git-tag archive writes to a
// worker instead of writing them.
func (s *Service) SetArchiveHandOff(h ArchiveHandOff) { s.archiveHandOff = h }

// ErrArchiveMismatch reports that the archive rebuilt from the recorded
// commit does not have the recorded digest. Retrying cannot fix it; the
// watchdog rejects the version.
var ErrArchiveMismatch = errors.New("registry: rebuilt archive does not match the recorded digest")

// StoreTagArchive is JobStoreTagArchive's handler: it stores the archive
// of a handed-off git-tag submission and enters the version into the
// machine, handing it to pipeline (the worker's queue). It is idempotent:
// a version that is no longer `submitted` was already taken in, and an
// archive already in the store is not written again (write-once).
func (s *Service) StoreTagArchive(ctx context.Context, args StoreTagArchiveArgs, pipeline Pipeline) error {
	q := s.st.Queries()
	v, err := q.GetVersionByID(ctx, args.VersionID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil // the version is gone (its agent was deleted)
	}
	if err != nil {
		return err
	}
	if Status(v.Status) != StatusSubmitted {
		return nil
	}
	if v.Source != SourceGitTag || v.ArchiveDigest == nil || v.ArchiveKey == nil || v.CommitSha == "" {
		return fmt.Errorf("registry: version %s is not a handed-off git-tag submission", v.ID)
	}
	if s.blobs == nil {
		return errors.New("registry: no blob store configured on this role")
	}
	row, err := q.GetAgentByID(ctx, v.AgentID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	a, err := s.Resolve(ctx, row.Namespace, row.Name)
	if err != nil {
		return err
	}

	exists, err := s.blobs.Exists(ctx, *v.ArchiveKey)
	if err != nil {
		return fmt.Errorf("registry: archive lookup: %w", err)
	}
	if !exists {
		if err := s.rebuildAndStore(ctx, a, v); err != nil {
			return err
		}
	}

	submitted := map[string]any{
		"version": v.Version, "source": v.Source, "channel": v.Channel,
	}
	if args.AdmissionTicket != "" {
		submitted["admissionTicket"] = args.AdmissionTicket
		submitted["versionId"] = v.ID.String()
	}
	_, err = s.enterPipeline(ctx, a, v.ID, submitted, audit.Event{ActorKind: audit.ActorSystem}, pipeline)
	if errors.Is(err, ErrScanNotScheduled) {
		// The version is in `scanning` now; a retry would find it past
		// `submitted` and do nothing. The scan watchdog has it (§7).
		return nil
	}
	return err
}

// rebuildAndStore rebuilds v's archive from its recorded commit exactly as
// SubmitVersion built it (the manifest allowlist over the commit's tree),
// checks the digest and writes the object.
func (s *Service) rebuildAndStore(ctx context.Context, a Agent, v Version) error {
	if s.gitArchiver == nil {
		return errors.New("registry: this role cannot read the repositories (no git data)")
	}
	ws, err := os.MkdirTemp("", "agentry-ws-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(ws) }()
	if err := s.gitArchiver.MaterializeCommit(ctx, a.RepoID, v.CommitSha, ws); err != nil {
		return fmt.Errorf("registry: materialize %s: %w", v.CommitSha, err)
	}
	files, err := WalkWorkspace(ws)
	if err != nil {
		return fmt.Errorf("registry: walk workspace: %w", err)
	}
	raw, err := os.ReadFile(ws + "/agent.yaml") //nolint:gosec // server-created workspace
	if err != nil {
		return fmt.Errorf("%w: the commit has no agent.yaml", ErrArchiveMismatch)
	}
	m, err := manifest.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrArchiveMismatch, err)
	}
	tmp, err := os.CreateTemp("", "agentry-archive-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()); _ = tmp.Close() }()
	info, err := stageArchive(ws, manifest.ResolveInclude(m.Publish.Include, files), tmp)
	if err != nil {
		return err
	}
	if info.Digest != *v.ArchiveDigest || ArchiveKey(info.Digest) != *v.ArchiveKey {
		return fmt.Errorf("%w: version %s recorded %s, the commit gives %s", ErrArchiveMismatch, v.ID, *v.ArchiveDigest, info.Digest)
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err := s.blobs.Put(ctx, *v.ArchiveKey, tmp); err != nil {
		return fmt.Errorf("registry: store archive: %w", err)
	}
	return nil
}

// ReconcileStuckSubmissions is the watchdog for handed-off git-tag
// submissions whose archive was never stored (a store job out of retries,
// a digest mismatch, a worker without the git volume): past the cap, each
// is rejected through scanning with a pipeline-error cause, so it is never
// served and an extension that charged for it refunds. It is not routed
// to review, since a reviewer's approval would publish a version with no
// archive behind it. Returns how many it rejected.
func (s *Service) ReconcileStuckSubmissions(ctx context.Context) (int, error) {
	rows, err := s.st.Queries().ListStuckSubmittedVersions(ctx, storegen.ListStuckSubmittedVersionsParams{
		UpdatedAt: time.Now().Add(-StuckSubmissionCap), Limit: 200,
	})
	if err != nil {
		return 0, fmt.Errorf("registry: list stuck submissions: %w", err)
	}
	sys := audit.Event{ActorKind: audit.ActorSystem}
	cause := TransitionCause{PipelineError: true}
	moved := 0
	for _, v := range rows {
		if err := s.TransitionFrom(ctx, v.ID, StatusSubmitted, StatusScanning,
			"the archive was never stored", sys, cause); err != nil {
			s.logger().Error("registry: watchdog could not move a stuck submission", "version", v.ID, "err", err)
			continue
		}
		reason := fmt.Sprintf("this version's archive was not stored within %s of the tag push, so it was rejected; push a new version tag", StuckSubmissionCap)
		if err := s.TransitionFrom(ctx, v.ID, StatusScanning, StatusRejected, reason, sys, cause); err != nil {
			s.logger().Error("registry: watchdog could not reject a stuck submission", "version", v.ID, "err", err)
			continue
		}
		s.logger().Warn("registry: stuck git-tag submission rejected", "version", v.ID)
		moved++
	}
	return moved, nil
}
