package registry

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/auth"
	storegen "github.com/blaktron/agentry/internal/store/gen"
	"github.com/blaktron/agentry/pkg/archive"
	"github.com/blaktron/agentry/pkg/manifest"
)

// Forks.
//
// Any signed-in account may fork a public QuickAgent into a namespace it
// may create in, under the same name unless another is given. The fork is
// its own agent: private for good, with its origin and the published
// version it was taken from kept on the row and never changed.
//
// It is made in two halves, because the api role holds no repositories (the
// chart mounts the git volume on the git and worker roles alone). Fork, in
// the request, authorizes, counts the namespace's quota and private-agent
// cap and records the fork, `copying`, then hands the copy to a worker.
// CopyFork, on the worker, copies the forked release's commit and its
// history from the origin's repository, writes one commit on top of it that
// renames the manifest into the fork's namespace, tags it with the same
// version and submits that tag through SubmitVersion like any submission:
// the same gates, the same admission (it is charged), the same
// pipeline. Nothing about a fork is ever written straight to published.
// The fork is `ready` once its first version is submitted, or `failed`
// with the reason in words.

// JobCopyFork is the worker's job that copies a fork's repository and
// submits its first version.
const JobCopyFork = "registry.copy_fork"

// StuckForkCap is how long a fork may stay `copying` before the watchdog
// marks it failed: the same allowance a handed-off tag archive gets, since
// the copy waits in the sandbox queue behind scans too.
const StuckForkCap = StuckSubmissionCap

// ForkState is a fork's copy, as fork_state records it.
const (
	ForkCopying = "copying"
	ForkReady   = "ready"
	ForkFailed  = "failed"
)

// CopyForkArgs are the job's arguments: the fork, and the account that
// asked for it, whose standing the worker reloads before submitting.
type CopyForkArgs struct {
	AgentID uuid.UUID `json:"agentId"`
	UserID  uuid.UUID `json:"userId"`
}

// ForkHandOff enqueues JobCopyFork (api.Server's queue).
type ForkHandOff interface {
	CopyFork(ctx context.Context, args CopyForkArgs) error
}

// SetForkHandOff wires the queue Fork hands the copy to.
func (s *Service) SetForkHandOff(h ForkHandOff) { s.forkHandOff = h }

// ForkRepos is what CopyFork needs of the repositories: a role that can
// read and write them (the worker, `all`) wires it.
type ForkRepos interface {
	// CopyHistory creates dst as a bare repository on defaultBranch and
	// copies into it commit and its history from src, through a tag of
	// src that points at it, with defaultBranch at commit; nothing else of
	// src comes over (copied, never shared through alternates, so nothing
	// done to src later reaches dst). An empty commit, a commit no tag of
	// src points at, or a src that was never pushed to leaves dst empty.
	CopyHistory(ctx context.Context, src, dst uuid.UUID, defaultBranch, commit string) error
	// RemoveRepository deletes a repository a failed copy left behind.
	RemoveRepository(repoID uuid.UUID) error
	// HasCommit reports whether commit is a commit in repo.
	HasCommit(ctx context.Context, repoID uuid.UUID, commit string) (bool, error)
	// ReadFileAt reads path's blob at commit.
	ReadFileAt(ctx context.Context, repoID uuid.UUID, commit, path string) ([]byte, error)
	// CommitFork writes one commit and points its refs at it.
	CommitFork(ctx context.Context, repoID uuid.UUID, c ForkCommit) (string, error)
}

// ForkCommit is the fork's one commit: a tree, the manifest replaced in it,
// the parent it continues from, and the refs moved to it.
type ForkCommit struct {
	// BaseCommit is the commit whose tree the fork's starts from. Empty
	// means Dir's files are the tree instead (an origin version with no
	// commit behind it: one uploaded rather than tagged).
	BaseCommit string
	Dir        string
	// ManifestPath's content is replaced with Manifest.
	ManifestPath string
	Manifest     []byte
	// Parent is the commit the fork's continues; empty for a root commit.
	Parent  string
	Message string
	// Refs are moved to the commit, whatever they held (the fork's default
	// branch, which the copy left at the origin's release, and its release
	// tag).
	Refs []string
	// Author is the account that forked, as a commit's identity.
	AuthorName  string
	AuthorEmail string
	When        time.Time
}

// SetForkRepos wires the repositories CopyFork copies.
func (s *Service) SetForkRepos(r ForkRepos) { s.forkRepos = r }

// ForkInput is a fork's target.
type ForkInput struct {
	Namespace string
	// Name defaults to the origin's.
	Name string
}

var (
	// ErrForkSourceNotForkable reports an origin that is not public, or
	// that the platform has quarantined or blocked.
	ErrForkSourceNotForkable = errors.New("registry: only a public QuickAgent in good standing can be forked")
	// ErrNothingToFork reports an origin with no published version.
	ErrNothingToFork = errors.New("registry: the QuickAgent has no published version to fork")
	// ErrNameTaken reports a fork whose name the target namespace already
	// has; the API answers 409 name-taken, and the person picks another.
	ErrNameTaken = errors.New("registry: the namespace already has a QuickAgent of that name")
	// ErrNameHeld reports a name a deleted agent holds for good.
	ErrNameHeld = errors.New("registry: the name is held by a deleted QuickAgent")
	// ErrForkTree reports a release whose files cannot be a fork's tree
	// (a .git path, a file that is not a regular one): ForkRepos wraps it,
	// and the fork fails rather than retrying.
	ErrForkTree = errors.New("registry: the release's files cannot be a fork's tree")
)

// Fork records a fork of src for p in in.Namespace and hands its copy to a
// worker. src is resolved and readable by p (the handler's agentForAction).
// The fork is returned `copying`.
func (s *Service) Fork(ctx context.Context, p *auth.Principal, src Agent, in ForkInput, actorEvent audit.Event) (Agent, error) {
	if p == nil || p.Anonymous {
		return Agent{}, auth.ErrUnauthorized
	}
	// Public is what makes an agent forkable: a retired or deleted agent
	// is private, and a fork is private, so a fork of a fork cannot happen
	// and lineage is one level deep. A quarantine or a block is the
	// platform's pause or stop, and a fork taken through it would carry
	// what the platform stopped.
	if src.Visibility != "public" || src.QuarantineState != "none" || src.RetiredAt != nil || src.DeletedAt != nil || src.ForkedFromAgentID != nil {
		return Agent{}, ErrForkSourceNotForkable
	}
	if src.LatestPublishedVersionID == nil {
		return Agent{}, ErrNothingToFork
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = src.Name
	}
	if !AgentNameRe.MatchString(name) {
		return Agent{}, fmt.Errorf("%w: the agent name must be 1-65 lowercase letters, digits and hyphens, starting and ending with a letter or digit", ErrDenied)
	}
	if s.forkHandOff == nil {
		return Agent{}, errors.New("registry: forks are unavailable on this role (no queue to copy them on)")
	}
	// The fork is private, so creating it is a member's in an organization
	// and needs a place under the private-agent cap.
	t, err := s.createTarget(ctx, p, in.Namespace, "private")
	if err != nil {
		return Agent{}, err
	}
	if held, err := s.resolve(ctx, in.Namespace, name, true); err == nil {
		if held.DeletedAt != nil {
			return Agent{}, ErrNameHeld
		}
		return Agent{}, ErrNameTaken
	} else if !errors.Is(err, ErrNotFound) {
		return Agent{}, err
	}

	repoID, agentID := newUUID(), newUUID()
	version := *src.LatestPublishedVersionID
	err = s.st.WithTx(ctx, func(q *storegen.Queries) error {
		if err := s.checkRoomInTx(ctx, q, t, "private"); err != nil {
			return err
		}
		// The forked version, read again under the transaction: a yank or
		// a block since the origin was resolved leaves nothing to fork.
		v, err := q.GetVersionByID(ctx, version)
		if err != nil {
			return fmt.Errorf("registry: forked version: %w", err)
		}
		if Status(v.Status) != StatusPublished {
			return ErrNothingToFork
		}
		if _, err := q.CreateRepoWithBranch(ctx, storegen.CreateRepoWithBranchParams{ID: repoID, DefaultBranch: src.DefaultBranch}); err != nil {
			return err
		}
		if _, err := q.CreateForkAgent(ctx, storegen.CreateForkAgentParams{
			ID: agentID, NamespaceID: t.ns.ID, Name: name, RepoID: repoID,
			Summary: src.Summary, Modes: src.Modes,
			ForkedFromAgentID: &src.ID, ForkedFromVersionID: &version, ForkedBy: &p.UserID,
		}); err != nil {
			if isUniqueViolationErr(err) {
				return ErrNameTaken
			}
			return err
		}
		// The audit event goes to the fork's namespace only. The origin's
		// publisher is told how many forks there are, never whose.
		e := actorEvent
		e.Action = audit.ActionAgentFork
		if t.ns.Kind == "org" {
			e.OrgID = t.ns.ID
		}
		e.TargetKind, e.TargetID = "agent", agentID
		e.Detail = map[string]any{
			"path":       in.Namespace + "/" + name,
			"forkedFrom": src.Namespace + "/" + src.Name + "@" + v.Version,
		}
		return s.aud.Write(ctx, q, e)
	})
	if err != nil {
		return Agent{}, err
	}
	if err := s.forkHandOff.CopyFork(ctx, CopyForkArgs{AgentID: agentID, UserID: p.UserID}); err != nil {
		s.logger().Error("registry: fork hand-off failed", "agent", agentID, "err", err)
		s.failFork(ctx, agentID, "Agentry could not start copying this fork. Delete it and fork again.")
	}
	return s.Resolve(ctx, in.Namespace, name)
}

// failFork marks a fork failed with detail, the sentence its readers see.
// From `copying` only; a fork that is ready stays ready.
func (s *Service) failFork(ctx context.Context, agentID uuid.UUID, detail string) {
	if _, err := s.st.Queries().SetForkState(ctx, storegen.SetForkStateParams{ID: agentID, ForkState: ptr(ForkFailed), ForkDetail: detail}); err != nil {
		s.logger().Error("registry: could not mark a fork failed", "agent", agentID, "err", err)
	}
}

func ptr[T any](v T) *T { return &v }

// CopyFork is JobCopyFork's handler. p is the account that forked, as it
// stands now (nil when it no longer does), and pipeline the queue the first
// version goes to. It is idempotent: a fork that is no longer `copying` is
// done, and a copy a crash left half-made is started again from nothing.
// What the job cannot fix by trying again (the account gone, the forked
// version withdrawn, a submission the gates or admission refuse) marks the
// fork failed with the reason and returns nil; anything else is returned
// for the queue to retry, and the watchdog marks a fork that never
// finishes.
func (s *Service) CopyFork(ctx context.Context, args CopyForkArgs, p *auth.Principal, pipeline Pipeline) error {
	q := s.st.Queries()
	row, err := q.GetAgentByID(ctx, args.AgentID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil // deleted before the copy ran
	}
	if err != nil {
		return err
	}
	if row.ForkState == nil || *row.ForkState != ForkCopying || row.ForkedFromAgentID == nil || row.ForkedFromVersionID == nil {
		return nil
	}
	fork, err := s.Resolve(ctx, row.Namespace, row.Name)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if s.forkRepos == nil || s.blobs == nil {
		return errors.New("registry: this role cannot copy forks (no repositories or no object store)")
	}
	if p == nil {
		s.failFork(ctx, fork.ID, "The account that forked this QuickAgent no longer stands, so its first version was not submitted.")
		return nil
	}
	// The organization may have been suspended or put on its decommission
	// hold since the fork was recorded: a request would meet that gate in
	// the middleware, and this job never passes through it.
	if err := s.OrgGateFor(ctx, fork, auth.ActAgentPublish); err != nil {
		var gate *OrgGateError
		if errors.As(err, &gate) {
			s.failFork(ctx, fork.ID, "The organization "+fork.Namespace+" is not taking new versions now, so the fork's first version was not submitted.")
			return nil
		}
		return err
	}
	// Taken off the pipeline before its first version (the pipeline-skip
	// flag, set by an organization's administrator while the copy waited):
	// the first version of a fork is always scanned.
	if fork.PipelineSkip {
		s.failFork(ctx, fork.ID, "This fork was taken off the pipeline before its first version, which a fork's first version never is. Clear pipeline: skip, delete this fork and fork again.")
		return nil
	}
	// The account may have lost its place in the namespace since it
	// forked: the submission is the publish rung's, asked again now.
	if role, err := s.EffectiveRole(ctx, p, fork); err != nil {
		return err
	} else if auth.CheckAgent(p, auth.AgentResource{EffectiveRole: role}, auth.ActAgentPublish) != nil {
		s.failFork(ctx, fork.ID, "The account that forked this QuickAgent can no longer publish in "+fork.Namespace+", so its first version was not submitted.")
		return nil
	}
	ov, err := q.GetVersionByID(ctx, *row.ForkedFromVersionID)
	if err != nil {
		return err
	}
	if Status(ov.Status) != StatusPublished {
		s.failFork(ctx, fork.ID, "The version this fork was taken from was withdrawn before it was copied, so the fork has no first version.")
		return nil
	}
	origin, err := q.GetAgentByID(ctx, *row.ForkedFromAgentID)
	if err != nil {
		return err
	}
	// A version already recorded means an earlier attempt got as far as
	// the submission; the fork is ready.
	if vs, err := q.ListVersions(ctx, fork.ID); err != nil {
		return err
	} else if len(vs) > 0 {
		return q.MarkForkReady(ctx, fork.ID)
	}

	// Start from nothing: whatever an attempt that died left on disk.
	if err := s.forkRepos.RemoveRepository(fork.RepoID); err != nil {
		return err
	}
	// The fork's owner reads every object in its repository, so it takes
	// only what a reader with no role may clone from the origin: the
	// forked release's commit and its history, when a review passed it.
	// Not the origin's branches, nor its other tags, which may be work
	// awaiting review, refused or never submitted. A collaborator of the
	// origin is held to the same: the fork outlives their role, and its
	// own namespace's members never had one.
	var history string
	if ov.CommitSha != "" && ov.ScanStatus == ScanStatusPipeline && origin.QuarantineState == "none" {
		history = ov.CommitSha
	}
	if err := s.forkRepos.CopyHistory(ctx, origin.RepoID, fork.RepoID, fork.DefaultBranch, history); err != nil {
		return err
	}
	if _, err := s.forkCommit(ctx, fork, origin.Namespace+"/"+origin.Name, ov, p); err != nil {
		var refused *forkRefusal
		if errors.As(err, &refused) {
			s.failFork(ctx, fork.ID, refused.detail)
			return nil
		}
		return err
	}

	tag := "v" + ov.Version
	ws, err := os.MkdirTemp("", "agentry-fork-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(ws) }()
	if s.gitArchiver == nil {
		return errors.New("registry: this role cannot read the repositories (no git data)")
	}
	commitSHA, err := s.gitArchiver.MaterializeTag(ctx, fork.RepoID, tag, ws)
	if err != nil {
		return err
	}
	forker := audit.Event{Actor: p.UserID, ActorKind: audit.ActorUser}
	_, err = s.SubmitVersion(ctx, p, fork, SubmitInput{
		Source: SourceGitTag, Tag: tag, CommitSHA: commitSHA, Workspace: ws, pipeline: pipeline,
	}, forker)
	switch {
	case err == nil, errors.Is(err, ErrScanNotScheduled):
		// The version is recorded; a scan that was not scheduled is the
		// scan watchdog's. Ready even if the fork watchdog gave up on
		// the copy meanwhile: the version is there.
		return q.MarkForkReady(ctx, fork.ID)
	case isForkSubmitRefusal(err):
		s.failFork(ctx, fork.ID, "The fork's first version was refused: "+refusalWords(err))
		return nil
	default:
		return err
	}
}

// forkRefusal is a reason the copy cannot succeed by trying again.
type forkRefusal struct{ detail string }

func (e *forkRefusal) Error() string { return e.detail }

// forkCommit writes the fork's one commit and points the fork's default
// branch and its release tag at it. Its tree is the forked version's, with
// the manifest renamed into the fork's namespace: the version's commit when
// the copy brought it over, else the version's archive (a version uploaded
// rather than tagged has no commit, and one no review passed has none
// copied). Its parent is that commit, so the fork's history runs back
// through the origin's release; from an archive it is a root commit.
func (s *Service) forkCommit(ctx context.Context, fork Agent, originPath string, ov Version, p *auth.Principal) (string, error) {
	c := ForkCommit{
		ManifestPath: "agent.yaml",
		Message:      fmt.Sprintf("Fork of %s@%s\n\nRenamed to %s/%s.\n", originPath, ov.Version, fork.Namespace, fork.Name),
		Refs:         []string{"refs/heads/" + fork.DefaultBranch, "refs/tags/v" + ov.Version},
		AuthorName:   p.Handle,
		AuthorEmail:  p.Handle + "@users.noreply.agentry",
		When:         time.Now().UTC(),
	}
	var raw []byte
	has := false
	if ov.CommitSha != "" {
		var err error
		if has, err = s.forkRepos.HasCommit(ctx, fork.RepoID, ov.CommitSha); err != nil {
			return "", err
		}
	}
	if has {
		c.BaseCommit, c.Parent = ov.CommitSha, ov.CommitSha
		var err error
		if raw, err = s.forkRepos.ReadFileAt(ctx, fork.RepoID, ov.CommitSha, c.ManifestPath); errors.Is(err, fs.ErrNotExist) {
			return "", &forkRefusal{detail: "The forked version's commit has no agent.yaml, so it could not be renamed."}
		} else if err != nil {
			return "", err
		}
	} else {
		dir, err := os.MkdirTemp("", "agentry-fork-tree-*")
		if err != nil {
			return "", err
		}
		defer func() { _ = os.RemoveAll(dir) }()
		if err := s.extractVersionArchive(ctx, ov, dir); err != nil {
			return "", err
		}
		c.Dir = dir
		if raw, err = os.ReadFile(filepath.Join(dir, c.ManifestPath)); errors.Is(err, fs.ErrNotExist) { //nolint:gosec // server-created directory
			return "", &forkRefusal{detail: "The forked version's archive has no agent.yaml, so it could not be renamed."}
		} else if err != nil {
			return "", err
		}
	}
	renamed, err := manifest.Rename(raw, fork.Namespace, fork.Name)
	if err != nil {
		return "", &forkRefusal{detail: "The forked version's agent.yaml could not be renamed: " + err.Error()}
	}
	c.Manifest = renamed
	commit, err := s.forkRepos.CommitFork(ctx, fork.RepoID, c)
	if errors.Is(err, ErrForkTree) {
		// Not something a retry changes.
		return "", &forkRefusal{detail: "The forked version's archive holds a .git path or a file that is not a regular one, which a fork's repository cannot take."}
	}
	return commit, err
}

// extractVersionArchive unpacks a published version's archive from the
// store into dir, within the extraction limits every reader of an archive
// keeps.
func (s *Service) extractVersionArchive(ctx context.Context, v Version, dir string) error {
	if v.ArchiveKey == nil {
		return &forkRefusal{detail: "The forked version has no archive in the store, so it could not be copied."}
	}
	r, err := s.blobs.Get(ctx, *v.ArchiveKey)
	if err != nil {
		return err
	}
	defer func() { _ = r.Close() }()
	var size int64
	if v.ArchiveSize != nil {
		size = *v.ArchiveSize
	}
	return archive.Extract(r, dir, size, archive.DefaultLimits())
}

// isForkSubmitRefusal says whether a submission error is a refusal that
// trying again will not change: the gates, the quotas, admission.
func isForkSubmitRefusal(err error) bool {
	var v *ErrValidation
	var r *ErrAdmissionRefused
	return errors.As(err, &v) || errors.As(err, &r) || errors.Is(err, ErrDenied) || errors.Is(err, ErrRetired) ||
		errors.Is(err, ErrTwoFactorRequired) || errors.Is(err, ErrNotFound) || errors.Is(err, auth.ErrUnauthorized)
}

// refusalWords is a refused submission's reason as its fork's readers see
// it, by the refusal's kind: admission's own detail (its error is only a
// slug), the validation issues, a quota or rule's sentence.
func refusalWords(err error) string {
	var r *ErrAdmissionRefused
	var v *ErrValidation
	switch {
	case errors.As(err, &r) && r.Refusal.Detail != "":
		return sentenceOf(r.Refusal.Detail)
	case errors.As(err, &v):
		msgs := make([]string, 0, len(v.Issues))
		for _, i := range v.Issues {
			msgs = append(msgs, i.Error())
		}
		return sentenceOf(strings.Join(msgs, "; "))
	case errors.Is(err, ErrRetired):
		return "The fork was retired before its first version."
	case errors.Is(err, ErrTwoFactorRequired):
		return "This needs two-factor authentication on the account that forked."
	case errors.Is(err, ErrDenied):
		// ErrDenied wraps its sentence after its own text.
		return sentenceOf(strings.TrimPrefix(err.Error(), ErrDenied.Error()+": "))
	}
	return "Agentry could not take it."
}

// sentenceOf is msg with a capital and a full stop.
func sentenceOf(msg string) string {
	msg = strings.TrimSpace(msg)
	if msg == "" {
		return "No reason was given."
	}
	if !strings.HasSuffix(msg, ".") {
		msg += "."
	}
	return strings.ToUpper(msg[:1]) + msg[1:]
}

// ReconcileStuckForks is the watchdog for forks whose copy never finished:
// past StuckForkCap, each is marked failed so its readers are told rather
// than left waiting. Returns how many it marked.
func (s *Service) ReconcileStuckForks(ctx context.Context) (int, error) {
	ids, err := s.st.Queries().ListStuckForks(ctx, storegen.ListStuckForksParams{
		CreatedBefore: time.Now().Add(-StuckForkCap), RowLimit: 200,
	})
	if err != nil {
		return 0, fmt.Errorf("registry: list stuck forks: %w", err)
	}
	for _, id := range ids {
		s.failFork(ctx, id, fmt.Sprintf("The copy did not finish within %s of the fork. Delete this fork and fork again.", StuckForkCap))
	}
	return len(ids), nil
}
