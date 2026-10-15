package gitsrv

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/audit"
	"github.com/blaktron/agentry/internal/queue"
	"github.com/blaktron/agentry/internal/store"
	storegen "github.com/blaktron/agentry/internal/store/gen"
)

// KindRepoPushed is the `repo.pushed` queue event. The git handler
// enqueues one per accepted push, in the request; the bookkeeping it
// carries — repo size, last_push_at, the audit row — then runs from the
// queue, so a git-role crash between receive-pack and bookkeeping does not
// lose them. Enqueue is one INSERT and is what
// makes the work durable; the handler keeps its inline path only for the
// no-queue case (tests, a role wired without a queue client).
const KindRepoPushed = "repo.pushed"

// RepoPushedArgs is the job payload. Everything the bookkeeping needs is
// carried so the worker never re-derives the principal or the agent.
type RepoPushedArgs struct {
	AgentID uuid.UUID `json:"agentId"`
	RepoID  uuid.UUID `json:"repoId"`
	// OrgID is the owning org for org-scoped audit; zero for user agents.
	OrgID uuid.UUID `json:"orgId,omitempty"`
	// ActorID is the pushing principal's user id (audit actor, PAT kind).
	ActorID uuid.UUID `json:"actorId"`
	// Refs are the accepted ref names, e.g. refs/heads/main, refs/tags/v1.0.0.
	Refs []string `json:"refs"`
}

// PushBookkeeper performs the repo.pushed bookkeeping. repos may be nil on
// a role without repository storage: the size is then left as it was and
// only last_push_at advances (TouchRepoOnPush), exactly as when `du` fails.
type PushBookkeeper struct {
	st    *store.Store
	repos *RepoStore
	aud   *audit.Writer
	log   *slog.Logger
	// diskUsage measures a repo; a field so tests can force its failure path.
	diskUsage func(uuid.UUID) (int64, error)
}

// NewPushBookkeeper wires the bookkeeping for a role.
func NewPushBookkeeper(st *store.Store, repos *RepoStore, aud *audit.Writer, log *slog.Logger) *PushBookkeeper {
	if log == nil {
		log = slog.Default()
	}
	b := &PushBookkeeper{st: st, repos: repos, aud: aud, log: log}
	if repos != nil {
		b.diskUsage = repos.DiskUsage
	}
	return b
}

// Register attaches the repo.pushed handler to a queue client.
func (b *PushBookkeeper) Register(q queue.Client) {
	q.Register(KindRepoPushed, func(ctx context.Context, job queue.Job) error {
		var args RepoPushedArgs
		if err := json.Unmarshal(job.Args, &args); err != nil {
			return fmt.Errorf("repo.pushed: bad args: %w", err)
		}
		return b.Run(ctx, args)
	})
	b.registerGC(q)
}

// Run does the bookkeeping for one push: size + last_push_at, then the
// audit row. A failed measurement degrades to a touch rather than a
// failed job (the refs are already durable; the size catches up on the
// next push), while a failed database write returns the error so the
// queue retries it.
func (b *PushBookkeeper) Run(ctx context.Context, args RepoPushedArgs) error {
	q := b.st.Queries()
	if b.diskUsage == nil {
		if err := q.TouchRepoOnPush(ctx, args.RepoID); err != nil {
			return fmt.Errorf("repo.pushed: touch: %w", err)
		}
	} else if size, err := b.diskUsage(args.RepoID); err != nil {
		b.log.Warn("post-receive du", "err", err, "repo", args.RepoID)
		if err := q.TouchRepoOnPush(ctx, args.RepoID); err != nil {
			return fmt.Errorf("repo.pushed: touch: %w", err)
		}
	} else if err := q.UpdateRepoOnPush(ctx, storegen.UpdateRepoOnPushParams{ID: args.RepoID, SizeBytes: size}); err != nil {
		return fmt.Errorf("repo.pushed: size: %w", err)
	}
	e := audit.Event{
		Actor: args.ActorID, ActorKind: audit.ActorPAT,
		Action: audit.ActionRepoPush, TargetKind: "agent", TargetID: args.AgentID,
		Detail: map[string]any{"refs": args.Refs},
	}
	if args.OrgID != uuid.Nil {
		e.OrgID = args.OrgID
	}
	if err := b.aud.Write(ctx, q, e); err != nil {
		return fmt.Errorf("repo.pushed: audit: %w", err)
	}
	return nil
}
