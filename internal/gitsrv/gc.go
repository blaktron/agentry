package gitsrv

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/queue"
)

// KindRepoGC is the gc job: housekeeping for a bare repository after
// pushes. The git handler enqueues one per accepted push
// with a delay so a burst of pushes coalesces into a quiet moment, and the
// job runs `git gc --auto`, which is a no-op unless git's own thresholds
// (loose objects, pack count) say there is work — so an extra job costs a
// fork and nothing else.
const KindRepoGC = "repo.gc"

// RepoGCArgs is the job payload.
type RepoGCArgs struct {
	RepoID uuid.UUID `json:"repoId"`
}

// gcDelay is how long after a push the gc runs; later pushes in the window
// each enqueue their own job, all of which are cheap no-ops after the first.
const gcDelay = 15 * time.Minute

// GC runs git's automatic housekeeping on a bare repository, bounded in time
// and with the same neutral environment archive/hook execution uses.
func (s *RepoStore) GC(ctx context.Context, repoID uuid.UUID) error {
	dir := s.Path(repoID)
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.gitBin, "-C", dir, "gc", "--auto", "--quiet") //nolint:gosec // fixed binary and args
	cmd.Env = archiveEnv()
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return fmt.Errorf("gitsrv: gc %s: %s", repoID, firstLine(msg))
		}
		return fmt.Errorf("gitsrv: gc %s: %w", repoID, err)
	}
	return nil
}

// registerGC attaches the repo.gc handler; a role without repository
// storage has nothing to do and marks the job done.
func (b *PushBookkeeper) registerGC(q queue.Client) {
	q.Register(KindRepoGC, func(ctx context.Context, job queue.Job) error {
		if b.repos == nil {
			return nil
		}
		var args RepoGCArgs
		if err := json.Unmarshal(job.Args, &args); err != nil {
			return fmt.Errorf("repo.gc: bad args: %w", err)
		}
		if err := b.repos.GC(ctx, args.RepoID); err != nil {
			b.log.Warn("repo.gc", "err", err, "repo", args.RepoID)
			return err
		}
		return nil
	})
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
