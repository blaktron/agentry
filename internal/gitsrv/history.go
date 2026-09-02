package gitsrv

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"

	"github.com/google/uuid"
)

// HistoryPatch streams the added lines of every non-merge commit reachable
// from commit as a unified diff (§8.3: S2 scans full git history on
// git-tag publishes, agentry#54). The stream is `git log -p` with each
// commit introduced by a line of the form "\x01<sha>" so the consumer can
// attribute a hit without ambiguity, zero context lines, no renames, and
// binary hunks summarized. Closing the reader terminates git.
func (s *RepoStore) HistoryPatch(ctx context.Context, repoID uuid.UUID, commit string) (io.ReadCloser, error) {
	dir := s.Path(repoID)
	if err := checkNoInfoAttributes(dir); err != nil {
		return nil, err
	}
	commit = strings.TrimSpace(commit)
	if commit == "" || strings.HasPrefix(commit, "-") {
		return nil, fmt.Errorf("gitsrv: history: invalid commit %q", commit)
	}
	ctx, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(ctx, s.gitBin, "-C", dir, "log", "-p", "--no-color", "--no-merges", //nolint:gosec // fixed binary; commit validated above
		"--format=%x01%H", "--diff-filter=AM", "--no-renames", "-U0", commit, "--")
	cmd.Env = archiveEnv()
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, fmt.Errorf("gitsrv: history: %w", err)
	}
	return &historyStream{r: out, cmd: cmd, cancel: cancel, stderr: &stderr}, nil
}

type historyStream struct {
	r      io.ReadCloser
	cmd    *exec.Cmd
	cancel context.CancelFunc
	stderr *strings.Builder
}

func (h *historyStream) Read(p []byte) (int, error) { return h.r.Read(p) }

// Close terminates git if it is still running and reaps it. A consumer
// that stopped early (output cap) is normal, so a killed process is not
// an error; a git that failed on its own is.
func (h *historyStream) Close() error {
	_ = h.r.Close()
	h.cancel()
	err := h.cmd.Wait()
	if err != nil && h.cmd.ProcessState != nil && h.cmd.ProcessState.Exited() && h.cmd.ProcessState.ExitCode() > 0 {
		if msg := strings.TrimSpace(h.stderr.String()); msg != "" {
			return fmt.Errorf("gitsrv: history: %s", msg)
		}
		return fmt.Errorf("gitsrv: history: %w", err)
	}
	return nil
}
