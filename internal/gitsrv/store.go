// Package gitsrv implements git hosting: bare-repo storage keyed by repo
// UUID, smart HTTP v2 by shelling out to git, and the pre-receive policy
// hook.
package gitsrv

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/config"
)

// RepoStore manages bare repositories under cfg.Git.DataDir:
// {dataDir}/{uuid[0:2]}/{uuid}.git.
type RepoStore struct {
	dataDir string
	gitBin  string
	hookBin string
	limits  config.Limits

	hooksBase string // cfg.Git.HooksDir: where each push's hooks directory is made (pushHooks)
}

// NewRepoStore builds the store. hookBin is the agentryd binary the hooks
// exec; empty means the current executable.
func NewRepoStore(cfg config.Config) (*RepoStore, error) {
	gitBin := cfg.Git.BinPath
	if gitBin == "" {
		p, err := exec.LookPath("git")
		if err != nil {
			return nil, fmt.Errorf("gitsrv: git binary not found: %w", err)
		}
		gitBin = p
	}
	// Release archives depend on `git archive` ignoring gitattributes;
	// prove it against this binary now rather than discovering at publish
	// time that releases have been silently filtered by a pushed
	// export-ignore (see archive.go).
	if err := verifyArchiveNeutralizesAttributes(gitBin); err != nil {
		return nil, err
	}
	hookBin, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("gitsrv: resolve executable for hooks: %w", err)
	}
	if err := os.MkdirAll(cfg.Git.DataDir, 0o750); err != nil {
		return nil, fmt.Errorf("gitsrv: data dir: %w", err)
	}
	return &RepoStore{
		dataDir:   cfg.Git.DataDir,
		gitBin:    gitBin,
		hookBin:   hookBin,
		limits:    cfg.Limits,
		hooksBase: cfg.Git.HooksDir,
	}, nil
}

// preReceiveShim is the hook git runs: it execs the agentryd binary the
// serving process names in AGENTRY_HOOK_BIN (gitEnv sets it; the variable
// rather than a recorded path lets the binary move during a rolling deploy),
// and exits non-zero without it, so a git started without the request
// context refuses the push rather than guessing.
const preReceiveShim = "#!/bin/sh\nexec \"${AGENTRY_HOOK_BIN:?AGENTRY_HOOK_BIN is not set}\" hook pre-receive \"$@\"\n"

// PrepareHooks proves the git role can run its pre-receive hook: it makes
// a hooks directory the way every push does (pushHooks), runs the hook
// there, and removes it. The git role calls it at startup, so a hooks base
// that cannot run hooks (a noexec mount) stops the role instead of every
// push being refused.
//
// Git runs the hook from such a directory rather than from each bare
// repository's hooks/ because the repository volume may be one the kernel
// will not exec from: on a virtiofs file system, for example, git fails
// with "cannot exec 'hooks/pre-receive': Bad address".
func (s *RepoStore) PrepareHooks() error {
	_, done, err := s.pushHooks()
	if err != nil {
		return err
	}
	done()
	return nil
}

// pushHooks makes a hooks directory for one receive-pack under the hooks
// base (the system temp directory when unset) and runs its hook once before
// git starts. The directory is the push's alone and is removed by done
// after git exits: no other push can remove it mid-upload, and a temp
// cleaner, which goes by age, does not take a file made moments ago. Its
// random name and mode 0700 (mkdir(2), which fails on an existing name)
// mean no other user can have planted a hook there beforehand. Not covered:
// a noexec remount of the base during the upload, and, in a base other
// users can write to that is not sticky, another user renaming the
// directory and putting theirs in its place.
func (s *RepoStore) pushHooks() (dir string, done func(), err error) {
	base := s.hooksBase
	if base == "" {
		base = os.TempDir()
	}
	if base, err = filepath.Abs(base); err != nil {
		return "", nil, fmt.Errorf("gitsrv: git hooks directory: %w", err)
	}
	if dir, err = os.MkdirTemp(base, "agentry-git-hooks-"); err != nil {
		return "", nil, fmt.Errorf("gitsrv: git hooks directory under %s: %w", base, err)
	}
	done = func() { _ = os.RemoveAll(dir) }
	if err = os.WriteFile(filepath.Join(dir, "pre-receive"), []byte(preReceiveShim), 0o700); err != nil { //nolint:gosec // hooks must be executable
		done()
		return "", nil, fmt.Errorf("gitsrv: git hooks directory: %w", err)
	}
	if err = s.exerciseHook(dir); err != nil {
		done()
		return "", nil, fmt.Errorf("gitsrv: git hooks cannot run from %s; set AGENTRY_GIT_HOOKS_DIR to a directory the server owns on a file system that allows exec: %w", base, err)
	}
	return dir, done, nil
}

// exerciseHook runs dir's pre-receive the way git would, with no ref
// updates on stdin, which the policy accepts. Git skips a hook that is
// missing or that it cannot exec and applies the push unpoliced, so this
// shows that the kernel runs the hook from that directory at that moment.
func (s *RepoStore) exerciseHook(dir string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(dir, "pre-receive")) //nolint:gosec // the shim this store wrote
	cmd.Dir = dir                                                      // the policy's quota walk measures the working directory
	cmd.Env = append(os.Environ(), "AGENTRY_HOOK_BIN="+s.hookBin)
	cmd.Stdin = strings.NewReader("")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Command starts a git service (upload-pack, receive-pack) for a client;
// done must be called once git has exited. A receive-pack gets its own
// hooks directory (pushHooks) as core.hooksPath, given on the command line,
// where it outranks any repository or environment config; when no hook
// will run, no receive-pack is started and the error says why.
func (s *RepoStore) Command(ctx context.Context, service string, args ...string) (cmd *exec.Cmd, done func(), err error) {
	argv := append([]string{service}, args...)
	done = func() {}
	// The ref advertisement receives nothing and runs no hook.
	if service == "receive-pack" && !slices.Contains(args, "--advertise-refs") {
		var dir string
		if dir, done, err = s.pushHooks(); err != nil {
			return nil, nil, err
		}
		argv = append([]string{"-c", "core.hooksPath=" + dir}, argv...)
	}
	return exec.CommandContext(ctx, s.gitBin, argv...), done, nil //nolint:gosec // fixed binary; service names and store paths
}

// Path returns the bare-repo directory for a repo id.
func (s *RepoStore) Path(repoID uuid.UUID) string {
	id := repoID.String()
	return filepath.Join(s.dataDir, id[:2], id+".git")
}

// InitBare creates and configures a bare repository: default branch,
// deny-delete-current, quota-derived receive.maxInputSize, policy hooks.
func (s *RepoStore) InitBare(ctx context.Context, repoID uuid.UUID, defaultBranch string) error {
	dir := s.Path(repoID)
	if _, err := os.Stat(dir); err == nil {
		return fmt.Errorf("gitsrv: repo %s already exists", repoID)
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0o750); err != nil {
		return err
	}
	run := func(args ...string) error {
		cmd := exec.CommandContext(ctx, s.gitBin, args...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("gitsrv: git %s: %v: %s", strings.Join(args, " "), err, out)
		}
		return nil
	}
	if err := run("init", "--bare", "-b", defaultBranch, dir); err != nil {
		return err
	}
	for _, kv := range [][2]string{
		{"receive.denyDeleteCurrent", "true"},
		{"receive.maxInputSize", fmt.Sprintf("%d", s.limits.RepoQuotaBytes)},
		{"uploadpack.allowFilter", "true"}, // partial clone
		{"core.commitGraph", "true"},       // faster history walks on large repos
	} {
		if err := run("-C", dir, "config", kv[0], kv[1]); err != nil {
			return err
		}
	}
	// The repository's own copy of the shim, which git runs when it is
	// started other than through Command; a receive-pack started through
	// Command runs its own hooks directory's instead.
	hookDir := filepath.Join(dir, "hooks")
	if err := os.WriteFile(filepath.Join(hookDir, "pre-receive"), []byte(preReceiveShim), 0o755); err != nil { //nolint:gosec // hooks must be executable
		return err
	}
	return nil
}

// Remove deletes a bare repository (compensation path).
func (s *RepoStore) Remove(repoID uuid.UUID) error {
	dir := s.Path(repoID)
	if !strings.HasPrefix(dir, filepath.Clean(s.dataDir)+string(os.PathSeparator)) {
		return fmt.Errorf("gitsrv: refusing to remove outside data dir")
	}
	return os.RemoveAll(dir)
}

// RefsAt reads the current object id of each named ref, omitting refs that do
// not exist. Push bookkeeping uses it to tell which requested updates were
// actually applied: receive-pack exits 0 even when the pre-receive hook
// rejects every command, so the repository — not the request — is the
// authority on what changed.
func (s *RepoStore) RefsAt(ctx context.Context, repoID uuid.UUID, refs []string) (map[string]string, error) {
	args := []string{"-C", s.Path(repoID), "for-each-ref", "--format=%(objectname) %(refname)"}
	for _, ref := range refs {
		// Only well-formed ref names become patterns: receive-pack commands
		// come from the client, and a leading "-" or a glob would otherwise
		// be read as an option or widen the match.
		if !safeRefName(ref) {
			continue
		}
		args = append(args, ref)
	}
	out, err := exec.CommandContext(ctx, s.gitBin, args...).Output() //nolint:gosec // fixed binary; ref names validated above
	if err != nil {
		return nil, fmt.Errorf("gitsrv: for-each-ref: %w", err)
	}
	have := make(map[string]string)
	for _, line := range strings.Split(string(out), "\n") {
		oid, name, ok := strings.Cut(line, " ")
		if ok {
			have[name] = oid
		}
	}
	return have, nil
}

// safeRefName reports whether a client-supplied ref name is a plain,
// fully-qualified ref: safe to hand to git as a literal pattern.
func safeRefName(ref string) bool {
	if !strings.HasPrefix(ref, "refs/") || len(ref) > 512 {
		return false
	}
	return !strings.ContainsAny(ref, " \t\n*?[]\\^:~")
}

// DiskUsage returns the repo's approximate size in bytes.
func (s *RepoStore) DiskUsage(repoID uuid.UUID) (int64, error) {
	var total int64
	err := filepath.Walk(s.Path(repoID), func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			total += info.Size()
		}
		return nil
	})
	return total, err
}
