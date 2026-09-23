// Package gitsrv implements git hosting (§6): bare-repo storage keyed by
// repo UUID (D-19), smart HTTP v2 by shelling out to git (D-07), and the
// pre-receive policy hook.
package gitsrv

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/config"
)

// RepoStore manages bare repositories under cfg.Git.DataDir:
// {dataDir}/{uuid[0:2]}/{uuid}.git (§6.2).
type RepoStore struct {
	dataDir string
	gitBin  string
	hookBin string
	limits  config.Limits

	hooksBase string     // cfg.Git.HooksDir: where PrepareHooks makes hooksDir
	hooksMu   sync.Mutex // guards hooksDir
	hooksDir  string     // where git runs the policy hook from (PrepareHooks)
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
	// §6.5 depends on `git archive` ignoring gitattributes; prove it against
	// this binary now rather than discovering at publish time that releases
	// have been silently filtered by a pushed export-ignore (see archive.go).
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

// PrepareHooks makes the directory git runs the pre-receive hook from and
// proves the hook runs there; the git role calls it at startup so a
// directory that cannot run hooks (a noexec mount) stops the role instead
// of refusing every push. Receive-pack prepares it on first use when
// nothing called this first.
//
// Git is pointed there (Command) rather than at each bare repository's
// hooks/ because the repository volume may be one the kernel will not exec
// from: on Vultr's virtiofs file system every push failed with "cannot exec
// 'hooks/pre-receive': Bad address" (agentry#495).
func (s *RepoStore) PrepareHooks() error {
	s.hooksMu.Lock()
	defer s.hooksMu.Unlock()
	return s.prepareHooksLocked()
}

func (s *RepoStore) prepareHooksLocked() error {
	base := s.hooksBase
	if base == "" {
		base = os.TempDir()
	}
	base, err := filepath.Abs(base)
	if err != nil {
		return fmt.Errorf("gitsrv: git hooks directory: %w", err)
	}
	// A directory every user can write to is safe to make ours in only
	// when it is sticky (/tmp): otherwise another user could rename ours
	// away and put theirs in its place.
	fi, err := os.Stat(base)
	if err != nil {
		return fmt.Errorf("gitsrv: git hooks directory: %w", err)
	}
	if fi.Mode().Perm()&0o002 != 0 && fi.Mode()&os.ModeSticky == 0 {
		return fmt.Errorf("gitsrv: git hooks directory: %s is writable by every user and not sticky; set AGENTRY_GIT_HOOKS_DIR to a directory the server owns", base)
	}
	// A random name made with mkdir(2) at 0700: nothing can have been
	// planted there first.
	dir, err := os.MkdirTemp(base, "agentry-git-hooks-")
	if err != nil {
		return fmt.Errorf("gitsrv: git hooks directory under %s: %w", base, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pre-receive"), []byte(preReceiveShim), 0o700); err != nil { //nolint:gosec // hooks must be executable
		_ = os.RemoveAll(dir)
		return fmt.Errorf("gitsrv: git hooks directory: %w", err)
	}
	if err := s.exerciseHook(dir); err != nil {
		_ = os.RemoveAll(dir)
		return fmt.Errorf("gitsrv: git hooks cannot run from %s; set AGENTRY_GIT_HOOKS_DIR to a directory on a file system that allows exec: %w", base, err)
	}
	if s.hooksDir != "" && s.hooksDir != dir {
		_ = os.RemoveAll(s.hooksDir)
	}
	s.hooksDir = dir
	return nil
}

// exerciseHook runs dir's pre-receive the way git would, with no ref
// updates on stdin, which the policy accepts. It is what shows that git can
// run that file now: git skips a hook that is missing or that it cannot
// exec and applies the push unpoliced, so nothing short of running it
// proves it will be run.
func (s *RepoStore) exerciseHook(dir string) error {
	cmd := exec.Command(filepath.Join(dir, "pre-receive")) //nolint:gosec // the shim this store wrote
	cmd.Dir = dir                                          // the policy's quota walk measures the working directory
	cmd.Env = append(os.Environ(), "AGENTRY_HOOK_BIN="+s.hookBin)
	cmd.Stdin = strings.NewReader("")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// hooksReady returns the hooks directory for a receive-pack about to start,
// having just run its hook; a directory whose hook no longer runs (deleted
// by a temp cleaner, remounted noexec) is replaced by a fresh one, and when
// that fails too the push is refused. What remains is the moment between
// this check and git's own exec.
func (s *RepoStore) hooksReady() (string, error) {
	s.hooksMu.Lock()
	defer s.hooksMu.Unlock()
	if s.hooksDir != "" && s.exerciseHook(s.hooksDir) == nil {
		return s.hooksDir, nil
	}
	if err := s.prepareHooksLocked(); err != nil {
		return "", err
	}
	return s.hooksDir, nil
}

// Command starts a git service (upload-pack, receive-pack) for a client with
// the store's hooks directory as core.hooksPath. Given on the command line
// it outranks any repository or environment config. For receive-pack the
// directory's hook is run first (hooksReady), and the push is refused with
// an error when it will not run.
func (s *RepoStore) Command(ctx context.Context, service string, args ...string) (*exec.Cmd, error) {
	dir := s.hooksDir
	if service == "receive-pack" {
		var err error
		if dir, err = s.hooksReady(); err != nil {
			return nil, err
		}
	}
	argv := append([]string{"-c", "core.hooksPath=" + dir, service}, args...)
	return exec.CommandContext(ctx, s.gitBin, argv...), nil //nolint:gosec // fixed binary; service names and store paths
}

// Path returns the bare-repo directory for a repo id.
func (s *RepoStore) Path(repoID uuid.UUID) string {
	id := repoID.String()
	return filepath.Join(s.dataDir, id[:2], id+".git")
}

// InitBare creates and configures a bare repository (§6.2): default branch,
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
		{"uploadpack.allowFilter", "true"}, // partial clone (§6.1)
		{"core.commitGraph", "true"},       // §6.2 mitigation
	} {
		if err := run("-C", dir, "config", kv[0], kv[1]); err != nil {
			return err
		}
	}
	// The repository's own copy of the shim, for a git started outside
	// Command; git served through Command runs the hooks directory's
	// instead, and never this one.
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
// authority on what changed (§6.3).
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
