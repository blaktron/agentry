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

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/config"
)

// RepoStore manages bare repositories under cfg.Git.DataDir:
// {dataDir}/{uuid[0:2]}/{uuid}.git (§6.2).
type RepoStore struct {
	dataDir  string
	gitBin   string
	hookBin  string
	hooksDir string // where git runs the policy hook from (installHooks)
	limits   config.Limits
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
	hooksDir, err := installHooks(cfg.Git.HooksDir)
	if err != nil {
		return nil, err
	}
	return &RepoStore{
		dataDir:  cfg.Git.DataDir,
		gitBin:   gitBin,
		hookBin:  hookBin,
		hooksDir: hooksDir,
		limits:   cfg.Limits,
	}, nil
}

// installHooks writes the pre-receive shim into a fresh directory under base
// (the system temp directory when empty) and proves a hook can run from it.
// Git is pointed there (Command) rather than at each bare repository's
// hooks/, because the repository volume may be one the kernel will not exec
// from: on Vultr's virtiofs file system every push failed with "cannot exec
// 'hooks/pre-receive': Bad address" (agentry#495). The directory gets a
// random name and mode 0700, so no other local user can have planted a hook
// in a shared /tmp first. A directory that cannot run a hook stops the git
// role here, at startup, rather than refusing every push later.
func installHooks(base string) (string, error) {
	if base == "" {
		base = os.TempDir()
	}
	base, err := filepath.Abs(base)
	if err != nil {
		return "", fmt.Errorf("gitsrv: hooks directory: %w", err)
	}
	dir, err := os.MkdirTemp(base, "agentry-git-hooks-")
	if err != nil {
		return "", fmt.Errorf("gitsrv: hooks directory under %s: %w", base, err)
	}
	// No fallback path: a git started without AGENTRY_HOOK_BIN (gitEnv sets
	// it) is refused rather than policed by a guess.
	shim := "#!/bin/sh\nexec \"${AGENTRY_HOOK_BIN:?AGENTRY_HOOK_BIN is not set}\" hook pre-receive \"$@\"\n"
	if err := os.WriteFile(filepath.Join(dir, "pre-receive"), []byte(shim), 0o700); err != nil { //nolint:gosec // hooks must be executable
		return "", fmt.Errorf("gitsrv: hooks directory: %w", err)
	}
	probe := filepath.Join(dir, "probe")
	if err := os.WriteFile(probe, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil { //nolint:gosec // the probe must be executable
		return "", fmt.Errorf("gitsrv: hooks directory: %w", err)
	}
	out, err := exec.Command(probe).CombinedOutput() //nolint:gosec // a script this function just wrote
	_ = os.Remove(probe)
	if err != nil {
		return "", fmt.Errorf("gitsrv: git hooks cannot run from %s (%v %s): set AGENTRY_GIT_HOOKS_DIR to a directory on a file system that allows exec", dir, err, strings.TrimSpace(string(out)))
	}
	return dir, nil
}

// Command is git run with the store's hooks directory as core.hooksPath.
// Given on the command line it outranks any repository's own config, so
// every receive-pack started through here runs the policy hook. Every git
// that serves a client is started through here.
func (s *RepoStore) Command(ctx context.Context, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, s.gitBin, append([]string{"-c", "core.hooksPath=" + s.hooksDir}, args...)...) //nolint:gosec // fixed binary; callers pass service names and store paths
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
	// The repository's own copy of the shim. Git served through Command
	// runs the hooks directory's instead (installHooks); this one is what a
	// git started any other way meets, so such a push is still policed (or,
	// on a volume that cannot exec, refused), never let through. The env
	// (see http.go) carries the request context; AGENTRY_HOOK_BIN is set by
	// the spawning server so the hook survives binary relocation, and the
	// recorded path is the fallback.
	hookDir := filepath.Join(dir, "hooks")
	hook := fmt.Sprintf("#!/bin/sh\nexec \"${AGENTRY_HOOK_BIN:-%s}\" hook pre-receive \"$@\"\n", s.hookBin)
	if err := os.WriteFile(filepath.Join(hookDir, "pre-receive"), []byte(hook), 0o755); err != nil { //nolint:gosec // hooks must be executable
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
