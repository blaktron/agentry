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

	"github.com/PLACEHOLDER_ORG/agentry/internal/config"
)

// RepoStore manages bare repositories under cfg.Git.DataDir:
// {dataDir}/{uuid[0:2]}/{uuid}.git (§6.2).
type RepoStore struct {
	dataDir string
	gitBin  string
	hookBin string
	limits  config.Limits
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
	hookBin, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("gitsrv: resolve executable for hooks: %w", err)
	}
	if err := os.MkdirAll(cfg.Git.DataDir, 0o750); err != nil {
		return nil, fmt.Errorf("gitsrv: data dir: %w", err)
	}
	return &RepoStore{
		dataDir: cfg.Git.DataDir,
		gitBin:  gitBin,
		hookBin: hookBin,
		limits:  cfg.Limits,
	}, nil
}

// Path returns the bare-repo directory for a repo id.
func (s *RepoStore) Path(repoID uuid.UUID) string {
	id := repoID.String()
	return filepath.Join(s.dataDir, id[:2], id+".git")
}

// GitBin exposes the git binary path (handlers spawn processes).
func (s *RepoStore) GitBin() string { return s.gitBin }

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
	// Policy hooks exec the agentryd binary (env carries request context;
	// see http.go). AGENTRY_HOOK_BIN is set by the spawning server so the
	// hook survives binary relocation; the recorded path is the fallback.
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
