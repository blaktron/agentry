package gitsrv

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"

	"github.com/blaktron/agentry/internal/config"
)

// newHooksStore is a store whose hooks directory lives under base.
func newHooksStore(t *testing.T, base string) *RepoStore {
	t.Helper()
	s, err := NewRepoStore(config.Config{Git: config.Git{DataDir: t.TempDir(), HooksDir: base}})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestPrepareHooks: the hooks directory is private and holds exactly the
// shim, which refuses to run without AGENTRY_HOOK_BIN (agentry#495).
func TestPrepareHooks(t *testing.T) {
	s := newHooksStore(t, t.TempDir())
	if err := s.PrepareHooks(); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(s.hooksDir)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("hooks directory mode %v, want 0700", fi.Mode().Perm())
	}
	entries, err := os.ReadDir(s.hooksDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "pre-receive" {
		t.Fatalf("hooks directory holds %v, want only pre-receive", entries)
	}
	shim := filepath.Join(s.hooksDir, "pre-receive")
	body, err := os.ReadFile(shim) //nolint:gosec // test-created path
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != preReceiveShim {
		t.Fatalf("shim is\n%s\nwant\n%s", body, preReceiveShim)
	}
	cmd := exec.Command(shim) //nolint:gosec // test-created path
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	if err := cmd.Run(); err == nil {
		t.Fatal("the shim ran without AGENTRY_HOOK_BIN; it must refuse")
	}
}

// TestHooksReadyReplacesAHookThatNoLongerRuns: git skips a hook that is
// missing or not executable and applies the push unpoliced, so a lost hook
// is replaced before the next receive-pack starts.
func TestHooksReadyReplacesAHookThatNoLongerRuns(t *testing.T) {
	for name, breakIt := range map[string]func(dir string) error{
		"deleted":        func(dir string) error { return os.Remove(filepath.Join(dir, "pre-receive")) },
		"not executable": func(dir string) error { return os.Chmod(filepath.Join(dir, "pre-receive"), 0o600) },
		"directory gone": os.RemoveAll,
	} {
		t.Run(name, func(t *testing.T) {
			s := newHooksStore(t, t.TempDir())
			if err := s.PrepareHooks(); err != nil {
				t.Fatal(err)
			}
			old := s.hooksDir
			if err := breakIt(old); err != nil {
				t.Fatal(err)
			}
			dir, err := s.hooksReady()
			if err != nil {
				t.Fatal(err)
			}
			if dir == old {
				t.Fatalf("kept %s, whose hook no longer runs", old)
			}
			if err := s.exerciseHook(dir); err != nil {
				t.Fatalf("the replacement's hook does not run: %v", err)
			}
		})
	}
}

// TestReceivePackRefusedWhenNoHookCanRun: when the hook cannot be made to
// run anywhere, receive-pack is not started at all.
func TestReceivePackRefusedWhenNoHookCanRun(t *testing.T) {
	base := t.TempDir()
	s := newHooksStore(t, base)
	if err := s.PrepareHooks(); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(base); err != nil {
		t.Fatal(err)
	}
	if cmd, err := s.Command(context.Background(), "receive-pack", "/data/git/ab/ab.git"); err == nil {
		t.Fatalf("receive-pack started with no runnable hook: %v", cmd.Args)
	}
}

// TestPrepareHooksRefusesAnUnsafeBase: a base every user can write to
// without the sticky bit could have ours swapped out; a file cannot hold
// the directory at all.
func TestPrepareHooksRefusesAnUnsafeBase(t *testing.T) {
	open := t.TempDir()
	if err := os.Chmod(open, 0o777); err != nil { //nolint:gosec // the unsafe base under test
		t.Fatal(err)
	}
	if err := newHooksStore(t, open).PrepareHooks(); err == nil {
		t.Fatal("accepted a world-writable, non-sticky base")
	}
	file := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := newHooksStore(t, file).PrepareHooks(); err == nil {
		t.Fatal("accepted a base that is a file")
	}
}

// TestCommandSetsHooksPath: git is given the hooks directory on its command
// line, ahead of the service and its arguments.
func TestCommandSetsHooksPath(t *testing.T) {
	s := &RepoStore{gitBin: "/usr/bin/git", hooksDir: "/tmp/agentry-git-hooks-x"}
	cmd, err := s.Command(context.Background(), "upload-pack", "/data/git/ab/ab.git")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/usr/bin/git", "-c", "core.hooksPath=/tmp/agentry-git-hooks-x", "upload-pack", "/data/git/ab/ab.git"}
	if !slices.Equal(cmd.Args, want) {
		t.Fatalf("args %q, want %q", cmd.Args, want)
	}
}
