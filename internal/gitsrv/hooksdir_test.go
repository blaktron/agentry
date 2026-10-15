package gitsrv

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/blaktron/agentry/internal/config"
)

// newHooksStore is a store whose pushes make their hooks directories under
// base.
func newHooksStore(t *testing.T, base string) *RepoStore {
	t.Helper()
	s, err := NewRepoStore(config.Config{Git: config.Git{DataDir: t.TempDir(), HooksDir: base}})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestPushHooks: a push's hooks directory is private, holds exactly the
// shim, and is gone once the push is done; the shim refuses to run
// without AGENTRY_HOOK_BIN.
func TestPushHooks(t *testing.T) {
	base := t.TempDir()
	s := newHooksStore(t, base)
	dir, done, err := s.pushHooks()
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("hooks directory mode %v, want 0700", fi.Mode().Perm())
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "pre-receive" {
		t.Fatalf("hooks directory holds %v, want only pre-receive", entries)
	}
	shim := filepath.Join(dir, "pre-receive")
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
	done()
	if left, _ := os.ReadDir(base); len(left) != 0 {
		t.Fatalf("done left %v behind", left)
	}
}

// TestEachPushOwnsItsHooks: one push finishing (or its directory going)
// never takes the hook from another push still running.
func TestEachPushOwnsItsHooks(t *testing.T) {
	s := newHooksStore(t, t.TempDir())
	a, doneA, err := s.pushHooks()
	if err != nil {
		t.Fatal(err)
	}
	b, doneB, err := s.pushHooks()
	if err != nil {
		t.Fatal(err)
	}
	defer doneB()
	if a == b {
		t.Fatalf("two pushes share %s", a)
	}
	doneA()
	if err := s.exerciseHook(b); err != nil {
		t.Fatalf("the other push lost its hook: %v", err)
	}
}

// TestReceivePackRefusedWhenNoHookCanRun: when no hook can be made to run,
// receive-pack is not started at all; PrepareHooks, the git role's startup
// check, says so too. A base that is a file cannot hold the directory.
func TestReceivePackRefusedWhenNoHookCanRun(t *testing.T) {
	gone := filepath.Join(t.TempDir(), "gone")
	s := newHooksStore(t, gone)
	if cmd, _, err := s.Command(context.Background(), "receive-pack", "/data/git/ab/ab.git"); err == nil {
		t.Fatalf("receive-pack started with no runnable hook: %v", cmd.Args)
	}
	if err := s.PrepareHooks(); err == nil {
		t.Fatal("PrepareHooks passed with no runnable hook")
	}
	file := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := newHooksStore(t, file).PrepareHooks(); err == nil {
		t.Fatal("accepted a base that is a file")
	}
}

// TestPrepareHooksLeavesNothingBehind: the startup check makes, runs and
// removes one push's directory.
func TestPrepareHooksLeavesNothingBehind(t *testing.T) {
	base := t.TempDir()
	if err := newHooksStore(t, base).PrepareHooks(); err != nil {
		t.Fatal(err)
	}
	if left, _ := os.ReadDir(base); len(left) != 0 {
		t.Fatalf("PrepareHooks left %v behind", left)
	}
}

// TestCommandSetsHooksPath: a receive-pack gets its own hooks directory on
// git's command line; the ref advertisement and upload-pack, which run no
// hook, get none.
func TestCommandSetsHooksPath(t *testing.T) {
	base := t.TempDir()
	s := newHooksStore(t, base)
	ctx := context.Background()
	cmd, done, err := s.Command(ctx, "receive-pack", "--stateless-rpc", "/data/git/ab/ab.git")
	if err != nil {
		t.Fatal(err)
	}
	defer done()
	if len(cmd.Args) != 6 || cmd.Args[1] != "-c" || !strings.HasPrefix(cmd.Args[2], "core.hooksPath="+base+string(os.PathSeparator)) ||
		!slices.Equal(cmd.Args[3:], []string{"receive-pack", "--stateless-rpc", "/data/git/ab/ab.git"}) {
		t.Fatalf("receive-pack args %q", cmd.Args)
	}
	for _, args := range [][]string{
		{"upload-pack", "--stateless-rpc", "/data/git/ab/ab.git"},
		{"receive-pack", "--stateless-rpc", "--advertise-refs", "/data/git/ab/ab.git"},
	} {
		cmd, done, err := s.Command(ctx, args[0], args[1:]...)
		if err != nil {
			t.Fatal(err)
		}
		done()
		if !slices.Equal(cmd.Args[1:], args) {
			t.Fatalf("%s args %q, want %q", args[0], cmd.Args[1:], args)
		}
	}
}
