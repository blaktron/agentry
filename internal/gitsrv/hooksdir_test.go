package gitsrv

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestInstallHooks: the hooks directory is private, holds an executable
// pre-receive shim that defers to AGENTRY_HOOK_BIN, and keeps nothing else
// (agentry#495).
func TestInstallHooks(t *testing.T) {
	dir, err := installHooks(t.TempDir())
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
		t.Fatalf("hooks directory holds %v, want only pre-receive (the probe is removed)", entries)
	}
	shim := filepath.Join(dir, "pre-receive")
	st, err := os.Stat(shim)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm()&0o100 == 0 {
		t.Fatalf("pre-receive mode %v is not executable", st.Mode().Perm())
	}
	body, err := os.ReadFile(shim) //nolint:gosec // test-created path
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "${AGENTRY_HOOK_BIN:?") || !strings.Contains(string(body), "hook pre-receive") {
		t.Fatalf("the shim must exec AGENTRY_HOOK_BIN and refuse without it:\n%s", body)
	}

	// Two stores on one base never share (or overwrite) a directory.
	again, err := installHooks(filepath.Dir(dir))
	if err != nil {
		t.Fatal(err)
	}
	if again == dir {
		t.Fatalf("a second store reused %s", dir)
	}
}

// TestInstallHooksRefusesAnUnusableBase: a base that cannot hold the
// directory stops the store at startup instead of every push later.
func TestInstallHooksRefusesAnUnusableBase(t *testing.T) {
	file := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := installHooks(file); err == nil {
		t.Fatal("installHooks accepted a base that is a file")
	}
}

// TestCommandSetsHooksPath: every git the store starts is given the hooks
// directory on its command line, ahead of the service and its arguments.
func TestCommandSetsHooksPath(t *testing.T) {
	s := &RepoStore{gitBin: "/usr/bin/git", hooksDir: "/tmp/agentry-git-hooks-x"}
	cmd := s.Command(context.Background(), "receive-pack", "/data/git/ab/ab.git")
	want := []string{"/usr/bin/git", "-c", "core.hooksPath=/tmp/agentry-git-hooks-x", "receive-pack", "/data/git/ab/ab.git"}
	if !slices.Equal(cmd.Args, want) {
		t.Fatalf("args %q, want %q", cmd.Args, want)
	}
}
