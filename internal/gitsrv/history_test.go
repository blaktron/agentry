package gitsrv_test

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/gitsrv"
)

func histGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.test",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.test",
		"GIT_CONFIG_NOSYSTEM=1", "HOME="+dir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func TestHistoryPatchStreamsAddedLines(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	cfg := config.Config{Git: config.Git{DataDir: t.TempDir()}}
	repos, err := gitsrv.NewRepoStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	id := uuid.New()
	ctx := context.Background()
	if err := repos.InitBare(ctx, id, "main"); err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	histGit(t, work, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(work, "config.env"), []byte("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	histGit(t, work, "add", ".")
	histGit(t, work, "commit", "-q", "-m", "leak")
	leak := histGit(t, work, "rev-parse", "HEAD")
	if err := os.WriteFile(filepath.Join(work, "config.env"), []byte("AWS_ACCESS_KEY_ID=rotated\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	histGit(t, work, "commit", "-qam", "fix")
	head := histGit(t, work, "rev-parse", "HEAD")
	// A push straight into the bare repository runs its own shim, which
	// (like the server's) needs the hook binary named: here, this test
	// binary, whose TestMain is the hook.
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGENTRY_HOOK_BIN", exe)
	histGit(t, work, "push", "-q", repos.Path(id), "main")

	stream, err := repos.HistoryPatch(ctx, id, head)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(stream)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	out := string(raw)
	if !strings.Contains(out, "\x01"+leak) || !strings.Contains(out, "\x01"+head) {
		t.Fatalf("commit markers missing:\n%s", out)
	}
	if !strings.Contains(out, "+AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE") || !strings.Contains(out, "-AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("patch lines missing:\n%s", out)
	}
	if _, err := repos.HistoryPatch(ctx, id, "--all"); err == nil {
		t.Fatal("option-looking commit must be refused")
	}
	bad, err := repos.HistoryPatch(ctx, id, "0000000000000000000000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(bad)
	if err := bad.Close(); err == nil {
		t.Fatal("unknown commit must surface git's failure on Close")
	}
}
