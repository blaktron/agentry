package gitsrv_test

import (
	"context"
	"fmt"
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

	// What is refused before git runs.
	for _, commit := range []string{"", " ", "\t\n", "-x", "--all", "--output=/x", " --all"} {
		if _, err := repos.HistoryPatch(ctx, id, commit); err == nil || !strings.Contains(err.Error(), "history: invalid commit") {
			t.Errorf("HistoryPatch(%q): %v, want 'history: invalid commit'", commit, err)
		}
	}
	// A revision git cannot find is git's own failure, said as git said it,
	// and the arguments end before anything after the revision.
	unknown, err := repos.HistoryPatch(ctx, id, "no-such-revision")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(unknown)
	if err := unknown.Close(); err == nil || !strings.Contains(err.Error(), "gitsrv: history: ") || !strings.Contains(err.Error(), "bad revision 'no-such-revision'") {
		t.Fatalf("unknown revision: %v, want git's own 'bad revision' text", err)
	}
	// A commit given with whitespace around it is the same commit.
	padded, err := repos.HistoryPatch(ctx, id, " "+head+"\n")
	if err != nil {
		t.Fatal(err)
	}
	paddedOut, err := io.ReadAll(padded)
	if err != nil || !strings.Contains(string(paddedOut), "\x01"+head) {
		t.Fatalf("padded commit: %q, %v", paddedOut, err)
	}
	if err := padded.Close(); err != nil {
		t.Fatalf("padded commit closed with %v", err)
	}

	// Later history: only the lines a commit added or changed are shown,
	// with no context around them, nothing for a deletion, a rename as the
	// file it now is, and nothing at all for a merge.
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(work, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var list strings.Builder
	for i := 1; i <= 9; i++ {
		fmt.Fprintf(&list, "line%d\n", i)
	}
	write("list.txt", list.String())
	histGit(t, work, "add", ".")
	histGit(t, work, "commit", "-qm", "list")
	write("list.txt", strings.Replace(list.String(), "line5\n", "line5-changed\n", 1))
	histGit(t, work, "commit", "-qam", "edit")
	write("gone.env", "DELETED-SECRET=1\n")
	histGit(t, work, "add", ".")
	histGit(t, work, "commit", "-qm", "add gone")
	histGit(t, work, "rm", "-q", "gone.env")
	histGit(t, work, "commit", "-qm", "remove gone")
	write("old-name.txt", "keep-1\nkeep-2\nkeep-3\nkeep-4\nkeep-5\nkeep-6\n")
	histGit(t, work, "add", ".")
	histGit(t, work, "commit", "-qm", "before rename")
	histGit(t, work, "mv", "old-name.txt", "new-name.txt")
	write("new-name.txt", "keep-1\nkeep-2\nkeep-3-edited\nkeep-4\nkeep-5\nkeep-6\n")
	histGit(t, work, "add", ".")
	histGit(t, work, "commit", "-qm", "rename")
	histGit(t, work, "checkout", "-q", "-b", "side")
	write("side.txt", "SIDE-ONLY\n")
	histGit(t, work, "add", ".")
	histGit(t, work, "commit", "-qm", "side")
	histGit(t, work, "checkout", "-q", "main")
	write("main.txt", "MAIN-ONLY\n")
	histGit(t, work, "add", ".")
	histGit(t, work, "commit", "-qm", "main work")
	histGit(t, work, "merge", "-q", "--no-ff", "-m", "merge side", "side")
	merge := histGit(t, work, "rev-parse", "HEAD")
	histGit(t, work, "push", "-q", repos.Path(id), "main")

	later, err := repos.HistoryPatch(ctx, id, merge)
	if err != nil {
		t.Fatal(err)
	}
	laterRaw, err := io.ReadAll(later)
	if err != nil {
		t.Fatal(err)
	}
	if err := later.Close(); err != nil {
		t.Fatal(err)
	}
	patch := string(laterRaw)
	if strings.Contains(patch, "\x01"+merge) {
		t.Errorf("the merge commit is in the stream")
	}
	if !strings.Contains(patch, "+line5-changed\n") || !strings.Contains(patch, "-line5\n") {
		t.Errorf("the edit's changed lines are missing:\n%s", patch)
	}
	for _, context := range []string{"\n line4\n", "\n line6\n", "\n keep-2\n"} {
		if strings.Contains(patch, context) {
			t.Errorf("a context line %q is in the stream", context)
		}
	}
	if !strings.Contains(patch, "+DELETED-SECRET=1\n") {
		t.Errorf("the commit that added gone.env is missing")
	}
	if strings.Contains(patch, "-DELETED-SECRET=1") {
		t.Errorf("the commit that deleted gone.env is in the stream")
	}
	if n := strings.Count(patch, "+keep-1\n"); n != 2 {
		t.Errorf("+keep-1 appears %d times, want 2 (the file when added, and again under its new name)", n)
	}
	for _, only := range []string{"+SIDE-ONLY\n", "+MAIN-ONLY\n"} {
		if !strings.Contains(patch, only) {
			t.Errorf("%q is missing: both sides of a merge are history", only)
		}
	}
}
