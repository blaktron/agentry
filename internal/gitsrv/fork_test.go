package gitsrv_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/gitsrv"
	"github.com/blaktron/agentry/internal/registry"
)

// A fork's repository (agentry#943): every branch and tag of the origin
// copied, objects included, then one commit renaming the manifest, with
// the fork's branch and release tag on it. The origin's own history is the
// fork's past, and removing the origin afterwards leaves the fork whole.

func forkStore(t *testing.T) *gitsrv.RepoStore {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	repos, err := gitsrv.NewRepoStore(config.Config{Git: config.Git{DataDir: t.TempDir()}})
	if err != nil {
		t.Fatal(err)
	}
	return repos
}

// originWithHistory makes a bare origin with two commits on main, a v1.0.0
// tag on the second and an extra branch, pushed from a work tree.
func originWithHistory(t *testing.T, repos *gitsrv.RepoStore) (id uuid.UUID, first, second string) {
	t.Helper()
	ctx := context.Background()
	id = uuid.New()
	if err := repos.InitBare(ctx, id, "main"); err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	histGit(t, work, "init", "-q", "-b", "main")
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(work, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("agent.yaml", "schemaVersion: \"2\"\nnamespace: alice\nname: summarize\nversion: 1.0.0\n")
	write("SKILL.md", "first\n")
	histGit(t, work, "add", ".")
	histGit(t, work, "commit", "-q", "-m", "first")
	first = histGit(t, work, "rev-parse", "HEAD")
	write("SKILL.md", "second\n")
	if err := os.WriteFile(filepath.Join(work, "run.sh"), []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil { //nolint:gosec // an executable the fork must keep executable
		t.Fatal(err)
	}
	histGit(t, work, "add", ".")
	histGit(t, work, "commit", "-qm", "second")
	second = histGit(t, work, "rev-parse", "HEAD")
	histGit(t, work, "tag", "v1.0.0")
	histGit(t, work, "branch", "experiment", first)
	// Fetched into the bare origin rather than pushed: a fetch runs no
	// receive hook, and the policy a push meets is not what this test is
	// about.
	histGit(t, repos.Path(id), "fetch", "-q", work, "+refs/heads/*:refs/heads/*", "+refs/tags/*:refs/tags/*")
	return id, first, second
}

func TestForkCopiesEveryRefAndWritesOneRenamingCommit(t *testing.T) {
	repos := forkStore(t)
	ctx := context.Background()
	origin, first, second := originWithHistory(t, repos)
	fork := uuid.New()
	if err := repos.CopyRepository(ctx, origin, fork, "main"); err != nil {
		t.Fatal(err)
	}
	refs, err := repos.RefsAt(ctx, fork, nil)
	if err != nil {
		t.Fatal(err)
	}
	for ref, want := range map[string]string{"refs/heads/main": second, "refs/heads/experiment": first} {
		if refs[ref] != want {
			t.Errorf("%s = %q, want the origin's %s", ref, refs[ref], want)
		}
	}
	if refs["refs/tags/v1.0.0"] == "" {
		t.Errorf("the origin's tag did not come over: %v", refs)
	}

	has, err := repos.HasCommit(ctx, fork, second)
	if err != nil || !has {
		t.Fatalf("HasCommit(%s) = %v, %v", second, has, err)
	}
	raw, err := repos.ReadFileAt(ctx, fork, second, "agent.yaml")
	if err != nil || !strings.Contains(string(raw), "namespace: alice") {
		t.Fatalf("ReadFileAt = %q, %v", raw, err)
	}
	renamed := []byte("schemaVersion: \"2\"\nnamespace: bob\nname: summarize\nversion: 1.0.0\n")
	commit, err := repos.CommitFork(ctx, fork, registry.ForkCommit{
		BaseCommit: second, Parent: second, ManifestPath: "agent.yaml", Manifest: renamed,
		Message: "Fork of alice/summarize@1.0.0\n", Refs: []string{"refs/heads/main", "refs/tags/v1.0.0"},
		AuthorName: "bob", AuthorEmail: "bob@users.noreply.agentry", When: time.Unix(1_700_000_000, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	dir := repos.Path(fork)
	if got := histGit(t, dir, "rev-parse", "refs/heads/main", "refs/tags/v1.0.0"); got != commit+"\n"+commit {
		t.Fatalf("main and v1.0.0 = %q, want both %s", got, commit)
	}
	// History back to the origin: the fork's log reaches the origin's
	// first commit.
	if log := histGit(t, dir, "log", "--format=%H", "main"); !strings.Contains(log, first) || !strings.Contains(log, second) {
		t.Fatalf("the fork's log does not reach the origin's commits:\n%s", log)
	}
	if got := histGit(t, dir, "show", commit+":agent.yaml"); !strings.Contains(got, "namespace: bob") {
		t.Fatalf("the manifest was not renamed: %s", got)
	}
	// The rest of the tree is the origin's, modes included.
	if got := histGit(t, dir, "show", commit+":SKILL.md"); got != "second" {
		t.Fatalf("SKILL.md = %q", got)
	}
	if mode := histGit(t, dir, "ls-tree", commit, "run.sh"); !strings.HasPrefix(mode, "100755") {
		t.Fatalf("run.sh lost its mode: %s", mode)
	}
	if author := histGit(t, dir, "log", "-1", "--format=%an <%ae> / %cn", commit); author != "bob <bob@users.noreply.agentry> / Agentry" {
		t.Fatalf("author = %q", author)
	}

	// Copied, not shared: with the origin gone, the fork still has every
	// object it needs.
	if err := repos.RemoveRepository(origin); err != nil {
		t.Fatal(err)
	}
	histGit(t, dir, "fsck", "--strict", "--no-dangling")
	if _, err := os.Stat(filepath.Join(dir, "objects", "info", "alternates")); err == nil {
		t.Fatal("the fork borrows the origin's objects through alternates")
	}
}

func TestForkFromAnArchiveAndAnOriginNeverPushed(t *testing.T) {
	repos := forkStore(t)
	ctx := context.Background()
	fork := uuid.New()
	// An origin published by upload has no repository on disk.
	if err := repos.CopyRepository(ctx, uuid.New(), fork, "main"); err != nil {
		t.Fatal(err)
	}
	tree := t.TempDir()
	for name, body := range map[string]string{"agent.yaml": "namespace: alice\n", "SKILL.md": "hi\n", ".gitignore": "SKILL.md\n"} {
		if err := os.WriteFile(filepath.Join(tree, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	commit, err := repos.CommitFork(ctx, fork, registry.ForkCommit{
		Dir: tree, ManifestPath: "agent.yaml", Manifest: []byte("namespace: bob\n"),
		Message: "Fork\n", Refs: []string{"refs/heads/main", "refs/tags/v1.0.0"},
		AuthorName: "bob", AuthorEmail: "bob@users.noreply.agentry", When: time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	dir := repos.Path(fork)
	// A root commit, with the archive's files: a .gitignore among them
	// hides nothing.
	if parents := histGit(t, dir, "log", "-1", "--format=%P", commit); parents != "" {
		t.Fatalf("parents = %q, want a root commit", parents)
	}
	if files := histGit(t, dir, "ls-tree", "--name-only", commit); files != ".gitignore\nSKILL.md\nagent.yaml" {
		t.Fatalf("files = %q", files)
	}
	if got := histGit(t, dir, "show", commit+":agent.yaml"); got != "namespace: bob" {
		t.Fatalf("agent.yaml = %q", got)
	}
}

func TestForkRefusesWhatIsNotAnObjectOrARef(t *testing.T) {
	repos := forkStore(t)
	ctx := context.Background()
	fork := uuid.New()
	if err := repos.CopyRepository(ctx, uuid.New(), fork, "main"); err != nil {
		t.Fatal(err)
	}
	for _, c := range []registry.ForkCommit{
		{BaseCommit: "--output=/tmp/x", ManifestPath: "agent.yaml"},
		{BaseCommit: "HEAD~1", ManifestPath: "agent.yaml"},
		{Dir: t.TempDir(), Parent: "main", ManifestPath: "agent.yaml"},
		{Dir: t.TempDir(), ManifestPath: "../agent.yaml"},
		{Dir: t.TempDir(), ManifestPath: "agent.yaml", Refs: []string{"refs/heads/../x"}},
		{Dir: t.TempDir(), ManifestPath: "agent.yaml", Refs: []string{"-d"}},
	} {
		if _, err := repos.CommitFork(ctx, fork, c); err == nil {
			t.Errorf("%+v: committed", c)
		}
	}
	if ok, _ := repos.HasCommit(ctx, fork, "--all"); ok {
		t.Error("HasCommit took an option for a commit")
	}
	if _, err := repos.ReadFileAt(ctx, fork, strings.Repeat("a", 40), "../etc/passwd"); err == nil {
		t.Error("ReadFileAt read outside the tree")
	}
}

// An uploaded release's files are hashed by path, never added through a
// work tree (agentry#943's review): a `.git` file pointing at another
// repository on the host, or a `.git` directory in any case, is refused
// rather than recorded as a gitlink, and a .gitattributes among the files
// changes no byte of what is committed.
func TestForkFromAnArchiveNeverLetsGitReadItAsAWorkTree(t *testing.T) {
	repos := forkStore(t)
	ctx := context.Background()
	other, _, _ := originWithHistory(t, repos)
	for name, files := range map[string]map[string]string{
		"a .git file naming another repository": {"agent.yaml": "x\n", "sub/.git": "gitdir: " + repos.Path(other) + "\n"},
		"a .GIT directory":                      {"agent.yaml": "x\n", "sub/.GIT/config": "[core]\n\thooksPath = /tmp\n"},
	} {
		fork := uuid.New()
		if err := repos.CopyRepository(ctx, uuid.New(), fork, "main"); err != nil {
			t.Fatal(err)
		}
		tree := t.TempDir()
		for rel, body := range files {
			p := filepath.Join(tree, filepath.FromSlash(rel))
			if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		_, err := repos.CommitFork(ctx, fork, registry.ForkCommit{Dir: tree, ManifestPath: "agent.yaml", Manifest: []byte("y\n"), Message: "m\n", Refs: []string{"refs/heads/main"}, AuthorName: "b", AuthorEmail: "b@x", When: time.Now()})
		if !errors.Is(err, registry.ErrForkTree) {
			t.Errorf("%s: err = %v, want ErrForkTree", name, err)
		}
	}

	fork := uuid.New()
	if err := repos.CopyRepository(ctx, uuid.New(), fork, "main"); err != nil {
		t.Fatal(err)
	}
	tree := t.TempDir()
	crlf := "line one\r\nline two\r\n"
	for rel, body := range map[string]string{".gitattributes": "* text=auto eol=lf\n*.md filter=evil\n", "notes.md": crlf, "agent.yaml": "x\n"} {
		if err := os.WriteFile(filepath.Join(tree, rel), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	commit, err := repos.CommitFork(ctx, fork, registry.ForkCommit{Dir: tree, ManifestPath: "agent.yaml", Manifest: []byte("y\n"), Message: "m\n", Refs: []string{"refs/heads/main"}, AuthorName: "b", AuthorEmail: "b@x", When: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("git", "-C", repos.Path(fork), "cat-file", "blob", commit+":notes.md")
	got, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != crlf {
		t.Fatalf("notes.md was committed as %q, want the release's bytes %q", got, crlf)
	}
}

// Keep sets a ref before the fork's refs move, so the origin's later work
// stays in the fork when its commit continues an older one.
func TestForkKeepsTheOriginsLaterWork(t *testing.T) {
	repos := forkStore(t)
	ctx := context.Background()
	origin, first, second := originWithHistory(t, repos)
	fork := uuid.New()
	if err := repos.CopyRepository(ctx, origin, fork, "main"); err != nil {
		t.Fatal(err)
	}
	// Fork from the first commit while main is at the second.
	commit, err := repos.CommitFork(ctx, fork, registry.ForkCommit{
		BaseCommit: first, Parent: first, ManifestPath: "agent.yaml", Manifest: []byte("namespace: bob\n"),
		Message: "Fork\n", Refs: []string{"refs/heads/main"}, Keep: map[string]string{"refs/heads/origin-main": second},
		AuthorName: "bob", AuthorEmail: "b@x", When: time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	refs, err := repos.RefsAt(ctx, fork, nil)
	if err != nil {
		t.Fatal(err)
	}
	if refs["refs/heads/main"] != commit || refs["refs/heads/origin-main"] != second {
		t.Fatalf("refs = %v, want main at the fork's commit and origin-main at %s", refs, second)
	}
	if _, err := repos.CommitFork(ctx, fork, registry.ForkCommit{BaseCommit: first, ManifestPath: "agent.yaml", Keep: map[string]string{"refs/heads/x": "main"}}); err == nil {
		t.Fatal("Keep took a ref name for a commit")
	}
}
