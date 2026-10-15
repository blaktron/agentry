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

// A fork's repository: the forked release's commit and its history copied
// from the origin, objects included, and nothing else of it, then one
// commit renaming the manifest, with the fork's branch and release tag on
// it. The release's history is the fork's past, and removing the origin
// afterwards leaves the fork whole.

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

// originWithHistory makes a bare origin with two commits on main and a
// v1.0.0 tag on the second, and work past the release that no fork may
// take: a third commit on main, a v1.1.0 tag on a commit of its own and an
// experiment branch, each with a file nothing else holds. unreviewed maps
// each of those commits and files, by name, to its id.
func originWithHistory(t *testing.T, repos *gitsrv.RepoStore) (id uuid.UUID, first, second string, unreviewed map[string]string) {
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
	// Work no review has passed, each commit with a file of its own.
	unreviewed = make(map[string]string)
	pending := func(file, body string) {
		write(file, body)
		histGit(t, work, "add", file)
		histGit(t, work, "commit", "-qm", file)
		unreviewed["commit "+file] = histGit(t, work, "rev-parse", "HEAD")
		unreviewed["file "+file] = histGit(t, work, "rev-parse", "HEAD:"+file)
	}
	pending("LATER.md", "main moved on\n")
	histGit(t, work, "checkout", "-q", "-b", "candidate")
	pending("CANDIDATE.md", "awaiting review\n")
	histGit(t, work, "tag", "-a", "-m", "candidate", "v1.1.0")
	unreviewed["tag v1.1.0"] = histGit(t, work, "rev-parse", "v1.1.0")
	histGit(t, work, "checkout", "-q", "-b", "experiment", first)
	pending("EXPERIMENT.md", "a branch\n")
	histGit(t, work, "checkout", "-q", "main")
	histGit(t, work, "branch", "-D", "candidate")
	// Fetched into the bare origin rather than pushed: a fetch runs no
	// receive hook, and the policy a push meets is not what this test is
	// about.
	histGit(t, repos.Path(id), "fetch", "-q", work, "+refs/heads/*:refs/heads/*", "+refs/tags/*:refs/tags/*")
	return id, first, second, unreviewed
}

func TestForkCopiesOnlyTheReleasesHistoryAndWritesOneRenamingCommit(t *testing.T) {
	repos := forkStore(t)
	ctx := context.Background()
	origin, first, second, unreviewed := originWithHistory(t, repos)
	fork := uuid.New()
	if err := repos.CopyHistory(ctx, origin, fork, "main", second); err != nil {
		t.Fatal(err)
	}
	refs, err := repos.RefsAt(ctx, fork, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 1 || refs["refs/heads/main"] != second {
		t.Fatalf("refs = %v, want main at the release %s and nothing else", refs, second)
	}
	// Nothing past the release came with it: no branch, no tag, and none
	// of their objects, which a client naming them by id would be served.
	dir := repos.Path(fork)
	for what, id := range unreviewed {
		if objectIn(dir, id) {
			t.Errorf("the fork holds the %s (%s), which only the origin's unreviewed work reaches", what, id)
		}
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
	if err := repos.CopyHistory(ctx, uuid.New(), fork, "main", ""); err != nil {
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
	if err := repos.CopyHistory(ctx, uuid.New(), fork, "main", ""); err != nil {
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
// work tree: a `.git` file pointing at another
// repository on the host, or a `.git` directory in any case, is refused
// rather than recorded as a gitlink, and a .gitattributes among the files
// changes no byte of what is committed.
func TestForkFromAnArchiveNeverLetsGitReadItAsAWorkTree(t *testing.T) {
	repos := forkStore(t)
	ctx := context.Background()
	other, _, _, _ := originWithHistory(t, repos)
	for name, files := range map[string]map[string]string{
		"a .git file naming another repository": {"agent.yaml": "x\n", "sub/.git": "gitdir: " + repos.Path(other) + "\n"},
		"a .GIT directory":                      {"agent.yaml": "x\n", "sub/.GIT/config": "[core]\n\thooksPath = /tmp\n"},
	} {
		fork := uuid.New()
		if err := repos.CopyHistory(ctx, uuid.New(), fork, "main", ""); err != nil {
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
	if err := repos.CopyHistory(ctx, uuid.New(), fork, "main", ""); err != nil {
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

// objectIn reports whether the bare repository at dir holds the object id.
func objectIn(dir, id string) bool {
	cmd := exec.Command("git", "-C", dir, "cat-file", "-e", id)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1")
	return cmd.Run() == nil
}

// A commit no tag of the origin points at is not copied: only a tag is
// what a reader with no role may clone, so the fork is left empty and its
// commit is made from the release's archive instead.
func TestForkCopiesNothingNoTagPointsAt(t *testing.T) {
	repos := forkStore(t)
	ctx := context.Background()
	origin, first, _, unreviewed := originWithHistory(t, repos)
	for name, commit := range map[string]string{"an untagged commit": first, "a branch tip": unreviewed["commit EXPERIMENT.md"]} {
		t.Run(name, func(t *testing.T) {
			fork := uuid.New()
			if err := repos.CopyHistory(ctx, origin, fork, "main", commit); err != nil {
				t.Fatal(err)
			}
			refs, err := repos.RefsAt(ctx, fork, nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(refs) != 0 || objectIn(repos.Path(fork), commit) {
				t.Fatalf("the fork took %s, which no tag names: refs %v", commit, refs)
			}
		})
	}
	if err := repos.CopyHistory(ctx, origin, uuid.New(), "main", "main"); err == nil {
		t.Fatal("CopyHistory took a ref name for a commit")
	}
}

// A tag moved after it was chosen brings history past the commit it was
// chosen for: the copy is refused and leaves no repository behind.
func TestForkRefusesATagMovedWhileItWasCopied(t *testing.T) {
	repos := forkStore(t)
	ctx := context.Background()
	origin, first, _, _ := originWithHistory(t, repos)
	fork := uuid.New()
	if err := repos.CopyHistoryVia(ctx, origin, fork, "main", first, "refs/tags/v1.0.0"); err == nil {
		t.Fatal("the copy took v1.0.0, which points past the commit it was chosen for")
	}
	if _, err := os.Stat(repos.Path(fork)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the refused copy left its repository behind: %v", err)
	}
}
