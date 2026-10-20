package gitsrv_test

// The repository store without a database: how a bare repository is laid
// out and configured, how its refs and tags are read, and the
// reviewed-only views a reader with no role is served from.

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/gitsrv"
)

func storeAt(t *testing.T, mod func(*config.Config)) (*gitsrv.RepoStore, string) {
	t.Helper()
	cfg := config.Config{Git: config.Git{DataDir: filepath.Join(t.TempDir(), "data", "git"), HooksDir: t.TempDir()}}
	if mod != nil {
		mod(&cfg)
	}
	s, err := gitsrv.NewRepoStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s, cfg.Git.DataDir
}

// gitStdin runs git in dir with stdin and returns its output.
func gitStdin(t *testing.T, dir, stdin string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Stdin = strings.NewReader(stdin)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func gitConfigValue(t *testing.T, dir, key string) string {
	t.Helper()
	out, err := gitRun(t, dir, "config", "--get", key)
	if err != nil {
		return "<unset: " + strings.TrimSpace(out) + ">"
	}
	return strings.TrimSpace(out)
}

// TestRepoStoreLayoutAndConfiguration: a repository lives at
// {data}/{first two of the id}/{id}.git, is made once, and is made with the
// settings every push depends on.
func TestRepoStoreLayoutAndConfiguration(t *testing.T) {
	s, data := storeAt(t, func(c *config.Config) { c.Limits.RepoQuotaBytes = 123456 })
	if fi, err := os.Stat(data); err != nil || fi.Mode().Perm()&0o007 != 0 {
		t.Fatalf("data directory: %v, %v; it must exist and be closed to others", fi, err)
	}
	id := uuid.MustParse("ab123456-0000-4000-8000-000000000001")
	if got, want := s.Path(id), filepath.Join(data, "ab", "ab123456-0000-4000-8000-000000000001.git"); got != want {
		t.Fatalf("Path = %s, want %s", got, want)
	}
	if err := s.InitBare(context.Background(), id, "trunk"); err != nil {
		t.Fatal(err)
	}
	dir := s.Path(id)
	if got := strings.TrimSpace(mustGit(t, dir, "symbolic-ref", "HEAD")); got != "refs/heads/trunk" {
		t.Errorf("HEAD = %s, want refs/heads/trunk", got)
	}
	for key, want := range map[string]string{
		"receive.denyDeleteCurrent": "true",
		"receive.maxInputSize":      "123456",
		"uploadpack.allowFilter":    "true",
		"core.commitGraph":          "true",
	} {
		if got := gitConfigValue(t, dir, key); got != want {
			t.Errorf("%s = %s, want %s", key, got, want)
		}
	}
	shim := filepath.Join(dir, "hooks", "pre-receive")
	body, err := os.ReadFile(shim) //nolint:gosec // test-created path
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(body), "#!/bin/sh\n") || !strings.Contains(string(body), "AGENTRY_HOOK_BIN") || !strings.Contains(string(body), "hook pre-receive") {
		t.Errorf("the repository's own hook is %q", body)
	}
	if fi, err := os.Stat(shim); err != nil || fi.Mode().Perm()&0o100 == 0 {
		t.Errorf("the repository's own hook is not executable: %v, %v", fi, err)
	}
	if err := s.InitBare(context.Background(), id, "trunk"); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("making the same repository twice: %v, want 'already exists'", err)
	}
}

// TestDiskUsageSumsFiles: the size of a repository is its files, not the
// directories that hold them.
func TestDiskUsageSumsFiles(t *testing.T) {
	s, _ := storeAt(t, nil)
	id := uuid.New()
	if err := s.InitBare(context.Background(), id, "main"); err != nil {
		t.Fatal(err)
	}
	before, err := s.DiskUsage(id)
	if err != nil || before <= 0 {
		t.Fatalf("DiskUsage = %d, %v", before, err)
	}
	extra := filepath.Join(s.Path(id), "extra", "deeper")
	if err := os.MkdirAll(extra, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(extra, "blob.bin"), make([]byte, 12345), 0o600); err != nil {
		t.Fatal(err)
	}
	after, err := s.DiskUsage(id)
	if err != nil || after-before != 12345 {
		t.Fatalf("DiskUsage grew by %d (%v), want exactly the 12345 bytes of the file", after-before, err)
	}
	if _, err := s.DiskUsage(uuid.New()); err == nil {
		t.Fatal("DiskUsage of a repository that is not there succeeded")
	}
}

// TestRefsAtReadsOnlyTheNamedPlainRefs: the object a ref is at, for the
// names asked for and no others; a name that is not a plain ref is not
// passed on as a pattern.
func TestRefsAtReadsOnlyTheNamedPlainRefs(t *testing.T) {
	repos := forkStore(t)
	origin, first, second, unreviewed := originWithHistory(t, repos)
	ctx := context.Background()

	got, err := repos.RefsAt(ctx, origin, []string{"refs/heads/main", "refs/tags/v1.0.0", "refs/heads/missing"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got["refs/tags/v1.0.0"] != second {
		t.Fatalf("RefsAt = %v, want main and v1.0.0 only (v1.0.0 at %s)", got, second)
	}
	if got["refs/heads/main"] != unreviewed["commit LATER.md"] {
		t.Errorf("main at %s, want %s", got["refs/heads/main"], unreviewed["commit LATER.md"])
	}
	_ = first
	for _, widened := range [][]string{
		{"refs/heads/main", "refs/heads/*"},
		{"refs/heads/main", "refs/heads/exp?riment"},
		{"refs/heads/main", "refs/heads/[a-z]xperiment"},
		{"refs/heads/main", "-d"},
		{"refs/heads/main", "main"},
		{"refs/heads/main", "refs/heads/main ~1"},
	} {
		got, err := repos.RefsAt(ctx, origin, widened)
		if err != nil {
			t.Fatalf("RefsAt(%q): %v", widened, err)
		}
		if len(got) != 1 || got["refs/heads/main"] == "" {
			t.Errorf("RefsAt(%q) = %v, want only refs/heads/main", widened, got)
		}
	}
	if _, err := repos.RefsAt(ctx, uuid.New(), []string{"refs/heads/main"}); err == nil {
		t.Fatal("RefsAt on a repository that is not there succeeded")
	}
}

// TestTagsListsCommitTagsOnly: each tag with its own object and the commit
// it peels to; a tag of anything else is left out; a repository never
// pushed to has none.
func TestTagsListsCommitTagsOnly(t *testing.T) {
	repos := forkStore(t)
	origin, _, second, unreviewed := originWithHistory(t, repos)
	ctx := context.Background()
	dir := repos.Path(origin)
	tree := strings.TrimSpace(mustGit(t, dir, "rev-parse", second+"^{tree}"))
	mustGit(t, dir, "update-ref", "refs/tags/of-a-tree", tree)
	blob := unreviewed["file LATER.md"]
	mustGit(t, dir, "update-ref", "refs/tags/of-a-blob", blob)
	annotatedTree := strings.TrimSpace(gitStdin(t, dir, "object "+tree+"\ntype tree\ntag treetag\ntagger t <t@example.test> 0 +0000\n\nm\n", "mktag"))
	mustGit(t, dir, "update-ref", "refs/tags/annotated-tree", annotatedTree)

	tags, err := repos.Tags(ctx, origin)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]gitsrv.Tag{
		"refs/tags/v1.0.0": {Object: second, Commit: second},
		"refs/tags/v1.1.0": {Object: unreviewed["tag v1.1.0"], Commit: unreviewed["commit CANDIDATE.md"]},
	}
	if len(tags) != len(want) {
		t.Fatalf("Tags = %v, want only the two commit tags", tags)
	}
	for ref, w := range want {
		if tags[ref] != w {
			t.Errorf("%s = %+v, want %+v", ref, tags[ref], w)
		}
	}
	none, err := repos.Tags(ctx, uuid.New())
	if err != nil || len(none) != 0 {
		t.Fatalf("Tags of a repository that was never made: %v, %v, want none and no error", none, err)
	}
}

// viewDir is where the store keeps the reviewed-only views of a repository.
func viewDir(data string, id uuid.UUID) string {
	return filepath.Join(data, "views", id.String()[:2])
}

func viewsOf(t *testing.T, data string, id uuid.UUID) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(viewDir(data, id), id.String()+"-*.git"))
	if err != nil {
		t.Fatal(err)
	}
	return matches
}

func ageView(t *testing.T, path string, age time.Duration) {
	t.Helper()
	when := time.Now().Add(-age)
	if err := os.Chtimes(path, when, when); err != nil {
		t.Fatal(err)
	}
}

// TestReviewedViewHoldsOnlyTheNamedTags: the repository a reader with no
// role is served holds the tags it was given and the objects they reach,
// HEAD detached at the head it was given, and is rebuilt only when the set
// changes.
func TestReviewedViewHoldsOnlyTheNamedTags(t *testing.T) {
	repos, data := storeAt(t, nil)
	origin, first, second, unreviewed := originWithHistory(t, repos)
	ctx := context.Background()
	tags := map[string]string{"refs/tags/v1.0.0": second}

	path, err := repos.ReviewedView(ctx, origin, tags, second)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(path) != viewDir(data, origin) || !strings.HasPrefix(filepath.Base(path), origin.String()+"-") || !strings.HasSuffix(path, ".git") {
		t.Fatalf("view at %s, want {data}/views/{shard}/{repo}-{hash}.git", path)
	}
	if got := strings.TrimSpace(mustGit(t, path, "for-each-ref", "--format=%(refname)")); got != "refs/tags/v1.0.0" {
		t.Errorf("view refs = %q, want only refs/tags/v1.0.0", got)
	}
	if got := strings.TrimSpace(mustGit(t, path, "rev-parse", "HEAD")); got != second {
		t.Errorf("view HEAD = %s, want %s", got, second)
	}
	if out, err := gitRun(t, path, "symbolic-ref", "-q", "HEAD"); err == nil {
		t.Errorf("view HEAD names a branch (%q); it must be detached", strings.TrimSpace(out))
	}
	if got := gitConfigValue(t, path, "uploadpack.allowFilter"); got != "true" {
		t.Errorf("view uploadpack.allowFilter = %s, want true", got)
	}
	for what, id := range unreviewed {
		if objectIn(path, id) {
			t.Errorf("the view holds the %s (%s)", what, id)
		}
	}
	if !objectIn(path, first) {
		t.Errorf("the view lacks the reviewed version's history (%s)", first)
	}
	if got := mustGit(t, path, "tag", "--list"); strings.TrimSpace(got) != "v1.0.0" {
		t.Errorf("view tags = %q", got)
	}

	// The same set is the same view; using it refreshes its time.
	ageView(t, path, 10*time.Minute)
	again, err := repos.ReviewedView(ctx, origin, tags, second)
	if err != nil || again != path {
		t.Fatalf("same set: %s, %v, want the same view %s", again, err, path)
	}
	if fi, _ := os.Stat(path); time.Since(fi.ModTime()) > time.Minute {
		t.Errorf("reusing the view did not refresh its use time (%v old)", time.Since(fi.ModTime()))
	}
	// A different head, or a different object for a tag, is another view.
	other, err := repos.ReviewedView(ctx, origin, tags, first)
	if err != nil || other == path {
		t.Fatalf("a different head: %s, %v, want a view of its own", other, err)
	}
	candidate := map[string]string{"refs/tags/v1.0.0": second, "refs/tags/v1.1.0": unreviewed["tag v1.1.0"]}
	third, err := repos.ReviewedView(ctx, origin, candidate, unreviewed["commit CANDIDATE.md"])
	if err != nil || third == path || third == other {
		t.Fatalf("a bigger set: %s, %v, want a view of its own", third, err)
	}
	swapped := map[string]string{"refs/tags/v1.0.0": first}
	if v, err := repos.ReviewedView(ctx, origin, swapped, second); err != nil || v == path {
		t.Fatalf("the same tag name at another object: %s, %v, want a view of its own", v, err)
	}
}

// TestReviewedViewRefusesWhatIsNotATagOfACommit: the inputs are checked
// before git sees them.
func TestReviewedViewRefusesWhatIsNotATagOfACommit(t *testing.T) {
	repos, _ := storeAt(t, nil)
	origin, _, second, _ := originWithHistory(t, repos)
	ctx := context.Background()
	for name, tc := range map[string]struct {
		tags map[string]string
		head string
	}{
		"head is not an id":      {map[string]string{"refs/tags/v1.0.0": second}, "main"},
		"head is empty":          {map[string]string{"refs/tags/v1.0.0": second}, ""},
		"head is uppercase":      {map[string]string{"refs/tags/v1.0.0": second}, strings.ToUpper(second)},
		"ref is a branch":        {map[string]string{"refs/heads/main": second}, second},
		"ref is not under refs/": {map[string]string{"v1.0.0": second}, second},
		"ref has a space":        {map[string]string{"refs/tags/v 1": second}, second},
		"ref has a glob":         {map[string]string{"refs/tags/v*": second}, second},
		"object is not an id":    {map[string]string{"refs/tags/v1.0.0": "v1.0.0"}, second},
		"object is short":        {map[string]string{"refs/tags/v1.0.0": second[:39]}, second},
	} {
		if path, err := repos.ReviewedView(ctx, origin, tc.tags, tc.head); err == nil {
			t.Errorf("%s: built a view at %s", name, path)
		}
	}
}

// TestReviewedViewsAreKeptWhileInUseAndPrunedWhenStale: building a view
// removes the repository's other views that have been idle for half an
// hour, keeps the younger ones, and touches no other repository's.
func TestReviewedViewsAreKeptWhileInUseAndPrunedWhenStale(t *testing.T) {
	repos, data := storeAt(t, nil)
	origin, first, second, unreviewed := originWithHistory(t, repos)
	ctx := context.Background()
	build := func(id uuid.UUID, tags map[string]string, head string) string {
		t.Helper()
		p, err := repos.ReviewedView(ctx, id, tags, head)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	// A neighbour in the same shard directory, with its own idle view.
	neighbour := uuid.MustParse(origin.String()[:2] + uuid.NewString()[2:])
	if err := repos.InitBare(ctx, neighbour, "main"); err != nil {
		t.Fatal(err)
	}
	mustGit(t, repos.Path(neighbour), "fetch", "-q", repos.Path(origin), "refs/tags/v1.0.0:refs/tags/v1.0.0")
	theirs := build(neighbour, map[string]string{"refs/tags/v1.0.0": second}, second)
	ageView(t, theirs, 3*time.Hour)

	oldest := build(origin, map[string]string{"refs/tags/v1.0.0": second}, first)
	middle := build(origin, map[string]string{"refs/tags/v1.0.0": second}, second)
	// Both views were built a moment ago: building the second pruned nothing.
	if len(viewsOf(t, data, origin)) != 2 {
		t.Fatalf("views = %v, want both while they are fresh", viewsOf(t, data, origin))
	}
	ageView(t, oldest, 31*time.Minute)
	ageView(t, middle, 10*time.Minute)
	newest := build(origin, map[string]string{"refs/tags/v1.0.0": second, "refs/tags/v1.1.0": unreviewed["tag v1.1.0"]}, unreviewed["commit CANDIDATE.md"])

	left := map[string]bool{}
	for _, v := range viewsOf(t, data, origin) {
		left[v] = true
	}
	if left[oldest] {
		t.Errorf("a view idle for 31 minutes was kept")
	}
	if !left[middle] {
		t.Errorf("a view idle for 10 minutes was removed")
	}
	if !left[newest] {
		t.Errorf("the view just built was removed")
	}
	if _, err := os.Stat(theirs); err != nil {
		t.Errorf("another repository's idle view was pruned: %v", err)
	}

	// Removing a repository removes its views, fresh or not, and only its.
	if err := repos.Remove(origin); err != nil {
		t.Fatal(err)
	}
	if left := viewsOf(t, data, origin); len(left) != 0 {
		t.Fatalf("after Remove the repository still has views %v", left)
	}
	if _, err := os.Stat(theirs); err != nil {
		t.Fatalf("Remove took another repository's view: %v", err)
	}
	if _, err := os.Stat(repos.Path(origin)); !os.IsNotExist(err) {
		t.Fatalf("Remove left the repository: %v", err)
	}
}
