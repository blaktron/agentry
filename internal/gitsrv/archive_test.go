package gitsrv

// White-box: the release archive. A release is what `git archive` makes of
// a commit, checked against that commit's tree, with no gitattributes of any
// source allowed to drop a file from it. No database: the repositories are
// built with git plumbing in a scratch data directory.

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/blaktron/agentry/internal/config"
)

// plumbIn runs git in dir with stdin and returns its trimmed stdout.
func plumbIn(t *testing.T, dir, stdin string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...) //nolint:gosec // test fixture
	cmd.Stdin = strings.NewReader(stdin)
	cmd.Env = append(os.Environ(),
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.test",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.test")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, stderr.String())
	}
	return strings.TrimSpace(string(out))
}

// releaseRepo is a bare repository holding one commit whose tree has plain
// files, a file in a directory, a file whose name git quotes, a
// .gitattributes marking everything export-ignore, and a submodule entry.
type releaseRepo struct {
	s      *RepoStore
	id     uuid.UUID
	dir    string
	commit string
	tree   string
	blob   string
	files  []string // every blob path of the tree
}

func newReleaseRepo(t *testing.T, extra map[string]string) releaseRepo {
	t.Helper()
	s, err := NewRepoStore(config.Config{Git: config.Git{DataDir: t.TempDir(), HooksDir: t.TempDir()}})
	if err != nil {
		t.Fatal(err)
	}
	id := uuid.New()
	if err := s.InitBare(context.Background(), id, "main"); err != nil {
		t.Fatal(err)
	}
	dir := s.Path(id)
	blobOf := func(content string) string { return plumbIn(t, dir, content, "hash-object", "-w", "--stdin") }
	r := releaseRepo{s: s, id: id, dir: dir, blob: blobOf("content\n")}
	var entries strings.Builder
	add := func(path string) {
		r.files = append(r.files, path)
	}
	for _, name := range []string{"README.md", "agent.yaml", "é.txt", "f1", "f2", "f3", "f4", "f5", "f6", "f7", "f8"} {
		entries.WriteString("100644 blob " + blobOf(name+"\n") + "\t" + name + "\n")
		add(name)
	}
	attrs := "* export-ignore\n"
	if v, ok := extra[".gitattributes"]; ok {
		attrs = v
	}
	entries.WriteString("100644 blob " + blobOf(attrs) + "\t.gitattributes\n")
	add(".gitattributes")
	inner := plumbIn(t, dir, "100644 blob "+blobOf("nested\n")+"\ta.txt\n", "mktree")
	entries.WriteString("040000 tree " + inner + "\tdir\n")
	add("dir/a.txt")
	// A submodule: git archive never descends into it.
	entries.WriteString("160000 commit " + strings.Repeat("1", 40) + "\tsub\n")
	r.tree = plumbIn(t, dir, entries.String(), "mktree", "--missing")
	r.commit = plumbIn(t, dir, "release\n", "commit-tree", r.tree)
	plumbIn(t, dir, "", "update-ref", "refs/heads/main", r.commit)
	plumbIn(t, dir, "", "update-ref", "refs/tags/v1.0.0", r.commit)
	plumbIn(t, dir, "", "tag", "-a", "-m", "annotated", "v2.0.0", r.commit)
	sort.Strings(r.files)
	return r
}

func tarNames(t *testing.T, rc io.Reader) []string {
	t.Helper()
	var names []string
	tr := tar.NewReader(rc)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if hdr.Typeflag == tar.TypeReg {
			names = append(names, hdr.Name)
		}
	}
	sort.Strings(names)
	return names
}

// dropArgGit is a git that runs the real one without the given argument:
// the stand-in for a git that no longer neutralizes some attribute source.
func dropArgGit(t *testing.T, arg string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "git-wrapper")
	script := "#!/bin/sh\nn=$#\ni=0\nwhile [ $i -lt $n ]; do\n  a=$1; shift; i=$((i+1))\n  [ \"$a\" = \"" + arg + "\" ] || set -- \"$@\" \"$a\"\ndone\nexec git \"$@\"\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil { //nolint:gosec // a test git must be executable
		t.Fatal(err)
	}
	return path
}

// TestArchiveCommitHoldsEveryBlobOfTheTree: whatever a pushed .gitattributes
// or the operator's own attributes say, the archive has every blob of the
// commit; a submodule is not expected, and the stream's file goes with it.
func TestArchiveCommitHoldsEveryBlobOfTheTree(t *testing.T) {
	r := newReleaseRepo(t, nil)
	want := r.files

	check := func(t *testing.T) {
		t.Helper()
		rc, err := r.s.ArchiveCommit(context.Background(), r.id, r.commit)
		if err != nil {
			t.Fatalf("ArchiveCommit: %v", err)
		}
		got := tarNames(t, rc)
		if !slices.Equal(got, want) {
			t.Fatalf("archive holds %q, want %q", got, want)
		}
		name := rc.(*tempFile).Name()
		if _, err := os.Stat(name); err != nil {
			t.Fatalf("the archive's temp file is not there while the stream is open: %v", err)
		}
		if err := rc.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(name); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("closing the stream left %s behind: %v", name, err)
		}
	}
	t.Run("a pushed .gitattributes marks everything export-ignore", check)
	t.Run("the operator's global attributes file does too", func(t *testing.T) {
		attrs := filepath.Join(t.TempDir(), "attributes")
		if err := os.WriteFile(attrs, []byte("README.md export-ignore\nagent.yaml export-ignore\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		gitconfig := filepath.Join(t.TempDir(), "gitconfig")
		if err := os.WriteFile(gitconfig, []byte("[core]\n\tattributesFile = "+attrs+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("GIT_CONFIG_GLOBAL", gitconfig)
		check(t)
		// The startup proof holds under it too.
		if err := probeArchiveAttributes(r.s.gitBin); err != nil {
			t.Fatalf("self-test with a global attributes file: %v", err)
		}
	})
}

// TestArchiveCommitRefusesWhatIsNotACommit: the commit a worker rebuilds an
// archive from is a full lowercase object id naming a commit.
func TestArchiveCommitRefusesWhatIsNotACommit(t *testing.T) {
	r := newReleaseRepo(t, nil)
	notID := []string{"", "--all", "abc", "HEAD", "main", strings.ToUpper(r.commit), r.commit + "0", r.commit[:39], " " + r.commit}
	for _, id := range notID {
		_, err := r.s.ArchiveCommit(context.Background(), r.id, id)
		if err == nil || !strings.Contains(err.Error(), "is not a commit id") {
			t.Errorf("ArchiveCommit(%q): %v, want 'is not a commit id'", id, err)
		}
	}
	notThere := []string{r.tree, r.blob, strings.Repeat("0", 40), strings.Repeat("a", 64)}
	for _, id := range notThere {
		_, err := r.s.ArchiveCommit(context.Background(), r.id, id)
		if err == nil || !strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "is not a commit id") {
			t.Errorf("ArchiveCommit(%s): %v, want 'not found'", id, err)
		}
	}
}

// TestArchiveFailsClosedOnInfoAttributes: $GIT_DIR/info/attributes cannot be
// switched off in git, so every reader of the repository's history for a
// release stops while it holds rules; an empty file holds none.
func TestArchiveFailsClosedOnInfoAttributes(t *testing.T) {
	r := newReleaseRepo(t, nil)
	info := filepath.Join(r.dir, "info")
	if err := os.MkdirAll(info, 0o750); err != nil {
		t.Fatal(err)
	}
	attrs := filepath.Join(info, "attributes")
	ctx := context.Background()
	refused := func(what string, err error) {
		t.Helper()
		if err == nil || !strings.Contains(err.Error(), "release archives must not be filtered by gitattributes") {
			t.Errorf("%s with rules in info/attributes: %v, want the gitattributes refusal", what, err)
		}
	}

	if err := os.WriteFile(attrs, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	rc, err := r.s.ArchiveCommit(ctx, r.id, r.commit)
	if err != nil {
		t.Fatalf("an empty info/attributes refused the archive: %v", err)
	}
	_ = rc.Close()

	if err := os.WriteFile(attrs, []byte("README.md export-ignore\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = r.s.ArchiveCommit(ctx, r.id, r.commit)
	refused("ArchiveCommit", err)
	_, _, err = r.s.ArchiveTag(ctx, r.id, "v1.0.0")
	refused("ArchiveTag", err)
	_, err = r.s.HistoryPatch(ctx, r.id, r.commit)
	refused("HistoryPatch", err)
	_, err = r.s.MaterializeTag(ctx, r.id, "v1.0.0", t.TempDir())
	refused("MaterializeTag", err)
	refused("MaterializeCommit", r.s.MaterializeCommit(ctx, r.id, r.commit, t.TempDir()))
}

// TestArchiveTagResolvesToTheCommit: a lightweight and an annotated tag give
// the commit they name, in the plain and the qualified spelling; a tag that
// is not there says so.
func TestArchiveTagResolvesToTheCommit(t *testing.T) {
	r := newReleaseRepo(t, nil)
	ctx := context.Background()
	for _, tag := range []string{"v1.0.0", "refs/tags/v1.0.0", "v2.0.0", "refs/tags/v2.0.0"} {
		rc, commit, err := r.s.ArchiveTag(ctx, r.id, tag)
		if err != nil {
			t.Fatalf("ArchiveTag(%q): %v", tag, err)
		}
		_ = rc.Close()
		if commit != r.commit {
			t.Errorf("ArchiveTag(%q) commit %s, want %s", tag, commit, r.commit)
		}
	}
	if _, _, err := r.s.ArchiveTag(ctx, r.id, "v9.9.9"); err == nil || !strings.Contains(err.Error(), "tag v9.9.9 not found") {
		t.Fatalf("a tag that is not there: %v, want 'tag v9.9.9 not found'", err)
	}
	if _, _, err := r.s.ArchiveTag(ctx, r.id, "--all"); err == nil || !strings.Contains(err.Error(), "not a tag name") {
		t.Fatalf("an option as a tag: %v, want 'not a tag name'", err)
	}

	dst := t.TempDir()
	commit, err := r.s.MaterializeTag(ctx, r.id, "v2.0.0", dst)
	if err != nil || commit != r.commit {
		t.Fatalf("MaterializeTag = %q, %v, want %s", commit, err, r.commit)
	}
	for _, f := range r.files {
		if _, err := os.Stat(filepath.Join(dst, filepath.FromSlash(f))); err != nil {
			t.Errorf("MaterializeTag left out %s", f)
		}
	}
	dst = t.TempDir()
	if err := r.s.MaterializeCommit(ctx, r.id, r.commit, dst); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(dst, "dir", "a.txt")); err != nil || string(got) != "nested\n" {
		t.Fatalf("MaterializeCommit dir/a.txt = %q, %v", got, err)
	}
}

// TestTagRefQualifiesOnlyPlainTagNames: what is handed to git as a tag is a
// plain ref under refs/tags/, spelled once, or the tag is refused before git
// starts.
func TestTagRefQualifiesOnlyPlainTagNames(t *testing.T) {
	for tag, want := range map[string]string{
		"v1.0.0":           "refs/tags/v1.0.0",
		"refs/tags/v1.0.0": "refs/tags/v1.0.0",
		"release/1.0":      "refs/tags/release/1.0",
		"a-b_c.d":          "refs/tags/a-b_c.d",
	} {
		if got, err := tagRef(tag); err != nil || got != want {
			t.Errorf("tagRef(%q) = %q, %v, want %q", tag, got, err, want)
		}
	}
	for _, tag := range []string{
		"", "refs/tags/", "refs/heads/main", "refs/remotes/origin/x", "-n1", "--all", "refs/tags/-x",
		"a..b", "refs/tags/a..b", "a b", "a\tb", "a\nb", "a*", "a?", "a[b", "a]b", `a\b`, "a^b", "a:b", "a~1",
		"a//b", "a/", "refs/tags/a/", "a{b", "a}b", "a@b", "v1@{1}", "v1.2.0^{}",
	} {
		if got, err := tagRef(tag); err == nil || !strings.Contains(err.Error(), "is not a tag name") {
			t.Errorf("tagRef(%q) = %q, %v, want a 'not a tag name' refusal", tag, got, err)
		}
	}
}

// tarOf writes a tar holding an empty regular file per name (and a
// directory entry per name ending in a slash) to a temp file.
func tarOf(t *testing.T, names ...string) *os.File {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "x*.tar")
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(f)
	for _, n := range names {
		hdr := &tar.Header{Name: n, Typeflag: tar.TypeReg, Mode: 0o644}
		if strings.HasSuffix(n, "/") {
			hdr = &tar.Header{Name: n, Typeflag: tar.TypeDir, Mode: 0o755}
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

// TestVerifyArchiveCompleteNamesWhatWasDropped: an archive missing any blob
// of the commit is refused, with the count and the first five paths in
// order; a submodule and a directory entry are not blobs.
func TestVerifyArchiveCompleteNamesWhatWasDropped(t *testing.T) {
	r := newReleaseRepo(t, nil)
	ctx := context.Background()
	without := func(drop ...string) []string {
		var keep []string
		for _, f := range r.files {
			if !slices.Contains(drop, f) {
				keep = append(keep, f)
			}
		}
		return append(keep, "dir/")
	}
	if err := r.s.verifyArchiveComplete(ctx, r.dir, r.commit, tarOf(t, without()...)); err != nil {
		t.Fatalf("a complete archive (no entry for the submodule): %v", err)
	}
	for _, tc := range []struct {
		name string
		drop []string
		want string
	}{
		{"one", []string{"f3"}, "dropped 1 path(s) of " + r.commit + " (f3)"},
		{"a nested file", []string{"dir/a.txt"}, "dropped 1 path(s) of " + r.commit + " (dir/a.txt)"},
		{"a name git quotes", []string{"é.txt"}, "dropped 1 path(s) of " + r.commit + " (é.txt)"},
		{"five", []string{"f5", "f1", "f4", "f2", "f3"}, "dropped 5 path(s) of " + r.commit + " (f1, f2, f3, f4, f5)"},
		{"six", []string{"f6", "f1", "f4", "f2", "f3", "f5"}, "dropped 6 path(s) of " + r.commit + " (f1, f2, f3, f4, f5, …)"},
		{"eight", []string{"f8", "f7", "f6", "f1", "f4", "f2", "f3", "f5"}, "dropped 8 path(s) of " + r.commit + " (f1, f2, f3, f4, f5, …)"},
	} {
		err := r.s.verifyArchiveComplete(ctx, r.dir, r.commit, tarOf(t, without(tc.drop...)...))
		if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "a gitattributes filter is still in effect") {
			t.Errorf("%s dropped: %v, want it to say %q", tc.name, err, tc.want)
		}
	}
	f, err := os.CreateTemp(t.TempDir(), "junk*.tar")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	_, _ = f.WriteString(strings.Repeat("this is not a tar archive\n", 100))
	if err := r.s.verifyArchiveComplete(ctx, r.dir, r.commit, f); err == nil || !strings.Contains(err.Error(), "archive read back") {
		t.Fatalf("bytes that are not a tar: %v, want an 'archive read back' error", err)
	}
}

// TestArchiveCheckedAgainstTheTree: with a git that no longer ignores the
// tree's own .gitattributes the archive comes out short, and it is the check
// against the tree that stops it; a failed archive leaves no temp file.
func TestArchiveCheckedAgainstTheTree(t *testing.T) {
	r := newReleaseRepo(t, map[string]string{".gitattributes": "README.md export-ignore\n"})
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	short := *r.s
	short.gitBin = dropArgGit(t, "--worktree-attributes")
	rc, err := short.ArchiveCommit(context.Background(), r.id, r.commit)
	if err == nil {
		_ = rc.Close()
		t.Fatal("an archive that dropped README.md was served")
	}
	if !strings.Contains(err.Error(), "dropped 1 path(s)") || !strings.Contains(err.Error(), "README.md") {
		t.Fatalf("short archive: %v, want the dropped path named", err)
	}
	if left, _ := os.ReadDir(tmp); len(left) != 0 {
		t.Fatalf("a refused archive left %v behind", left)
	}
	// An archive git itself cannot make leaves nothing either.
	if _, err := r.s.archiveCommit(context.Background(), r.dir, strings.Repeat("0", 40)); err == nil {
		t.Fatal("archive of a commit that is not there succeeded")
	}
	if left, _ := os.ReadDir(tmp); len(left) != 0 {
		t.Fatalf("a failed git archive left %v behind", left)
	}
}

// TestStartupRefusesAGitThatHonoursExportIgnore: NewRepoStore proves
// against the git it will use that export-ignore cannot filter a release,
// says which git failed, and remembers the answer per binary.
func TestStartupRefusesAGitThatHonoursExportIgnore(t *testing.T) {
	cfg := func(bin string) config.Config {
		return config.Config{Git: config.Git{DataDir: t.TempDir(), BinPath: bin}}
	}
	if _, err := NewRepoStore(cfg("")); err != nil {
		t.Fatalf("the installed git: %v", err)
	}
	bad := dropArgGit(t, "--worktree-attributes")
	_, err := NewRepoStore(cfg(bad))
	if err == nil {
		t.Fatal("a git that honours export-ignore was accepted")
	}
	for _, want := range []string{bad, "honours export-ignore", "git version", "refusing to start"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not say %q", err, want)
		}
	}
	// The verdict is kept for the binary: replacing the script does not
	// ask git again.
	good := "#!/bin/sh\nexec git \"$@\"\n"
	if err := os.WriteFile(bad, []byte(good), 0o755); err != nil { //nolint:gosec // a test git must be executable
		t.Fatal(err)
	}
	if _, err := NewRepoStore(cfg(bad)); err == nil {
		t.Fatal("the self-test ran again for the same binary")
	}

	t.Setenv("PATH", "")
	if _, err := NewRepoStore(cfg("")); err == nil || !strings.Contains(err.Error(), "git binary not found") {
		t.Fatalf("no git on PATH: %v, want 'git binary not found'", err)
	}
}

// tarEntry is one member of a tar built for extractPlainTar.
type tarEntry struct {
	name string
	typ  byte
	body string
	link string
}

func tarBytes(t *testing.T, entries ...tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Typeflag: e.typ, Mode: 0o644, Size: int64(len(e.body)), Linkname: e.link}
		switch e.typ {
		case tar.TypeDir:
			hdr.Size = 0
		case tar.TypeXGlobalHeader:
			// What git archive writes first: only the records are set.
			hdr = &tar.Header{Typeflag: e.typ, PAXRecords: map[string]string{"comment": "0123456789012345678901234567890123456789"}}
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if hdr.Size > 0 {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestExtractPlainTarIsDefensive: directories and regular files are
// unpacked, anything that would land outside the destination or is not a
// plain file is refused, and a file is never written over another.
func TestExtractPlainTarIsDefensive(t *testing.T) {
	t.Run("regular files, directories and git's global header", func(t *testing.T) {
		dst := t.TempDir()
		err := extractPlainTar(bytes.NewReader(tarBytes(t,
			tarEntry{typ: tar.TypeXGlobalHeader},
			tarEntry{name: "d/", typ: tar.TypeDir},
			tarEntry{name: "d/f.txt", typ: tar.TypeReg, body: "hello"},
			tarEntry{name: "x/y/z.txt", typ: tar.TypeReg, body: "deep"},
		)), dst)
		if err != nil {
			t.Fatal(err)
		}
		for path, want := range map[string]string{"d/f.txt": "hello", "x/y/z.txt": "deep"} {
			got, err := os.ReadFile(filepath.Join(dst, filepath.FromSlash(path)))
			if err != nil || string(got) != want {
				t.Errorf("%s = %q, %v, want %q", path, got, err, want)
			}
			fi, _ := os.Stat(filepath.Join(dst, filepath.FromSlash(path)))
			if fi.Mode().Perm()&0o111 != 0 {
				t.Errorf("%s was unpacked executable (%v)", path, fi.Mode().Perm())
			}
		}
	})
	for _, tc := range []struct {
		name  string
		entry tarEntry
		want  string
	}{
		{"parent directory", tarEntry{name: "../evil.txt", typ: tar.TypeReg, body: "x"}, "path traversal"},
		{"parent directory in the middle", tarEntry{name: "a/../../evil.txt", typ: tar.TypeReg, body: "x"}, "path traversal"},
		{"absolute path", tarEntry{name: "/etc/evil.txt", typ: tar.TypeReg, body: "x"}, "path traversal"},
		{"symbolic link", tarEntry{name: "link", typ: tar.TypeSymlink, link: "/etc/passwd"}, "unsupported tar entry"},
		{"hard link", tarEntry{name: "link", typ: tar.TypeLink, link: "other"}, "unsupported tar entry"},
		{"character device", tarEntry{name: "dev", typ: tar.TypeChar}, "unsupported tar entry"},
		{"fifo", tarEntry{name: "fifo", typ: tar.TypeFifo}, "unsupported tar entry"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parent := t.TempDir()
			dst := filepath.Join(parent, "dst")
			if err := os.Mkdir(dst, 0o750); err != nil {
				t.Fatal(err)
			}
			err := extractPlainTar(bytes.NewReader(tarBytes(t, tc.entry)), dst)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("%v, want an error saying %q", err, tc.want)
			}
			for _, dir := range []string{parent, dst, "/etc"} {
				if _, err := os.Stat(filepath.Join(dir, "evil.txt")); err == nil && dir != "/etc" {
					t.Errorf("a file was written at %s", filepath.Join(dir, "evil.txt"))
				}
			}
		})
	}
	t.Run("a file is not written over another", func(t *testing.T) {
		dst := t.TempDir()
		err := extractPlainTar(bytes.NewReader(tarBytes(t,
			tarEntry{name: "f.txt", typ: tar.TypeReg, body: "first"},
			tarEntry{name: "f.txt", typ: tar.TypeReg, body: "second"},
		)), dst)
		if err == nil {
			t.Fatal("the second f.txt was accepted")
		}
		if got, _ := os.ReadFile(filepath.Join(dst, "f.txt")); string(got) != "first" {
			t.Fatalf("f.txt = %q, want the first entry's bytes", got)
		}
	})
}
