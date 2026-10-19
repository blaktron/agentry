package gitsrv_test

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"

	"github.com/blaktron/agentry/internal/gitsrv"
)

// hookRepo is a bare repository the hook runs in, with plumbing helpers to
// build the objects a push would carry.
type hookRepo struct {
	t   *testing.T
	dir string
}

func newHookRepo(t *testing.T) hookRepo {
	t.Helper()
	dir := t.TempDir()
	mustGit(t, dir, "init", "--bare", "-b", "main")
	t.Chdir(dir)
	return hookRepo{t: t, dir: dir}
}

func (r hookRepo) git(stdin string, args ...string) string {
	r.t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = r.dir
	cmd.Env = append(cmd.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.test", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.test")
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		r.t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func (r hookRepo) blob(content string) string {
	return r.git(content, "hash-object", "-w", "--stdin")
}

func (r hookRepo) tree(entries string) string { return r.git(entries, "mktree") }

func (r hookRepo) commit(tree string) string { return r.git("", "commit-tree", tree, "-m", "c") }

// runHook feeds one "old new ref" line to the hook and returns its exit code
// and what it wrote to stderr.
func runHook(old, new, ref string) (int, string) {
	var stderr bytes.Buffer
	code := gitsrv.RunPreReceiveHook(strings.NewReader(old+" "+new+" "+ref+"\n"), &stderr)
	return code, stderr.String()
}

// The version-tag namespace is immutable and gated on publish permission
// whatever the case of the version's leading letter.
func TestHookProtectsVersionTagsInEveryCase(t *testing.T) {
	repo := newHookRepo(t)
	anOID := strings.Repeat("a", 40)
	for _, ref := range []string{"refs/tags/v1.0.0", "refs/tags/V1.0.0"} {
		t.Run(ref, func(t *testing.T) {
			if code, msg := runHook(anOID, zeroesOID, ref); code == 0 || !strings.Contains(msg, "immutable") {
				t.Fatalf("delete of %s: code %d, %q", ref, code, msg)
			}
			if code, msg := runHook(anOID, strings.Repeat("b", 40), ref); code == 0 || !strings.Contains(msg, "immutable") {
				t.Fatalf("update of %s: code %d, %q", ref, code, msg)
			}
			// No publish permission in the environment: a new one is refused.
			if code, msg := runHook(zeroesOID, strings.Repeat("b", 40), ref); code == 0 || !strings.Contains(msg, "publish permission") {
				t.Fatalf("create of %s without permission: code %d, %q", ref, code, msg)
			}
		})
	}
	// A tag that is not a version tag is not in the namespace.
	if code, msg := runHook(anOID, zeroesOID, "refs/tags/release-1"); code != 0 {
		t.Fatalf("delete of a non-version tag was refused: %q", msg)
	}
	// The namespace is the tags, not any ref whose name starts with a v.
	for _, ref := range []string{"refs/heads/v1.0.0", "refs/heads/V1.0.0", "v1.0.0"} {
		if code, msg := runHook(anOID, zeroesOID, ref); code != 0 {
			t.Fatalf("delete of %s was refused as a version tag: %q", ref, msg)
		}
	}
	// Publish permission is the word true and nothing else.
	commit := repo.commit(repo.tree("100644 blob " + repo.blob("hello") + "\tREADME.md\n"))
	for _, value := range []string{"", "false", "1", "yes", "TRUE", "True", "t"} {
		t.Setenv("AGENTRY_HOOK_CAN_PUBLISH", value)
		if code, msg := runHook(zeroesOID, commit, "refs/tags/v1.0.0"); code == 0 || !strings.Contains(msg, "creating refs/tags/v1.0.0 requires publish permission on this agent") {
			t.Fatalf("create of a version tag with CAN_PUBLISH=%q: code %d, %q", value, code, msg)
		}
	}
	t.Setenv("AGENTRY_HOOK_CAN_PUBLISH", "true")
	for _, ref := range []string{"refs/tags/v1.0.0", "refs/tags/V1.0.0"} {
		if code, msg := runHook(zeroesOID, commit, ref); code != 0 {
			t.Fatalf("create of %s with publish permission was refused: %q", ref, msg)
		}
	}
	// Even then an existing version tag is immutable.
	if code, msg := runHook(commit, zeroesOID, "refs/tags/v1.0.0"); code == 0 || !strings.Contains(msg, "immutable") {
		t.Fatalf("delete of a version tag with publish permission: code %d, %q", code, msg)
	}
}

// A new tip whose tree the hook cannot read is refused: an object that is
// missing, or one that git cannot list, must not pass the content policy by
// failing to be scanned. What genuinely has no tree (a tag of a single file)
// is still admitted.
func TestHookTreeCheckFailsClosed(t *testing.T) {
	t.Setenv("AGENTRY_HOOK_MAX_BLOB_BYTES", "1048576")

	t.Run("object that is not in the repository", func(t *testing.T) {
		newHookRepo(t)
		code, msg := runHook(zeroesOID, strings.Repeat("b", 40), "refs/heads/feature")
		if code == 0 {
			t.Fatal("a tip git cannot read was accepted")
		}
		if !strings.Contains(msg, "could not read") {
			t.Fatalf("refusal does not say why: %q", msg)
		}
	})

	t.Run("an ordinary commit", func(t *testing.T) {
		r := newHookRepo(t)
		commit := r.commit(r.tree("100644 blob " + r.blob("hello") + "\tREADME.md\n"))
		if code, msg := runHook(zeroesOID, commit, "refs/heads/feature"); code != 0 {
			t.Fatalf("an ordinary commit was refused: %q", msg)
		}
	})

	t.Run("an annotated tag of a single file", func(t *testing.T) {
		r := newHookRepo(t)
		blob := r.blob("just a file")
		r.git("", "update-ref", "refs/keep/blob", blob) // keep the object reachable
		tag := r.git("object "+blob+"\ntype blob\ntag note\ntagger t <t@example.test> 0 +0000\n\nnote\n", "mktag")
		if code, msg := runHook(zeroesOID, tag, "refs/tags/note"); code != 0 {
			t.Fatalf("a tag of a blob was refused: %q", msg)
		}
	})

	t.Run("an annotated tag of a commit is scanned", func(t *testing.T) {
		r := newHookRepo(t)
		dotgit := r.tree("100644 blob " + r.blob("x") + "\tconfig\n")
		commit := r.commit(r.tree("040000 tree " + dotgit + "\t.git\n"))
		tag := r.git("object "+commit+"\ntype commit\ntag note\ntagger t <t@example.test> 0 +0000\n\nnote\n", "mktag")
		if code, msg := runHook(zeroesOID, tag, "refs/tags/note"); code == 0 || !strings.Contains(msg, ".git") {
			t.Fatalf("a tag of a commit with a .git entry: code %d, %q", code, msg)
		}
	})

	t.Run("a nested .git entry in a path git quotes", func(t *testing.T) {
		r := newHookRepo(t)
		// A non-ASCII name makes `git ls-tree` wrap the whole path in quotes
		// unless it is asked not to, which would hide a leading or a trailing
		// ".git" segment from a comparison on the segment.
		inside := r.tree("100644 blob " + r.blob("x") + "\t\xc3\xa9.txt\n")
		leading := r.commit(r.tree("040000 tree " + inside + "\t.git\n"))
		trailing := r.commit(r.tree("040000 tree " + r.tree("100644 blob "+r.blob("x")+"\t.git\n") + "\t\xc3\xa9\n"))
		for name, oid := range map[string]string{"leading segment": leading, "trailing segment": trailing} {
			if code, msg := runHook(zeroesOID, oid, "refs/heads/feature"); code == 0 || !strings.Contains(msg, ".git") {
				t.Fatalf("%s: code %d, %q", name, code, msg)
			}
		}
	})

	t.Run("a nested .git entry in any case", func(t *testing.T) {
		r := newHookRepo(t)
		for _, name := range []string{".GIT", ".Git", ".gIT"} {
			inner := r.tree("100644 blob " + r.blob("x") + "\tconfig\n")
			commit := r.commit(r.tree("040000 tree " + r.tree("040000 tree "+inner+"\t"+name+"\n") + "\tvendor\n"))
			code, msg := runHook(zeroesOID, commit, "refs/heads/feature")
			if code == 0 || !strings.Contains(msg, "nested .git entries are not allowed: vendor/"+name+"/config") {
				t.Fatalf("%s directory: code %d, %q", name, code, msg)
			}
		}
		// A name that only contains the segment is not the segment.
		fine := r.commit(r.tree("100644 blob " + r.blob("x") + "\t.gitignore\n100644 blob " + r.blob("y") + "\tgit.txt\n"))
		if code, msg := runHook(zeroesOID, fine, "refs/heads/feature"); code != 0 {
			t.Fatalf("a .gitignore was refused: %q", msg)
		}
	})

	t.Run("the single-file limit is exact", func(t *testing.T) {
		r := newHookRepo(t)
		const limit = 1048576
		atLimit := r.commit(r.tree("100644 blob " + r.blob(strings.Repeat("x", limit)) + "\tbig.bin\n"))
		if code, msg := runHook(zeroesOID, atLimit, "refs/heads/feature"); code != 0 {
			t.Fatalf("a file of exactly the limit was refused: %q", msg)
		}
		overBlob := r.blob(strings.Repeat("x", limit+1))
		// The file sits inside a directory so the refusal names its path.
		over := r.commit(r.tree("040000 tree " + r.tree("100644 blob "+overBlob+"\tbig.bin\n") + "\tdir\n"))
		if code, msg := runHook(zeroesOID, over, "refs/heads/feature"); code == 0 || !strings.Contains(msg, "dir/big.bin exceeds the 1 MB single-file limit") {
			t.Fatalf("a file one byte over the limit: code %d, %q", code, msg)
		}
	})

	t.Run("a tag of a single file is held to the limit too", func(t *testing.T) {
		r := newHookRepo(t)
		const limit = 1048576
		tagOf := func(blob string) string {
			return r.git("object "+blob+"\ntype blob\ntag note\ntagger t <t@example.test> 0 +0000\n\nnote\n", "mktag")
		}
		if code, msg := runHook(zeroesOID, tagOf(r.blob(strings.Repeat("x", limit))), "refs/tags/note"); code != 0 {
			t.Fatalf("a tag of a file of exactly the limit was refused: %q", msg)
		}
		over := tagOf(r.blob(strings.Repeat("x", limit+1)))
		if code, msg := runHook(zeroesOID, over, "refs/tags/note"); code == 0 || !strings.Contains(msg, over+" exceeds the 1 MB single-file limit") {
			t.Fatalf("a tag of a file one byte over the limit: code %d, %q", code, msg)
		}
	})

	t.Run("the limit is 25 MB when nothing sets it", func(t *testing.T) {
		for _, unset := range []string{"", "not a number"} {
			t.Setenv("AGENTRY_HOOK_MAX_BLOB_BYTES", unset)
			r := newHookRepo(t)
			const limit = 25 << 20
			atLimit := r.commit(r.tree("100644 blob " + r.blob(strings.Repeat("x", limit)) + "\tbig.bin\n"))
			if code, msg := runHook(zeroesOID, atLimit, "refs/heads/feature"); code != 0 {
				t.Fatalf("MAX_BLOB_BYTES=%q: a file of 25 MB was refused: %q", unset, msg)
			}
			over := r.commit(r.tree("100644 blob " + r.blob(strings.Repeat("x", limit+1)) + "\tbig.bin\n"))
			if code, msg := runHook(zeroesOID, over, "refs/heads/feature"); code == 0 || !strings.Contains(msg, "exceeds the 25 MB single-file limit") {
				t.Fatalf("MAX_BLOB_BYTES=%q: a file one byte over 25 MB: code %d, %q", unset, code, msg)
			}
		}
	})
}
