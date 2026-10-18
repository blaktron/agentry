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
	newHookRepo(t)
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
}
