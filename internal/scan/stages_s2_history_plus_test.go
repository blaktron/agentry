package scan

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// gitHistoryOf commits each step's files in a fresh repository (a nil content
// removes the file) and returns the history as the scan reads it: `git log
// -p` with the arguments the git host streams it with.
func gitHistoryOf(t *testing.T, steps ...map[string]*string) string {
	t.Helper()
	dir := t.TempDir()
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.test",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.test", "GIT_CONFIG_GLOBAL=/dev/null")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, out)
		}
		return string(out)
	}
	git("init", "-q", "-b", "main")
	for i, step := range steps {
		for name, content := range step {
			p := filepath.Join(dir, name)
			if content == nil {
				git("rm", "-q", name)
				continue
			}
			if err := os.WriteFile(p, []byte(*content), 0o600); err != nil {
				t.Fatal(err)
			}
			git("add", name)
		}
		git("commit", "-q", "--allow-empty", "-m", "step "+string(rune('a'+i)))
	}
	return git("log", "-p", "--no-color", "--no-merges", "--format=%x01%H",
		"--diff-filter=AM", "--no-renames", "-U0", "HEAD", "--")
}

func textOf(s string) *string { return &s }

// TestS2HistoryReadsAddedLinesThatStartWithPlus pins that an added line is
// scanned whatever its own first character: a committed patch's "+" line, a
// Markdown "+ " item, and a line whose text begins "++ " (which a diff shows
// as "+++ ", the shape of a file header) are each found after the commit
// that removes them.
func TestS2HistoryReadsAddedLinesThatStartWithPlus(t *testing.T) {
	for file, content := range map[string]string{
		"fix.patch": "diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n-old\n+AKIAI44QH8DHBEXAMPLE\n",
		"notes.md":  "# Notes\n\n+ deploy key AKIAJ5ZCLPN4EXAMPLE0\n",
		"list.txt":  "++ key AKIAQ7XRZ2VNEXAMPLE1\n",
	} {
		t.Run(file, func(t *testing.T) {
			patch := gitHistoryOf(t, map[string]*string{file: textOf(content)}, map[string]*string{file: nil})
			findings, truncated, err := scanHistoryPatch(strings.NewReader(patch))
			if err != nil || truncated {
				t.Fatalf("err=%v truncated=%v", err, truncated)
			}
			for _, f := range findings {
				if f.Scanner == "S2/history-aws-access-key" && f.FilePath == file {
					return
				}
			}
			t.Fatalf("the secret added to %s and later removed was not found (findings %+v)", file, findings)
		})
	}
}

// TestS2HistoryFileHeadersAreNotContent pins that a real "+++ b/<path>"
// header still names the file and is not itself scanned as an added line,
// and that an added line shaped like a header does not rename the file.
func TestS2HistoryFileHeadersAreNotContent(t *testing.T) {
	patch := "\x01" + strings.Repeat("c", 40) + "\n" +
		"diff --git a/AKIAZZZZZZZZEXAMPLE2 b/AKIAZZZZZZZZEXAMPLE2\n--- /dev/null\n+++ b/AKIAZZZZZZZZEXAMPLE2\n@@ -0,0 +1,2 @@\n" +
		"+harmless\n" +
		"+++ b/elsewhere AKIAI44QH8DHBEXAMPLE\n"
	findings, _, err := scanHistoryPatch(strings.NewReader(patch))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("want exactly the added line's secret, got %+v", findings)
	}
	if f := findings[0]; f.FilePath != "AKIAZZZZZZZZEXAMPLE2" || !strings.HasPrefix(f.Excerpt, "++ b/") {
		t.Fatalf("finding = %+v, want the added line, in the file its header named", f)
	}
}
