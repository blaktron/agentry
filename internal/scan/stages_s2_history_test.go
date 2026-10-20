package scan

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

const historyFixture = "\x01aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n" +
	"diff --git a/config.env b/config.env\n--- /dev/null\n+++ b/config.env\n@@ -0,0 +1,2 @@\n" +
	"+AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n+GREETING=hello\n" +
	"\x01bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n" +
	"diff --git a/config.env b/config.env\n--- a/config.env\n+++ b/config.env\n@@ -1 +0,0 @@\n" +
	"-AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n" +
	"diff --git a/notes.md b/notes.md\n--- /dev/null\n+++ b/notes.md\n@@ -0,0 +1 @@\n+AKIAIOSFODNN7EXAMPLE again\n"

func TestScanHistoryPatch(t *testing.T) {
	findings, truncated, err := scanHistoryPatch(strings.NewReader(historyFixture))
	if err != nil || truncated {
		t.Fatalf("err=%v truncated=%v", err, truncated)
	}
	if len(findings) != 1 {
		t.Fatalf("one de-duplicated finding expected, got %+v", findings)
	}
	f := findings[0]
	if f.Scanner != "S2/history-aws-access-key" || f.FilePath != "config.env" || f.Detail["commit"] != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("finding: %+v", f)
	}
	if strings.Contains(f.Excerpt, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("excerpt must be redacted: %q", f.Excerpt)
	}

	scanHistoryPatchAttribution(t)
}

func TestScanHistoryPatchCap(t *testing.T) {
	big := strings.NewReader(strings.Repeat("+x\n", historyPatchCap/3+10))
	_, truncated, err := scanHistoryPatch(big)
	if err != nil || !truncated {
		t.Fatalf("cap must truncate cleanly: err=%v truncated=%v", err, truncated)
	}

	// The cap counts every byte read, newlines included: a patch of exactly
	// the cap is read whole and one byte more is not, whether read directly
	// or through the stage (which hands the scan one byte beyond the cap).
	for _, tc := range []struct {
		name, tail string
		truncated  bool
	}{{"exactly the cap", "", false}, {"one byte over", "\n", true}} {
		patch := func() io.Reader {
			return io.MultiReader(&contextLines{size: 64 << 20}, strings.NewReader(tc.tail))
		}
		if _, truncated, err := scanHistoryPatch(patch()); err != nil || truncated != tc.truncated {
			t.Errorf("%s: err=%v truncated=%v, want truncated=%v", tc.name, err, truncated, tc.truncated)
		}
		f, ran := s2History(context.Background(), &Input{Source: "git-tag", History: func(context.Context) (io.ReadCloser, error) {
			return io.NopCloser(patch()), nil
		}})
		if !ran || (len(f) == 1) != tc.truncated || len(f) > 1 {
			t.Errorf("%s through the stage: %+v ran=%v", tc.name, f, ran)
		}
		if tc.truncated {
			if f[0].Scanner != "S2/history-truncated" || f[0].Severity != SevMedium || f[0].Detail["capBytes"] != 64<<20 {
				t.Errorf("%s: truncation finding = %+v", tc.name, f[0])
			}
			// A stream that cannot be closed cleanly after the stage stopped
			// reading it is still only truncated.
			g, _ := s2History(context.Background(), &Input{Source: "git-tag", History: func(context.Context) (io.ReadCloser, error) {
				return rcErr{patch()}, nil
			}})
			if len(g) != 1 || g[0].Scanner != "S2/history-truncated" {
				t.Errorf("%s with a close error: %+v", tc.name, g)
			}
		}
	}
}

type rcErr struct{ io.Reader }

func (rcErr) Close() error { return errors.New("git exited 128: bad object") }

func TestS2HistoryOutcomes(t *testing.T) {
	ctx := context.Background()
	if f, ran := s2History(ctx, &Input{Source: "cli-upload"}); f != nil || ran {
		t.Fatal("cli-upload has no history")
	}
	f, ran := s2History(ctx, &Input{Source: "git-tag"})
	if ran || len(f) != 1 || f[0].Scanner != "S2/history-not-scanned" {
		t.Fatalf("no seam must be reported: %+v", f)
	}
	if f[0].Severity != SevInfo || f[0].Confidence != ConfLow {
		t.Fatalf("not-scanned finding = %s/%s, want info/low", f[0].Severity, f[0].Confidence)
	}
	// A history that cannot be opened is a medium finding and leaves the
	// result cacheable; one that is scanned and fails halfway does not.
	f, ran = s2History(ctx, &Input{Source: "git-tag", History: func(context.Context) (io.ReadCloser, error) {
		return nil, errors.New("git: repository not found")
	}})
	if ran || len(f) != 1 || f[0].Scanner != "S2/history-error" || f[0].Severity != SevMedium || f[0].Detail["error"] != "git: repository not found" {
		t.Fatalf("history that cannot be opened: %+v ran=%v", f, ran)
	}
	f, ran = s2History(ctx, &Input{Source: "git-tag", History: func(context.Context) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader("\x01" + strings.Repeat("a", 40) + "\n+" + strings.Repeat("y", 70<<10) + "\n")), nil
	}})
	if !ran || len(f) != 1 || f[0].Scanner != "S2/history-error" || !strings.Contains(f[0].Detail["error"].(string), "history patch line longer than") {
		t.Fatalf("history with a line too long to read: %+v ran=%v", f, ran)
	}
	// When the scan failed, a close error does not replace its reason.
	f, _ = s2History(ctx, &Input{Source: "git-tag", History: func(context.Context) (io.ReadCloser, error) {
		return rcErr{strings.NewReader("\x01" + strings.Repeat("a", 40) + "\n+" + strings.Repeat("y", 70<<10) + "\n")}, nil
	}})
	if len(f) != 1 || !strings.Contains(f[0].Detail["error"].(string), "history patch line longer than") {
		t.Fatalf("the close error replaced the scan error: %+v", f)
	}
	f, ran = s2History(ctx, &Input{Source: "git-tag", History: func(context.Context) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(historyFixture)), nil
	}})
	if !ran || len(f) != 1 || f[0].Scanner != "S2/history-aws-access-key" {
		t.Fatalf("history scan: %+v", f)
	}
	f, _ = s2History(ctx, &Input{Source: "git-tag", History: func(context.Context) (io.ReadCloser, error) {
		return rcErr{strings.NewReader("")}, nil
	}})
	if len(f) != 1 || f[0].Scanner != "S2/history-error" {
		t.Fatalf("git failure must be a finding: %+v", f)
	}
	if f[0].Severity != SevMedium || f[0].Confidence != ConfHigh || f[0].Detail["error"] != "git exited 128: bad object" {
		t.Fatalf("git failure = %s/%s %+v", f[0].Severity, f[0].Confidence, f[0].Detail)
	}
	res := S2Secrets{}.Run(stageContext{ctx: ctx}, &Input{Source: "git-tag", History: func(context.Context) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(historyFixture)), nil
	}})
	if !res.NoCache {
		t.Fatal("a history-scanned S2 result must not be cached by archive digest")
	}
}

// contextLine is a 1 KiB context line: a space, 1022 letters, a newline.
var contextLine = func() []byte {
	b := bytes.Repeat([]byte("x"), 1024)
	b[0], b[1023] = ' ', '\n'
	return b
}()

// contextLines reads size bytes of context lines: lines the history scan
// reads and finds nothing in, so that a patch of an exact size costs no
// memory.
type contextLines struct{ pos, size int64 }

func (c *contextLines) Read(b []byte) (int, error) {
	if c.pos >= c.size {
		return 0, io.EOF
	}
	if rest := c.size - c.pos; int64(len(b)) > rest {
		b = b[:rest]
	}
	n := copy(b, contextLine[c.pos%1024:])
	c.pos += int64(n)
	return n, nil
}

// fakeHistoryPAT is a GitHub token assembled at run time, so the source
// carries no token-shaped literal.
func fakeHistoryPAT() string { return "gh" + "p_a1B2c3D4e5F6g7H8i9J0" + "k1L2m3N4o5P6q7R8" }

// historyAssignments is n added lines, each a distinct high-entropy password
// assignment, so each is its own finding.
func historyAssignments(n int) string {
	var b strings.Builder
	b.WriteString("\x01" + strings.Repeat("c", 40) + "\n+++ b/app.conf\n@@ -0,0 +1 @@\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "+password = \"%s.%03d\"\n", "aB3dE5gH7j"+"K9mN1pQ", i)
	}
	return b.String()
}

// scanHistoryPatchAttribution is the history scan's reading of a patch: what
// counts as a commit, which file a finding is placed in, which rules apply to
// an added line, and what is reported for it.
func scanHistoryPatchAttribution(t *testing.T) {
	const aws = "AKIAIOSFODNN7EXAMPLE"
	scan := func(patch string) []Finding {
		t.Helper()
		findings, truncated, err := scanHistoryPatch(strings.NewReader(patch))
		if err != nil || truncated {
			t.Fatalf("err=%v truncated=%v", err, truncated)
		}
		return findings
	}

	// A commit id is 7 to 64 lower-case hex digits; any other \x01 line is not a
	// commit, so what follows it is placed at none.
	for _, tc := range []struct{ id, want string }{
		{"abcdef0", "abcdef0"}, {strings.Repeat("a", 64), strings.Repeat("a", 64)},
		{"abcdef", ""}, {strings.Repeat("a", 65), ""}, {"ABCDEF0", ""}, {"abcdefg", ""},
	} {
		got := scan("\x01" + tc.id + "\n+++ b/f.txt\n@@ -0,0 +1 @@\n+" + aws + "\n")
		if len(got) != 1 || got[0].Detail["commit"] != tc.want {
			t.Errorf("commit line %q: %+v, want commit %q", tc.id, got, tc.want)
		}
	}

	// The finding says what it is: rule, severity, the commit's file, a
	// redacted excerpt.
	got := scan("\x01" + strings.Repeat("a", 40) + "\n+++ b/one.env\n@@ -0,0 +1 @@\n+" + aws + "\n")
	if len(got) != 1 || got[0].Severity != SevHigh || got[0].Confidence != ConfHigh || got[0].FilePath != "one.env" || got[0].Detail["rule"] != "aws-access-key" {
		t.Fatalf("finding: %+v", got)
	}

	// A new commit starts with no file; a deleted file has none either.
	got = scan("\x01" + strings.Repeat("a", 40) + "\n+++ b/one.env\n@@ -0,0 +1 @@\n+" + aws + "\n" +
		"\x01" + strings.Repeat("b", 40) + "\n@@ -0,0 +1 @@\n+" + fakeHistoryPAT() + "\n")
	if len(got) != 2 || got[1].FilePath != "" || got[1].Detail["commit"] != strings.Repeat("b", 40) {
		t.Errorf("a new commit kept the previous file: %+v", got)
	}
	got = scan("\x01" + strings.Repeat("a", 40) + "\n--- a/gone.env\n+++ /dev/null\n@@ -0,0 +1 @@\n+" + aws + "\n")
	if len(got) != 1 || got[0].FilePath != "" {
		t.Errorf("an added line under /dev/null: %+v", got)
	}

	// Rules that need entropy apply it: a repeated character is a placeholder.
	pw := func(v string) string {
		return "\x01" + strings.Repeat("a", 40) + "\n+++ b/c.conf\n@@ -0,0 +1 @@\n+password = \"" + v + "\"\n"
	}
	if got := scan(pw(strings.Repeat("a", 24))); len(got) != 0 {
		t.Errorf("a placeholder password: %+v", got)
	}
	if got := scan(pw("aB3dE5gH7j" + "K9mN1pQ2rS")); len(got) != 1 || got[0].Scanner != "S2/history-generic-assignment" || got[0].Severity != SevMedium {
		t.Errorf("a real-looking password: %+v", got)
	}

	// One secret is one finding per rule: two rules that mask to the same
	// text are two findings.
	aws40 := aws + "0123456789abcdefghij"
	got = scan("\x01" + strings.Repeat("a", 40) + "\n+++ b/k.conf\n@@ -0,0 +1 @@\n+aws_key = \"" + aws40 + "\" # " + aws + "\n")
	rules := map[string]bool{}
	for _, f := range got {
		rules[f.Scanner] = true
	}
	if len(got) != 2 || !rules["S2/history-aws-access-key"] || !rules["S2/history-aws-secret-key"] {
		t.Errorf("two rules on one line: %+v", got)
	}

	// The report lists 100 findings; past that the scan reads on, is not
	// truncated, and adds one finding that counts the rest.
	findings, truncated, err := scanHistoryPatch(strings.NewReader(historyAssignments(100)))
	if err != nil || truncated || len(findings) != 100 {
		t.Errorf("100 findings: %d, truncated=%v, err=%v", len(findings), truncated, err)
	}
	findings, truncated, err = scanHistoryPatch(strings.NewReader(historyAssignments(101)))
	if err != nil || truncated || len(findings) != 101 || findings[100].Scanner != scannerHistoryFindingLimit || findings[100].Detail["notShown"] != 1 {
		t.Errorf("101 findings: %d, truncated=%v, err=%v", len(findings), truncated, err)
	}

	// A line the scanner cannot hold is an error that says so, and the
	// findings made before it are returned.
	long := "\x01" + strings.Repeat("a", 40) + "\n+++ b/f.txt\n@@ -0,0 +1 @@\n+" + aws + "\n+" + strings.Repeat("y", 70<<10) + "\n"
	findings, truncated, err = scanHistoryPatch(strings.NewReader(long))
	if err == nil || !strings.Contains(err.Error(), "history patch line longer than") || truncated || len(findings) != 1 {
		t.Errorf("an over-long line: %d findings, truncated=%v, err=%v", len(findings), truncated, err)
	}
}
