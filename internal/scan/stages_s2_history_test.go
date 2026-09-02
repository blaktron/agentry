package scan

import (
	"context"
	"errors"
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
}

func TestScanHistoryPatchCap(t *testing.T) {
	big := strings.NewReader(strings.Repeat("+x\n", historyPatchCap/3+10))
	_, truncated, err := scanHistoryPatch(big)
	if err != nil || !truncated {
		t.Fatalf("cap must truncate cleanly: err=%v truncated=%v", err, truncated)
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
	res := S2Secrets{}.Run(stageContext{ctx: ctx}, &Input{Source: "git-tag", History: func(context.Context) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(historyFixture)), nil
	}})
	if !res.NoCache {
		t.Fatal("a history-scanned S2 result must not be cached by archive digest")
	}
}
