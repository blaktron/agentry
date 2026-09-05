package scan

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fakeTool writes an executable shell script that ignores its arguments
// except for finding the report path (gitleaks) and prints canned output.
func fakeTool(t *testing.T, name, script string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell fixtures")
	}
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestResolveExecTool(t *testing.T) {
	if tool, err := ResolveExecTool("gitleaks", "", "", 0); err != nil || tool != nil {
		t.Fatalf("empty must disable: %v %v", tool, err)
	}
	if _, err := ResolveExecTool("gitleaks", filepath.Join(t.TempDir(), "missing"), "", 0); err == nil {
		t.Fatal("missing binary must error")
	}
	bin := fakeTool(t, "gitleaks", "exit 0\n")
	if _, err := ResolveExecTool("gitleaks", bin, filepath.Join(t.TempDir(), "no-rules"), 0); err == nil {
		t.Fatal("missing rules must error")
	}
	tool, err := ResolveExecTool("gitleaks", bin, "", 0)
	if err != nil || tool == nil || tool.Bin != bin {
		t.Fatalf("resolve: %v %v", tool, err)
	}
	if _, err := ResolveExecTool("definitely-not-a-tool-xyz", "auto", "", 0); err == nil {
		t.Fatal("auto with no PATH hit must error")
	}
}

func TestRunGitleaksMergesReport(t *testing.T) {
	// The fixture writes a two-hit report to the --report-path argument.
	bin := fakeTool(t, "gitleaks", `
for a in "$@"; do last="$a"; done
cat > "$last" <<'JSON'
[
 {"RuleID":"aws-access-token","Description":"AWS Access Key","File":"src/config.js","StartLine":3,"EndLine":3,"Match":"AKIAIOSFODNN7EXAMPLE","Entropy":3.5},
 {"RuleID":"generic-api-key","Description":"Generic API Key","File":"./notes.txt","StartLine":9,"EndLine":10,"Match":"api_key = 'abcdefghijklmnop'","Entropy":4.1}
]
JSON
`)
	dir := t.TempDir()
	seen := map[string]bool{"src/config.js|3": true}
	got := runGitleaks(context.Background(), &ExecTool{Bin: bin}, dir, seen)
	if len(got) != 2 {
		t.Fatalf("findings: %+v", got)
	}
	if got[0].FilePath != "notes.txt" || got[0].Scanner != "S2/gitleaks-generic-api-key" || got[0].LineEnd != 10 {
		t.Fatalf("first (sorted by path): %+v", got[0])
	}
	if got[1].FilePath != "src/config.js" || got[1].Detail["corroborates"] != true || got[1].Severity != SevHigh {
		t.Fatalf("second: %+v", got[1])
	}
	if strings.Contains(got[1].Excerpt, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("excerpt must be redacted: %q", got[1].Excerpt)
	}
}

func TestRunGitleaksFailureIsAFinding(t *testing.T) {
	bin := fakeTool(t, "gitleaks", "echo boom >&2; exit 3\n")
	got := runGitleaks(context.Background(), &ExecTool{Bin: bin}, t.TempDir(), nil)
	if len(got) != 1 || got[0].Scanner != "S2/tool-error" || !strings.Contains(got[0].Detail["error"].(string), "boom") {
		t.Fatalf("expected a tool-error finding: %+v", got)
	}
	empty := fakeTool(t, "gitleaks", `for a in "$@"; do last="$a"; done; : > "$last"`)
	if got := runGitleaks(context.Background(), &ExecTool{Bin: empty}, t.TempDir(), nil); len(got) != 0 {
		t.Fatalf("empty report must yield nothing: %+v", got)
	}
}

func TestSanitizeRuleID(t *testing.T) {
	if got := sanitizeRuleID("AWS Access_Token/v2"); got != "aws-access-token-v2" {
		t.Fatal(got)
	}
	if got := sanitizeRuleID("///"); got != "rule" {
		t.Fatal(got)
	}
}
