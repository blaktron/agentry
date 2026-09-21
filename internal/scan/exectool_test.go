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
func fakeTool(t *testing.T, script string) string {
	const name = "gitleaks"
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
	bin := fakeTool(t, "exit 0\n")
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
	bin := fakeTool(t, `
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
	bin := fakeTool(t, "echo boom >&2; exit 3\n")
	got := runGitleaks(context.Background(), &ExecTool{Bin: bin}, t.TempDir(), nil)
	if len(got) != 1 || got[0].Scanner != "S2/tool-error" || !strings.Contains(got[0].Detail["error"].(string), "boom") {
		t.Fatalf("expected a tool-error finding: %+v", got)
	}
	empty := fakeTool(t, `for a in "$@"; do last="$a"; done; : > "$last"`)
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

// TestRunGitleaksAlwaysPassesTheRegistrysConfig: gitleaks reads a
// .gitleaks.toml from the scanned source when no --config is given, so a
// submission could ship one with no rules and scan clean. Every invocation
// carries --config: the embedded default-rules file, or the operator's
// Rules path (security review 2026-09-20 §5.7).
func TestRunGitleaksAlwaysPassesTheRegistrysConfig(t *testing.T) {
	argsFile := filepath.Join(t.TempDir(), "args")
	bin := fakeTool(t, `printf '%s\n' "$@" > `+argsFile+`
for a in "$@"; do last="$a"; done; : > "$last"`)
	_ = runGitleaks(context.Background(), &ExecTool{Bin: bin}, t.TempDir(), nil)
	args := strings.Split(strings.TrimSpace(mustRead(t, argsFile)), "\n")
	cfg := ""
	for i, a := range args {
		if a == "--config" && i+1 < len(args) {
			cfg = args[i+1]
		}
	}
	if cfg == "" {
		t.Fatalf("no --config in %v", args)
	}
	if _, err := os.Stat(cfg); err == nil {
		t.Fatalf("the embedded config file %s outlived the run", cfg)
	}
	if !strings.Contains(string(gitleaksConfig), "useDefault = true") {
		t.Fatal("the embedded config must extend gitleaks' default rules")
	}
	// An operator's rules file is passed as given.
	rules := filepath.Join(t.TempDir(), "rules.toml")
	if err := os.WriteFile(rules, []byte("[extend]\nuseDefault = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = runGitleaks(context.Background(), &ExecTool{Bin: bin, Rules: rules}, t.TempDir(), nil)
	if !strings.Contains(mustRead(t, argsFile), "--config\n"+rules+"\n") {
		t.Fatalf("Rules not passed as --config: %s", mustRead(t, argsFile))
	}
}

// TestRunGitleaksIgnoresTheArchivesOwnConfig runs the real binary when it
// is on PATH: a tree carrying a .gitleaks.toml whose one rule matches
// nothing, beside a file with a key-shaped string, still yields an S2 hit.
func TestRunGitleaksIgnoresTheArchivesOwnConfig(t *testing.T) {
	tool, err := ResolveExecTool("gitleaks", "auto", "", 0)
	if err != nil || tool == nil {
		t.Skip("gitleaks not on PATH")
	}
	dir := t.TempDir()
	hostile := "title = \"empty\"\n[[rules]]\nid = \"never\"\ndescription = \"never matches\"\nregex = \"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\"\n"
	for name, body := range map[string]string{
		".gitleaks.toml": hostile,
		"config.js":      "const key = \"AKIAQ3F7Z9K2M8N4P6R1\";\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got := runGitleaks(context.Background(), tool, dir, nil)
	hit := false
	for _, f := range got {
		if f.FilePath == "config.js" && f.Scanner != "S2/tool-error" {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("the archive's .gitleaks.toml governed the scan: %+v", got)
	}
}

func mustRead(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
