package scan

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
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
	if _, err := ResolveExecTool("definitely-not-a-tool-xyz", "auto", "", 0); err == nil || !strings.Contains(err.Error(), "AGENTRY_SCAN_DEFINITELY-NOT-A-TOOL-XYZ_BIN") {
		t.Fatalf("auto with no PATH hit must error and name the setting: %v", err)
	}

	// The binary must be an executable file: a directory is not, nor is a
	// file without an execute bit.
	if _, err := ResolveExecTool("gitleaks", t.TempDir(), "", 0); err == nil || !strings.Contains(err.Error(), "not an executable file") {
		t.Fatalf("a directory as the tool: %v", err)
	}
	plain := filepath.Join(t.TempDir(), "gitleaks")
	if err := os.WriteFile(plain, []byte("#!/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveExecTool("gitleaks", plain, "", 0); err == nil || !strings.Contains(err.Error(), "not an executable file") {
		t.Fatalf("a non-executable file as the tool: %v", err)
	}
	// What is configured is what is kept: the trimmed path, the rules, the timeout.
	rules := filepath.Join(t.TempDir(), "rules.toml")
	if err := os.WriteFile(rules, []byte("title = \"x\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if tool, err := ResolveExecTool("gitleaks", "  "+bin+"  ", rules, 7*time.Second); err != nil || tool.Bin != bin || tool.Rules != rules || tool.Timeout != 7*time.Second {
		t.Fatalf("resolved tool: %+v %v", tool, err)
	}
	// "auto" is a PATH lookup of the tool's own name.
	if tool, err := ResolveExecTool("sh", "auto", "", 0); err != nil || filepath.Base(tool.Bin) != "sh" {
		t.Fatalf("auto: %+v %v", tool, err)
	}
}

// The bounds the adapter keeps on what it runs.
func TestExecToolRunIsBoundedAndScrubbed(t *testing.T) {
	if execToolDefaultTimeout != 2*time.Minute || execToolOutputCap != 8<<20 || execToolMaxFindings != 500 {
		t.Fatalf("bounds: timeout %v, output %d, findings %d", execToolDefaultTimeout, execToolOutputCap, execToolMaxFindings)
	}
	ctx := context.Background()

	t.Run("the tool runs in the archive directory with a scrubbed environment", func(t *testing.T) {
		t.Setenv("AGENTRY_TEST_SERVER_SECRET", "hunter2-credential")
		t.Setenv("GITHUB_TOKEN", "ghp_ambient")
		dir := t.TempDir()
		out := filepath.Join(t.TempDir(), "seen")
		bin := fakeTool(t, `pwd -P > `+out+`; env | sort >> `+out+`; echo "tmp=$TMPDIR" >> `+out+`; [ -d "$HOME" ] && echo "homedir=$HOME" >> `+out)
		if _, err := (&ExecTool{Bin: bin}).run(ctx, dir, "detect"); err != nil {
			t.Fatal(err)
		}
		seen := mustRead(t, out)
		real, _ := filepath.EvalSymlinks(dir)
		if first := strings.SplitN(seen, "\n", 2)[0]; first != real {
			t.Fatalf("working directory %q, want %q", first, real)
		}
		if strings.Contains(seen, "hunter2-credential") || strings.Contains(seen, "ghp_ambient") {
			t.Fatalf("the server's environment reached the tool:\n%s", seen)
		}
		allowed := map[string]bool{"PATH": true, "HOME": true, "TMPDIR": true, "XDG_CACHE_HOME": true, "LANG": true, "NO_COLOR": true, "PWD": true, "SHLVL": true, "_": true, "OLDPWD": true}
		var home string
		for _, line := range strings.Split(seen, "\n")[1:] {
			if k, v, ok := strings.Cut(line, "="); ok && !strings.HasPrefix(line, "tmp=") && !strings.HasPrefix(line, "homedir=") {
				if !allowed[k] {
					t.Errorf("unexpected variable %q in the tool's environment", k)
				}
				if k == "HOME" {
					home = v
				}
			}
		}
		if home == "" || home == os.Getenv("HOME") {
			t.Fatalf("HOME must be a private directory, got %q", home)
		}
		if _, err := os.Stat(home); err == nil {
			t.Fatalf("the tool's home %s outlived the run", home)
		}
	})
	t.Run("what a tool prints is cut at 8 MiB", func(t *testing.T) {
		bin := fakeTool(t, "dd if=/dev/zero bs=1000 count=8400 2>/dev/null | tr '\\0' 'x'\n")
		out, err := (&ExecTool{Bin: bin}).run(ctx, t.TempDir())
		if err != nil || len(out) != 8<<20 {
			t.Fatalf("output %d bytes (want %d), err %v", len(out), 8<<20, err)
		}
	})
	t.Run("a write that straddles the cap is cut at it and still reported whole", func(t *testing.T) {
		var buf bytes.Buffer
		w := &limitedWriter{w: &buf, n: 10}
		for i, c := range []struct{ in, wrote, held int }{{6, 6, 6}, {8, 8, 10}, {5, 5, 10}, {3, 3, 10}} {
			n, err := w.Write(bytes.Repeat([]byte{'x'}, c.in))
			if err != nil || n != c.wrote || buf.Len() != c.held {
				t.Fatalf("write %d of %d bytes: returned %d (%v), holding %d, want %d and %d", i, c.in, n, err, buf.Len(), c.wrote, c.held)
			}
		}
	})
	t.Run("a tool that outlives its timeout is stopped and the error says so", func(t *testing.T) {
		bin := fakeTool(t, "exec sleep 30\n")
		_, err := (&ExecTool{Bin: bin, Timeout: 200 * time.Millisecond}).run(ctx, t.TempDir())
		if err == nil || err.Error() != "timed out after 200ms" {
			t.Fatalf("timeout error: %v", err)
		}
		got := runGitleaks(ctx, &ExecTool{Bin: bin, Timeout: 200 * time.Millisecond}, t.TempDir(), nil)
		if len(got) != 1 || got[0].Scanner != "S2/tool-error" || got[0].Detail["error"] != "timed out after 200ms" {
			t.Fatalf("a timeout is a tool-error finding: %+v", got)
		}
	})
	t.Run("a tool that is not there is a tool-error finding", func(t *testing.T) {
		got := runGitleaks(ctx, &ExecTool{Bin: filepath.Join(t.TempDir(), "gone")}, t.TempDir(), nil)
		if len(got) != 1 || got[0].Scanner != "S2/tool-error" {
			t.Fatalf("a missing binary: %+v", got)
		}
	})
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
	// What a finding says: the redacted match (not the secret field, not the
	// raw line), the rule's description for a title, the rule and entropy in
	// the detail, and the severity the gate holds secrets at.
	if got[1].Excerpt != "AKI******" || got[0].Excerpt != "api_key = 'abc******'" {
		t.Fatalf("excerpts: %q, %q", got[1].Excerpt, got[0].Excerpt)
	}
	if got[1].Title != "Possible secret (gitleaks): AWS Access Key" || got[0].Title != "Possible secret (gitleaks): Generic API Key" {
		t.Fatalf("titles: %q, %q", got[1].Title, got[0].Title)
	}
	if got[1].Detail["tool"] != "gitleaks" || got[1].Detail["rule"] != "aws-access-token" || got[1].Detail["entropy"] != 3.5 {
		t.Fatalf("detail: %v", got[1].Detail)
	}
	if got[0].Detail["corroborates"] != nil || got[0].LineStart != 9 {
		t.Fatalf("a line the native rules did not flag is not corroborated: %v at line %d", got[0].Detail, got[0].LineStart)
	}
	if got[1].Confidence != ConfHigh || len(got[1].Taxonomy) != 1 || got[1].Taxonomy[0] != "LLM03" || got[1].LineStart != 3 || got[1].LineEnd != 3 {
		t.Fatalf("finding: %+v", got[1])
	}

	// A report is read in file, line, rule order; a line whose end is missing
	// ends where it starts; a title falls back to the rule id; and the rule id
	// becomes the lower-case [a-z0-9-] vocabulary of a scanner id.
	t.Run("ordering, line ends, titles and ids", func(t *testing.T) {
		bin := fakeTool(t, `
for a in "$@"; do last="$a"; done
cat > "$last" <<'JSON'
[
 {"RuleID":"rule-b","Description":"  ","File":"b.txt","StartLine":1,"EndLine":0,"Match":"secretvalue1","Entropy":1},
 {"RuleID":"Generic_API.Key","File":"a.txt","StartLine":9,"EndLine":9,"Match":"secretvalue2","Entropy":1},
 {"RuleID":"rule-z","File":"a.txt","StartLine":3,"EndLine":3,"Match":"secretvalue3","Entropy":1},
 {"RuleID":"rule-y","File":"a.txt","StartLine":3,"EndLine":3,"Match":"secretvalue4","Entropy":1},
 {"RuleID":"rule-x","File":"a.txt","StartLine":3,"EndLine":3,"Match":"secretvalue5","Entropy":1}
]
JSON
`)
		got := runGitleaks(context.Background(), &ExecTool{Bin: bin}, t.TempDir(), nil)
		var order []string
		for _, f := range got {
			order = append(order, fmt.Sprintf("%s:%d:%s", f.FilePath, f.LineStart, f.Scanner))
		}
		want := "a.txt:3:S2/gitleaks-rule-x a.txt:3:S2/gitleaks-rule-y a.txt:3:S2/gitleaks-rule-z a.txt:9:S2/gitleaks-generic-api-key b.txt:1:S2/gitleaks-rule-b"
		if strings.Join(order, " ") != want {
			t.Fatalf("order\n got %s\nwant %s", strings.Join(order, " "), want)
		}
		last := got[4]
		if last.LineEnd != 1 || last.Title != "Possible secret (gitleaks): rule-b" {
			t.Fatalf("a hit with no end line and a blank description: %+v", last)
		}
	})
	t.Run("paths", func(t *testing.T) {
		dir := t.TempDir()
		bin := fakeTool(t, `
for a in "$@"; do last="$a"; done
cat > "$last" <<JSON
[
 {"RuleID":"r1","File":"$PWD/abs/in.txt","StartLine":1,"EndLine":1,"Match":"secretvalue1"},
 {"RuleID":"r2","File":"/elsewhere/out.txt","StartLine":2,"EndLine":2,"Match":"secretvalue2"},
 {"RuleID":"r3","File":"  ./padded.txt ","StartLine":3,"EndLine":3,"Match":"secretvalue3"}
]
JSON
`)
		real, _ := filepath.EvalSymlinks(dir)
		got := runGitleaks(context.Background(), &ExecTool{Bin: bin}, real, nil)
		var paths []string
		for _, f := range got {
			paths = append(paths, f.FilePath)
		}
		sort.Strings(paths)
		if strings.Join(paths, " ") != "/elsewhere/out.txt abs/in.txt padded.txt" {
			t.Fatalf("paths: %v", paths)
		}
	})
	t.Run("a report of 600 hits is held to 500", func(t *testing.T) {
		var sb strings.Builder
		sb.WriteString("[")
		for i := 0; i < 600; i++ {
			if i > 0 {
				sb.WriteString(",")
			}
			fmt.Fprintf(&sb, `{"RuleID":"r","File":"f%04d.txt","StartLine":1,"EndLine":1,"Match":"secretvalue%d"}`, i, i)
		}
		sb.WriteString("]")
		src := filepath.Join(t.TempDir(), "report.json")
		if err := os.WriteFile(src, []byte(sb.String()), 0o600); err != nil {
			t.Fatal(err)
		}
		bin := fakeTool(t, `for a in "$@"; do last="$a"; done; cp `+src+` "$last"`)
		got := runGitleaks(context.Background(), &ExecTool{Bin: bin}, t.TempDir(), nil)
		if len(got) != 500 || got[499].FilePath != "f0499.txt" {
			t.Fatalf("%d findings, last %q", len(got), got[len(got)-1].FilePath)
		}
	})
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
	blank := fakeTool(t, `for a in "$@"; do last="$a"; done; printf ' \n\t\n' > "$last"`)
	if got := runGitleaks(context.Background(), &ExecTool{Bin: blank}, t.TempDir(), nil); len(got) != 0 {
		t.Fatalf("a report of blanks must yield nothing: %+v", got)
	}

	// The finding says what failed and that the built-in rules still ran, and
	// is held at medium for the gate.
	f := got[0]
	if f.Scanner != "S2/tool-error" || f.Severity != SevMedium || f.Confidence != ConfHigh || f.Title != "Secret scan incomplete" {
		t.Fatalf("tool-error finding: %+v", f)
	}
	if f.Detail["tool"] != "gitleaks" || f.Detail["error"] != "exit status 3: boom" || f.Detail["note"] != "The built-in secret rules still ran." {
		t.Fatalf("detail: %v", f.Detail)
	}
	if len(f.Taxonomy) != 1 || f.Taxonomy[0] != "LLM03" {
		t.Fatalf("taxonomy: %v", f.Taxonomy)
	}

	// The tool's words are its first line, bounded at 200 bytes with an ellipsis.
	errorOf := func(script string) string {
		t.Helper()
		got := runGitleaks(context.Background(), &ExecTool{Bin: fakeTool(t, script)}, t.TempDir(), nil)
		if len(got) != 1 {
			t.Fatalf("findings: %+v", got)
		}
		return got[0].Detail["error"].(string)
	}
	if e := errorOf("exit 5\n"); e != "exit status 5" {
		t.Fatalf("no stderr: %q", e)
	}
	if e := errorOf("echo first >&2; echo second >&2; exit 3\n"); e != "exit status 3: first" {
		t.Fatalf("two lines of stderr: %q", e)
	}
	if e := errorOf("printf '%0200d' 0 >&2; exit 3\n"); e != "exit status 3: "+strings.Repeat("0", 200) {
		t.Fatalf("a line of exactly 200 bytes is whole: %q", e)
	}
	if e := errorOf("printf '%0201d' 0 >&2; exit 3\n"); e != "exit status 3: "+strings.Repeat("0", 200)+"\u2026" {
		t.Fatalf("a line of 201 bytes is cut: %q", e)
	}
	if e := errorOf(`for a in "$@"; do last="$a"; done; echo '{not json' > "$last"`); !strings.HasPrefix(e, "report: ") {
		t.Fatalf("an unparseable report: %q", e)
	}
	if e := errorOf(`for a in "$@"; do last="$a"; done; rm -f "$last"`); !strings.Contains(e, "no such file") {
		t.Fatalf("a report that is not there: %q", e)
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
// Rules path.
func TestRunGitleaksAlwaysPassesTheRegistrysConfig(t *testing.T) {
	argsFile := filepath.Join(t.TempDir(), "args")
	cfgCopy := filepath.Join(t.TempDir(), "config-as-read")
	bin := fakeTool(t, `printf '%s\n' "$@" > `+argsFile+`
prev=""; for a in "$@"; do if [ "$prev" = "--config" ]; then cp "$a" `+cfgCopy+`; fi; prev="$a"; done
for a in "$@"; do last="$a"; done; : > "$last"`)
	_ = runGitleaks(context.Background(), &ExecTool{Bin: bin}, t.TempDir(), nil)
	if mustRead(t, cfgCopy) != string(gitleaksConfig) {
		t.Fatalf("the file passed as --config is not the embedded configuration: %q", mustRead(t, cfgCopy))
	}
	args := strings.Split(strings.TrimSpace(mustRead(t, argsFile)), "\n")
	cfg := ""
	for i, a := range args {
		if a == "--config" && i+1 < len(args) {
			cfg = args[i+1]
		}
	}
	// The whole command line: the tree as files, no git history, no banner,
	// "leaks found" is not a crash, and the report as JSON at a path of ours.
	if len(args) != 13 {
		t.Fatalf("args = %v", args)
	}
	for i, want := range map[int]string{0: "detect", 1: "--no-git", 2: "--source", 3: ".", 4: "--no-banner", 5: "--config", 7: "--exit-code", 8: "0", 9: "--report-format", 10: "json", 11: "--report-path"} {
		if args[i] != want {
			t.Fatalf("argument %d = %q, want %q (all: %v)", i, args[i], want, args)
		}
	}
	if !strings.HasSuffix(args[12], ".json") {
		t.Fatalf("report path %q", args[12])
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
	if mustRead(t, cfgCopy) != "[extend]\nuseDefault = true\n" {
		t.Fatalf("the operator's rules were not read as given: %q", mustRead(t, cfgCopy))
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

// A documented placeholder is not a secret:
// a security QuickAgent's proof-of-concept command line, and the
// template markers documentation uses, are dropped; a value with no marker
// is still reported, whatever host sits beside it on the line.
func TestRunGitleaksSkipsDocumentedPlaceholders(t *testing.T) {
	// The credential-shaped value and the "-u" gitleaks' curl-auth-user rule
	// reads after "curl" are put in at run time, so the repository's own
	// gitleaks job does not read the test as a leak.
	pw := strings.Join([]string{"Tr0ub", "4dor3x"}, "")
	bin := fakeTool(t, strings.ReplaceAll(strings.ReplaceAll(`
for a in "$@"; do last="$a"; done
cat > "$last" <<'JSON'
[
 {"RuleID":"curl-auth-user","File":"skills/sast-sqli/SKILL.md","StartLine":457,"EndLine":458,"Match":"curl payload. Show parameter ... sqlmap DASHU \"https://app.example.com/search?q=test\"","Secret":"https://app.example.com/search?q=test","Entropy":4.0},
 {"RuleID":"curl-auth-user","File":"a.md","StartLine":2,"EndLine":2,"Match":"curl DASHU <user>:<password> https://api.github.com","Secret":"<user>:<password>","Entropy":3.0},
 {"RuleID":"generic-api-key","File":"b.md","StartLine":3,"EndLine":3,"Match":"api_key = ${API_KEY}","Secret":"${API_KEY}","Entropy":3.0},
 {"RuleID":"curl-auth-user","File":"c.md","StartLine":4,"EndLine":4,"Match":"curl DASHU admin:PW https://app.example.com","Secret":"admin:PW","Entropy":3.6},
 {"RuleID":"aws-access-token","File":"d.md","StartLine":5,"EndLine":5,"Match":"AKIAIOSFODNN7EXAMPLE","Entropy":3.5},
 {"RuleID":"generic-api-key","File":"e.md","StartLine":6,"EndLine":6,"Match":"api_key = ${API_KEY}","Entropy":3.0}
]
JSON
`, "PW", pw), "DASHU", "-"+"u"))
	got := runGitleaks(context.Background(), &ExecTool{Bin: bin}, t.TempDir(), nil)
	var files []string
	for _, f := range got {
		files = append(files, f.FilePath)
	}
	if len(got) != 2 || got[0].FilePath != "c.md" || got[1].FilePath != "d.md" {
		t.Fatalf("kept %v, want [c.md d.md]", files)
	}
}

func TestDocumentedPlaceholder(t *testing.T) {
	for v, want := range map[string]bool{
		"https://app.example.com/search?q=test": true,
		"<user>:<password>":                     true,
		"${API_KEY}":                            true,
		"$GITHUB_TOKEN":                         true,
		"your_api_key":                          true,
		"sk_test_xxxxxxxxxxxxxxxx":              true,
		"admin:Tr0ub4dor3x":                     false,
		"pa$sword-Q9vT2mLx":                     false,
		"AKIAIOSFODNN7EXAMPLE":                  false,
		"":                                      false,

		// Each kind of marker documentation uses, alone.
		"db.internal.example":     true, // reserved top-level names
		"svc.invalid":             true,
		"api.test":                true,
		"localhost:8080":          true,
		"{{ secrets.TOKEN }}":     true, // template forms
		"%API_KEY%":               true,
		"[token goes here]":       true,
		"my_password":             true, // a word that says it is not real
		"my-token":                true,
		"example":                 true,
		"placeholder":             true,
		"changeme":                true,
		"redacted":                true,
		"dummy":                   true,
		"sk-****":                 true,
		"***":                     true,
		"HTTPS://APP.EXAMPLE.COM": true, // markers are matched in any case
		"YOUR_API_KEY":            true,

		// Case matters for the shell-variable forms, so a value that only
		// looks like one is not a marker; nor is three x's, or a lower-case
		// variable.
		"$secretvalue": false,
		"%api_key%":    false,
		"abcxxxdef":    false,
		"**":           false,

		// What is left once the markers are taken out is judged by runs of
		// eight letters and digits with the entropy of a secret.
		"<x>Zq8vR2m":            true,  // a run of seven is not a secret
		"<x>Zq8vR2mT":           false, // a run of eight is
		"<x>aaabbcde":           true,  // eight characters at about 2.2 bits
		"<x>aabbcdef":           false, // at exactly 2.5 bits
		"<x>aaaaaaaa":           true,  // no entropy at all
		"abcd<x>efgh":           true,  // the marker separates what is left
		"<x> aaaaaaaa Zq8vR2mT": false, // every run is judged, not the first
	} {
		if got := documentedPlaceholder(v); got != want {
			t.Errorf("documentedPlaceholder(%q) = %v, want %v", v, got, want)
		}
	}
}

// A placeholder beside a real value does not hide it:
// gitleaks' curl-auth-user Secret is "user:pass".
func TestDocumentedPlaceholderNeedsTheWholeValue(t *testing.T) {
	// Credential-shaped values are built at run time, so the repository's
	// own gitleaks job does not read the test as a leak.
	real := strings.Join([]string{"Zq8vR2mT", "9pL4xW7c"}, "")
	for v, want := range map[string]bool{
		"your_username:<password>":                        true,
		"your_username:" + real:                           false,
		"example:" + real:                                 false,
		"https://app.example.com/?key=" + real:            false,
		real + "localhost":                                false,
		"[REDACTED]":                                      true,
		"https://api.example.com/v1/search?q=test&page=2": true,
		"sk_live_" + strings.Repeat("x", 24):              true,
		"sk_live_" + real + real + "xxxx":                 false,
	} {
		if got := documentedPlaceholder(v); got != want {
			t.Errorf("documentedPlaceholder(%q) = %v, want %v", v, got, want)
		}
	}
}
