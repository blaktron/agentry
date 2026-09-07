package scan

import (
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Masterminds/semver/v3"

	"github.com/blaktron/agentry/pkg/rules"
)

// Release-diff helpers for S9 (§8.3). S9's job is to compare THIS version's
// content against the previous published version's, because the documented
// dominant real-world shape is a package that was clean for fifteen releases
// and malicious in the sixteenth (postmark-mcp). Diffing manifests alone
// misses it entirely: the postmark change was one line of code and one host in
// prose, with no manifest edit at all.

// bumpSize classifies the version step between two semver strings.
// "unknown" covers unparsable versions on either side — S9 then treats the
// bump as if it were minor rather than assuming the least alarming case.
func bumpSize(prev, cur string) string {
	p, perr := semver.NewVersion(strings.TrimPrefix(prev, "v"))
	c, cerr := semver.NewVersion(strings.TrimPrefix(cur, "v"))
	if perr != nil || cerr != nil {
		return "unknown"
	}
	switch {
	case c.Major() != p.Major():
		return "major"
	case c.Minor() != p.Minor():
		return "minor"
	case c.Patch() != p.Patch():
		return "patch"
	}
	return "none"
}

// emailRe matches an address well enough to recover its domain. S9 wants
// recipients, not RFC 5322 conformance: the postmark line that started the
// incident was a hardcoded BCC address.
var emailRe = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)

// bareHostRe matches a hostname appearing without a scheme, as it does inside
// a client constructor or a config string.
var bareHostRe = regexp.MustCompile(`\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.){1,}(?:com|net|org|io|dev|ai|co|app|cloud|xyz|ru|cn|invalid|example|test|local)\b`)

// egressTarget is one destination referenced by package content.
type egressTarget struct {
	// Kind is how the target was written ("url", "email", "host").
	Kind string
	// File and Line locate the first occurrence.
	File string
	Line int
	// Excerpt is the surrounding text.
	Excerpt string
}

// extractEgressTargets finds every destination a set of files references:
// URLs, email recipients, and bare hostnames. It is the content-level twin of
// the manifest's declared `capabilities.network.egress`, and the input to
// S9's "newly added egress hosts/URLs anywhere in content" check.
//
// The map is keyed by the normalized target so a host written as a URL in one
// release and as a bare string in the next still compares equal.
func extractEgressTargets(files []FileEntry) map[string]egressTarget {
	out := map[string]egressTarget{}
	record := func(key, kind, file string, line int, excerpt string) {
		key = strings.ToLower(strings.TrimSuffix(key, "."))
		if key == "" || out[key].Kind != "" {
			return
		}
		out[key] = egressTarget{Kind: kind, File: file, Line: line, Excerpt: truncateStr(excerpt, 160)}
	}
	for _, f := range files {
		if !f.IsText || f.Content == nil {
			continue
		}
		for i, line := range strings.Split(string(f.Content), "\n") {
			if isCommentLine(f.Path, line) {
				continue
			}
			for _, u := range urlRe.FindAllString(line, -1) {
				record(urlHost(u), "url", f.Path, i+1, line)
			}
			for _, a := range emailRe.FindAllString(line, -1) {
				record(a, "email", f.Path, i+1, line)
			}
			for _, h := range bareHostRe.FindAllString(strings.ToLower(line), -1) {
				record(h, "host", f.Path, i+1, line)
			}
		}
	}
	return out
}

// isCommentLine reports whether a line is a comment in a file the machine
// reads rather than the agent: a `#` line in YAML, TOML, shell or Python, a
// `//` line in code. A destination named only in such a comment is not one
// the package can reach, and the CLI's own scaffold carries a commented
// `# egress: [host]` example that sent every first publish to review
// (agentry#223). Prose files (markdown, plain text) are not comment-aware:
// an agent reads all of them.
func isCommentLine(path, line string) bool {
	t := strings.TrimSpace(line)
	if t == "" {
		return false
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".sh", ".bash", ".zsh", ".py", ".rb", ".env", ".properties", ".dockerfile":
		return strings.HasPrefix(t, "#")
	case ".go", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".java", ".c", ".h", ".cpp", ".cc", ".rs", ".swift", ".kt", ".cs", ".php", ".scala":
		return strings.HasPrefix(t, "//")
	}
	return false
}

// urlHost returns the host component of a URL string.
func urlHost(u string) string {
	rest := strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
	if i := strings.IndexAny(rest, "/:?#"); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.Index(rest, "@"); i >= 0 { // userinfo
		rest = rest[i+1:]
	}
	return strings.ToLower(rest)
}

// findingKey identifies a finding across releases: the detector plus the file
// it fired on. Keying on the file (rather than the detector alone) means a
// payload that moves to a new file still reads as newly introduced — the
// fail-safe direction — while a rule that has fired on the same file since
// before this release does not re-escalate on every publish.
func findingKey(f Finding) string { return f.Scanner + "\x00" + f.FilePath }

// baselineFindings re-runs the deterministic content detectors over the
// PREVIOUS version's files, so S9 can tell "this package has always had an
// install script" from "this release added one".
//
// This re-scan is the fix for an escalation bug: S9 used to raise every
// current S3/S4/install-script medium to high whenever any previous version
// existed, so a package with one long-standing postinstall hook was escalated
// on every single release forever, and the escalation carried no information
// about the diff it claimed to describe.
func baselineFindings(bundle *rules.Bundle, prevFiles []FileEntry) map[string]bool {
	out := map[string]bool{}
	if len(prevFiles) == 0 {
		return out
	}
	for _, rf := range rules.Scan(bundle, toRuleFiles(prevFiles)) {
		out[findingKey(fromRules(rf))] = true
	}
	return out
}

// proseDelta measures how much instruction text changed between two file sets.
// It compares the union of prose files line-by-line as multisets: the returned
// ratio is (lines added + lines removed) / (previous prose lines), so a
// rewritten README scores near or above 1 while a typo fix scores near 0.
//
// Line sets rather than a real diff because the question is "how much of the
// instruction surface is new", not "what exactly changed" — and because a
// reordering that keeps every line is not an instruction rewrite.
func proseDelta(prev, cur []FileEntry) (ratio float64, changed, base int) {
	prevLines := proseLineCounts(prev)
	curLines := proseLineCounts(cur)
	for line, n := range curLines {
		if d := n - prevLines[line]; d > 0 {
			changed += d
		}
	}
	for line, n := range prevLines {
		base += n
		if d := n - curLines[line]; d > 0 {
			changed += d
		}
	}
	if base == 0 {
		if changed > 0 {
			return 1, changed, 0
		}
		return 0, 0, 0
	}
	return float64(changed) / float64(base), changed, base
}

// proseLineCounts counts non-blank lines across prose files.
func proseLineCounts(files []FileEntry) map[string]int {
	out := map[string]int{}
	for _, f := range files {
		if !f.IsText || f.Content == nil || !isProsePath(f.Path) {
			continue
		}
		for _, line := range strings.Split(string(f.Content), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				out[line]++
			}
		}
	}
	return out
}

// isProsePath reports whether a file carries instruction text (the surface S4
// and S5 read). Mirrors pkg/rules' prose extension list.
func isProsePath(p string) bool {
	switch strings.ToLower(path.Ext(p)) {
	case ".md", ".markdown", ".txt", ".text", "":
		return true
	}
	return false
}
