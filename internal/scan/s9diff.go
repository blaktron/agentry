package scan

import (
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Masterminds/semver/v3"
	"golang.org/x/net/publicsuffix"

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

// How a destination was written in package content.
const (
	egressKindURL   = string(rules.DestinationURL)
	egressKindEmail = string(rules.DestinationEmail)
	egressKindIP    = string(rules.DestinationIP)
	egressKindHost  = string(rules.DestinationHost)
)

// egressTarget is one destination referenced by package content.
type egressTarget struct {
	// Kind is how the target was written: egressKindURL, egressKindEmail,
	// egressKindIP or egressKindHost.
	Kind string
	// File and Line locate the first occurrence.
	File string
	Line int
	// Excerpt is the surrounding text.
	Excerpt string
}

// extractEgressTargets finds every destination a set of files references:
// URLs, email recipients, IPv4 addresses and bare host names. It is the
// content-level twin of the manifest's declared `capabilities.network.egress`,
// and the input to S9's "newly added egress hosts/URLs anywhere in content"
// check.
//
// The grammar is pkg/rules' (rules.Destinations), the one S4's rating by
// declaration reads, so a URL ends where a browser's authority ends and a
// Markdown backtick or bracket is never part of a host (agentry#958). A bare
// name is held to bareDestination as well, because without a scheme a host
// and a file name or a code identifier look alike.
//
// The map is keyed by the normalized target so a host written as a URL in one
// release and as a bare string in the next still compares equal.
func extractEgressTargets(files []FileEntry) map[string]egressTarget {
	out := map[string]egressTarget{}
	ownFiles := map[string]bool{}
	for _, f := range files {
		ownFiles[strings.ToLower(path.Base(f.Path))] = true
	}
	for _, f := range files {
		if !f.IsText || f.Content == nil {
			continue
		}
		code := isCodePath(f.Path)
		for i, line := range strings.Split(string(f.Content), "\n") {
			if isCommentLine(f.Path, line) {
				continue
			}
			for _, d := range rules.Destinations(line) {
				if out[d.Target].Kind != "" {
					continue
				}
				if d.Kind == rules.DestinationHost && !bareDestination(d.Target, line, code, ownFiles) {
					continue
				}
				out[d.Target] = egressTarget{Kind: string(d.Kind), File: f.Path, Line: i + 1, Excerpt: truncateStr(line, 160)}
			}
		}
	}
	return out
}

// fileLikeTLDs are top-level domains that are also the extensions of files
// a package's prose names all the time (README.md, inputs.zip, demo.mov). A
// bare two-label name ending in one is read as the file; with a subdomain,
// a scheme or an "@" it is still a destination.
var fileLikeTLDs = map[string]bool{"md": true, "zip": true, "mov": true}

// specialUseTLDs are the reserved names (RFC 2606, RFC 6761, RFC 6762) that
// no public suffix list carries but test fixtures and local services use.
var specialUseTLDs = map[string]bool{
	"example": true, "invalid": true, "test": true, "localhost": true, "local": true, "internal": true, "onion": true,
}

// bareDestination decides whether a bare dotted name (no scheme, no "@") in
// a line is a host. It replaces a hand-kept list of sixteen top-level domains
// that left webhook.site, interact.sh and every .me host out (agentry#958):
//   - its last label must be a top-level domain ICANN delegates, from the
//     public suffix list, or a special-use name, so config.yaml, main.go and
//     package.json are file names;
//   - a two-label name ending in a file-like TLD, or naming one of the
//     package's own files (deploy.sh, analyze.py beside it), is that file;
//   - in a code file it must sit inside a string literal: user.email or
//     self.name outside quotes is a field, not a destination.
//
// URLs, email addresses and IP addresses are destinations without these
// tests: a scheme or an "@" says what they are.
func bareDestination(host, line string, code bool, ownFiles map[string]bool) bool {
	labels := strings.Split(host, ".")
	tld := labels[len(labels)-1]
	if !specialUseTLDs[tld] {
		if _, icann := publicsuffix.PublicSuffix(tld); !icann {
			return false
		}
	}
	if len(labels) == 2 && (fileLikeTLDs[tld] || ownFiles[host]) {
		return false
	}
	if code && !inStringLiteral(strings.ToLower(line), host) {
		return false
	}
	return true
}

// stringLiteralRe finds a double-, single- or backtick-quoted literal.
var stringLiteralRe = regexp.MustCompile(`"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|` + "`[^`]*`")

// inStringLiteral reports whether host occurs inside a quoted literal of a
// (lower-cased) line of code.
func inStringLiteral(line, host string) bool {
	for _, lit := range stringLiteralRe.FindAllString(line, -1) {
		if strings.Contains(lit, host) {
			return true
		}
	}
	return false
}

// isCodePath reports whether a file is program source whose bare names are
// mostly identifiers (obj.field), so a host there must be quoted. Shell is
// not: a shell line names a host bare (curl webhook.site/x).
func isCodePath(p string) bool {
	switch strings.ToLower(filepath.Ext(p)) {
	case ".go", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".java", ".c", ".h", ".cpp", ".cc", ".rs", ".swift", ".kt", ".cs", ".php", ".scala", ".py", ".rb":
		return true
	}
	return false
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
