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

// Release-diff helpers for S9. S9's job is to compare THIS version's
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

// egressTarget is one destination referenced by package content.
type egressTarget struct {
	// Kind is how the target was written.
	Kind rules.DestinationKind
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
// declaration reads, so the two agree on what a URL reaches. A
// bare name is held to isBareDestination as well, because without a scheme a
// host, a file name and a code identifier look alike.
//
// The map is keyed by the normalized target so a host written as a URL in one
// release and as a bare string in the next still compares equal.
func extractEgressTargets(files []FileEntry) map[string]egressTarget {
	out := map[string]egressTarget{}
	for _, f := range files {
		if !f.IsText || f.Content == nil {
			continue
		}
		code, markdown := isCodePath(f.Path), isProsePath(f.Path)
		open := ""     // the delimiter of a multi-line string open at a line's start
		fence := false // inside a Markdown fenced code block
		for i, line := range strings.Split(string(f.Content), "\n") {
			// Inside a multi-line string, or on a line that opens or closes
			// one, a line of code is text: its bare names count as in prose.
			// A Markdown fence's lines are code, and so is its fence line.
			next := multilineString(open, line)
			prose := !code || open != "" || next != open
			open = next
			if markdown && strings.HasPrefix(strings.TrimSpace(line), "```") {
				fence = !fence
				prose = false
			}
			if fence {
				prose = false
			}
			if isCommentLine(f.Path, line) {
				continue
			}
			lower := strings.ToLower(line)
			for _, d := range rules.Destinations(line) {
				if out[d.Target].Kind != "" {
					continue
				}
				if d.Kind == rules.DestinationHost && !isBareDestination(d.Target, lower, prose, markdown) {
					continue
				}
				out[d.Target] = egressTarget{Kind: d.Kind, File: f.Path, Line: i + 1, Excerpt: truncateStr(line, 160)}
			}
		}
	}
	return out
}

// Top-level domains that are also the extensions of files a package names
// all the time. A bare two-label name under an archive-like one (README.md, Main.java,
// app.zip/src/Main.java, demo.mov) is that file; under a script-like one
// (deploy.sh, main.py) it is a host only when a path follows it
// (interact.sh/x). With a subdomain, a scheme or an "@" either is a host.
// The lists are fixed rather than drawn from the package, whose file names
// its author chooses.
var (
	archiveLikeTLDs = map[string]bool{"md": true, "zip": true, "mov": true, "java": true}
	scriptLikeTLDs  = map[string]bool{"sh": true, "py": true, "pl": true, "pm": true, "rs": true, "so": true}
)

// specialUseTLDs are the reserved names (RFC 2606, RFC 6761, RFC 6762) that
// no public suffix list carries but test fixtures and local services use.
var specialUseTLDs = map[string]bool{
	"example": true, "invalid": true, "test": true, "localhost": true, "local": true, "internal": true, "onion": true,
}

// codeSpanRe finds a Markdown inline code span.
var codeSpanRe = regexp.MustCompile("`[^`]+`")

// isBareDestination decides whether a bare dotted name (no scheme, no "@")
// in a lower-cased line is a host:
//   - its last label must be a top-level domain ICANN delegates, from the
//     public suffix list, or a special-use name, so config.yaml, main.go and
//     package.json are file names;
//   - a two-label name under an archive-like TLD is never a host, and under
//     a script-like one only with a path after it;
//   - in code it must sit inside a string literal or have a path after it.
//     Code is program source outside a multi-line string (prose false), and
//     in Markdown a fenced block or an inline code span (`window.name`,
//     `request.post(...)`, `req.query.host`), where many delegated TLDs are
//     ordinary words (.name, .post, .host, .read, .java, .properties).
//
// URLs, email addresses and IP addresses are destinations without these
// tests: a scheme, an "@" or the digits say what they are.
func isBareDestination(host, line string, prose, markdown bool) bool {
	labels := strings.Split(host, ".")
	tld := labels[len(labels)-1]
	if !specialUseTLDs[tld] {
		if _, icann := publicsuffix.PublicSuffix(tld); !icann {
			return false
		}
	}
	path := followedByPath(line, host)
	if len(labels) == 2 && (archiveLikeTLDs[tld] || scriptLikeTLDs[tld] && !path) {
		return false
	}
	if prose && markdown && !strings.Contains(codeSpanRe.ReplaceAllString(line, " "), host) {
		prose = false // only inside code spans
	}
	if prose || path || inStringLiteral(line, host, !markdown) {
		return true
	}
	// Markdown's code is about hosts as often as identifiers (`crates.io`,
	// `gmail.googleapis.com`): there a name under a TLD hosts are usually
	// under counts too, and one under a word TLD (.read, .post) does not.
	return markdown && hostLikeTLD(tld)
}

// commonHostTLDs are the generic top-level domains most hosts are under.
var commonHostTLDs = map[string]bool{
	"com": true, "net": true, "org": true, "io": true, "dev": true, "ai": true, "co": true, "app": true,
	"cloud": true, "xyz": true, "edu": true, "gov": true,
}

// identifierCCTLDs are country codes that are also common field names
// (user.id, path.to, x.is, a.in, it, at, do).
var identifierCCTLDs = map[string]bool{"id": true, "to": true, "is": true, "in": true, "it": true, "at": true, "do": true}

// hostLikeTLD reports whether tld is one a dotted name in Markdown's code
// is a host under: a common generic one, a country code that is not also a
// field name, or a special-use name.
func hostLikeTLD(tld string) bool {
	return commonHostTLDs[tld] || specialUseTLDs[tld] || len(tld) == 2 && !identifierCCTLDs[tld]
}

// followedByPath reports whether host occurs in line directly before a "/",
// as a destination's path is written and a file name is not. A port is no
// evidence: "agent.md:12" is a file and a line.
func followedByPath(line, host string) bool {
	for i := 0; ; {
		j := strings.Index(line[i:], host)
		if j < 0 {
			return false
		}
		if strings.HasPrefix(line[i+j+len(host):], "/") {
			return true
		}
		i += j + len(host)
	}
}

// stringLiteralRe finds a double- or single-quoted literal, and
// backtickLiteralRe a backtick-quoted one: a string in program source, but
// in Markdown the code span itself.
var (
	stringLiteralRe   = regexp.MustCompile(`"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`)
	backtickLiteralRe = regexp.MustCompile("`[^`]*`")
)

// inStringLiteral reports whether host occurs inside a quoted literal of a
// (lower-cased) line; backtick-quoted ones count when backticks quote
// strings, as in program source and not in Markdown.
func inStringLiteral(line, host string, backticks bool) bool {
	lits := stringLiteralRe.FindAllString(line, -1)
	if backticks {
		lits = append(lits, backtickLiteralRe.FindAllString(line, -1)...)
	}
	for _, lit := range lits {
		if strings.Contains(lit, host) {
			return true
		}
	}
	return false
}

// multiDelims open a string that can span lines: Python's triple quotes, a
// JavaScript template literal, a Go raw string.
var multiDelims = []string{`"""`, "'''", "`"}

// multilineString is the delimiter of the multi-line string still open after
// line, given the one open before it ("" for none). An odd count of the
// open delimiter closes it; with none open, an odd count of one opens it.
func multilineString(open, line string) string {
	if open != "" {
		if strings.Count(line, open)%2 == 1 {
			return ""
		}
		return open
	}
	for _, d := range multiDelims {
		if strings.Count(line, d)%2 == 1 {
			return d
		}
	}
	return ""
}

// The extensions whose comment lines start with "//" or "#". A file with
// neither is prose to isCommentLine, and every line of it is read.
var (
	slashCommentExts = map[string]bool{
		".go": true, ".js": true, ".mjs": true, ".cjs": true, ".ts": true, ".tsx": true, ".jsx": true, ".java": true,
		".c": true, ".h": true, ".cpp": true, ".cc": true, ".rs": true, ".swift": true, ".kt": true, ".cs": true,
		".php": true, ".scala": true,
	}
	hashCommentExts = map[string]bool{
		".yaml": true, ".yml": true, ".toml": true, ".ini": true, ".cfg": true, ".conf": true, ".sh": true,
		".bash": true, ".zsh": true, ".py": true, ".rb": true, ".env": true, ".properties": true, ".dockerfile": true,
	}
)

// isCodePath reports whether a file is program source, whose bare dotted
// names are mostly identifiers (obj.field), so a host there must be quoted.
// Configuration and shell are not: they name a host bare (host: x.example,
// curl webhook.site/x).
func isCodePath(p string) bool {
	ext := strings.ToLower(filepath.Ext(p))
	return slashCommentExts[ext] || ext == ".py" || ext == ".rb"
}

// isCommentLine reports whether a line is a comment in a file the machine
// reads rather than the agent: a `#` line in YAML, TOML, shell or Python, a
// `//` line in code. A destination named only in such a comment is not one
// the package can reach, and the CLI's own scaffold carries a commented
// `# egress: [host]` example that would otherwise send every first publish
// to review. Prose files (markdown, plain text) are not comment-aware:
// an agent reads all of them.
func isCommentLine(path, line string) bool {
	t := strings.TrimSpace(line)
	if t == "" {
		return false
	}
	ext := strings.ToLower(filepath.Ext(path))
	switch {
	case hashCommentExts[ext]:
		return strings.HasPrefix(t, "#")
	case slashCommentExts[ext]:
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
// This re-scan keeps S9 from raising every
// current S3/S4/install-script medium to high whenever any previous version
// exists: a package with one long-standing postinstall hook would be escalated
// on every single release forever, and the escalation would carry no information
// about the diff it claims to describe.
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
