package scan

import (
	"fmt"
	"regexp"
	"strings"
)

// Obfuscated string-assembly detection for S6 (§8.3 S6 lists "obfuscated
// string assembly" alongside the capability detectors).
//
// The capability detectors above match a literal `fetch(` or `eval(`. Every
// one of them is defeated by building the identifier or the destination out of
// pieces — `["fe","tch"].join("")`, `String.fromCharCode(101,118,97,108)`,
// `atob("...")`, `getattr(__builtins__, "e"+"val")`. The pieces are individually
// meaningless, which is the point: the detector has to notice the ASSEMBLY,
// not the result.
//
// Two independent signals, both required to fire together with a sink, keep
// this from flagging ordinary string concatenation: an assembly construct
// (char codes, base64 decode, a split/join of short fragments, a reversed
// string) and a dangerous sink on the same line or the next few.

// assemblyPattern is one obfuscated-construction signature.
type assemblyPattern struct {
	name string
	re   *regexp.Regexp
}

var jsAssembly = []assemblyPattern{
	{"char-codes", regexp.MustCompile(`String\.fromCharCode\s*\(\s*\d+\s*(?:,\s*\d+\s*){3,}\)`)},
	{"base64-decode", regexp.MustCompile(`\batob\s*\(|Buffer\.from\s*\([^)]*['"]base64['"]\s*\)`)},
	{"array-join", regexp.MustCompile(`\[\s*(?:['"][^'"]{1,4}['"]\s*,\s*){2,}['"][^'"]{1,4}['"]\s*\]\s*\.\s*(?:join|reduce)\s*\(`)},
	{"reverse", regexp.MustCompile(`\.split\s*\(\s*['"]{2}\s*\)\s*\.\s*reverse\s*\(\s*\)\s*\.\s*join\s*\(`)},
	{"hex-escape-run", regexp.MustCompile(`(?:\\x[0-9a-fA-F]{2}){6,}`)},
	{"unicode-escape-run", regexp.MustCompile(`(?:\\u00[0-9a-fA-F]{2}){6,}`)},
	{"fragment-concat", regexp.MustCompile(`['"][^'"]{1,4}['"]\s*\+\s*['"][^'"]{1,4}['"]\s*\+\s*['"][^'"]{1,4}['"]`)},
}

var pyAssembly = []assemblyPattern{
	{"char-codes", regexp.MustCompile(`(?:''|""|"" *)\.join\s*\(\s*(?:map\s*\(\s*chr|\[\s*chr)`)},
	{"chr-sequence", regexp.MustCompile(`(?:chr\s*\(\s*\d+\s*\)\s*\+\s*){3,}chr\s*\(\s*\d+\s*\)`)},
	{"base64-decode", regexp.MustCompile(`base64\.(?:b64decode|standard_b64decode|urlsafe_b64decode)\s*\(|codecs\.decode\s*\([^)]*['"](?:base64|rot_?13|hex)`)},
	{"reverse", regexp.MustCompile(`\[\s*::\s*-1\s*\]`)},
	{"hex-escape-run", regexp.MustCompile(`(?:\\x[0-9a-fA-F]{2}){6,}`)},
	{"fragment-concat", regexp.MustCompile(`['"][^'"]{1,4}['"]\s*\+\s*['"][^'"]{1,4}['"]\s*\+\s*['"][^'"]{1,4}['"]`)},
}

// dangerousSinks are the calls whose argument being assembled at runtime is
// what makes the assembly interesting.
var jsSinks = regexp.MustCompile(`\b(?:eval|Function|require|import|fetch|exec|execSync|spawn|spawnSync|writeFileSync)\s*\(|new\s+Function\s*\(`)
var pySinks = regexp.MustCompile(`\b(?:eval|exec|compile|__import__|getattr|system|popen|check_output|urlopen|run|Popen)\s*\(`)

// assemblyWindow is how many following lines still count as "feeding" a sink;
// obfuscators routinely build a string on one line and call it on the next.
const assemblyWindow = 3

// s6StringAssembly reports obfuscated string construction that feeds a
// dangerous sink.
func s6StringAssembly(in *Input) []Finding {
	var findings []Finding
	for _, f := range in.Files {
		if !f.IsText || f.Content == nil {
			continue
		}
		var pats []assemblyPattern
		var sinks *regexp.Regexp
		switch codeLanguage(f.Path) {
		case "js":
			pats, sinks = jsAssembly, jsSinks
		case "py":
			pats, sinks = pyAssembly, pySinks
		default:
			continue
		}
		lines := strings.Split(string(f.Content), "\n")
		reported := map[string]bool{}
		for i, line := range lines {
			if isCommentLine(line) {
				continue
			}
			for _, p := range pats {
				if !p.re.MatchString(line) || reported[p.name] {
					continue
				}
				if !sinkNearby(lines, i, sinks) {
					continue
				}
				reported[p.name] = true
				findings = append(findings, Finding{
					Scanner: "S6/obfuscated-assembly", Severity: SevHigh, Confidence: ConfMedium,
					Title:     "Obfuscated string assembly feeding a dynamic call: " + p.name,
					FilePath:  f.Path,
					LineStart: i + 1, LineEnd: i + 1,
					Excerpt: truncateStr(strings.TrimSpace(line), 160),
					Detail: map[string]any{
						"construct": p.name,
						"reason":    "the identifier or destination is built at runtime, defeating literal-string detection",
					},
					Taxonomy: []string{"LLM01", "ASI05"},
				})
			}
		}
	}
	return findings
}

// sinkNearby reports whether a dangerous call appears on the same line as the
// assembly or within the next few lines.
func sinkNearby(lines []string, i int, sinks *regexp.Regexp) bool {
	end := i + assemblyWindow
	if end >= len(lines) {
		end = len(lines) - 1
	}
	for j := i; j <= end; j++ {
		if sinks.MatchString(lines[j]) {
			return true
		}
	}
	return false
}

// codeLanguage maps a path to the detector family that understands it (D-14:
// JS/TS and Python are the only code kinds v1 accepts).
func codeLanguage(p string) string {
	switch strings.ToLower(extOf(p)) {
	case ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs":
		return "js"
	case ".py":
		return "py"
	}
	return ""
}

func extOf(p string) string {
	if i := strings.LastIndex(p, "."); i >= 0 {
		return p[i:]
	}
	return ""
}

// isCommentLine is the same best-effort comment skip the capability detectors
// use.
func isCommentLine(line string) bool {
	t := strings.TrimSpace(line)
	return strings.HasPrefix(t, "//") || strings.HasPrefix(t, "#")
}

// s6DeclaredUnused reports capabilities the manifest asks for that no code in
// the package appears to use (§8.3 S6: "Declared-but-unused = info (manifest
// hygiene)").
//
// Info severity, and deliberately so: the detectors are regex approximations,
// a capability may be exercised through a path they do not model, and over-
// declaration is a hygiene problem rather than an attack. It still belongs on
// the report — a manifest asking for `exec` it never uses is either stale or
// preparing the ground for a later release that does use it, and the reviewer
// comparing two versions is the person who can tell which.
func s6DeclaredUnused(declared map[string]bool, detected map[string][]detection) []Finding {
	var findings []Finding
	for _, capToken := range sortedSet(declared) {
		if len(detected[capToken]) > 0 {
			continue
		}
		// fs-read is satisfied by a declared fs-write in declaredHas; keep the
		// two consistent so a package that declares write and only reads is
		// not reported as unused.
		if capToken == "fs-read" && len(detected["fs-write"]) > 0 {
			continue
		}
		if capToken == "fs-write" && len(detected["fs-read"]) > 0 {
			continue
		}
		findings = append(findings, Finding{
			Scanner: "S6/declared-unused-" + capToken, Severity: SevInfo, Confidence: ConfLow,
			Title: "Declared capability with no detected use: " + capToken,
			Detail: map[string]any{
				"capability": capToken,
				"reason":     fmt.Sprintf("the manifest requests %q but no %s call was detected in the package's code", capToken, capToken),
			},
			Taxonomy: []string{"ASI04"},
		})
	}
	return findings
}
