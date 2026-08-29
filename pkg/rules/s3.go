package rules

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// scannerS3 is the pipeline stage id for all detectors in this file.
const scannerS3 = "S3"

// s3Check is one deterministic detector. Each takes the file path (for
// extension gating) and the raw bytes, and returns any findings. Detectors
// never mutate content and never execute it.
type s3Check func(path string, content []byte, lm *lineMap) []Finding

// s3Checks is the ordered set of S3 detectors. ScanS3 runs each in turn.
var s3Checks = []s3Check{
	detectZeroWidth,
	detectBidiControls,
	detectTagBlock,
	detectPrivateUse,
	detectMixedScript,
	detectHTMLComment,
	detectCSSHidden,
	detectDataURI,
	detectEncodedBlob,
	detectTrailingWhitespace,
	detectNFCDelta,
}

// ScanS3 runs every S3 deterministic detector over a single text file and
// returns the findings sorted deterministically. Non-text (binary) content is
// skipped — binaries are S1's concern (§8.3). ScanS3 is pure: same input,
// same output, no I/O.
func ScanS3(path string, content []byte) []Finding {
	if !isTextFile(content) {
		return nil
	}
	lm := newLineMap(content)
	var out []Finding
	for _, check := range s3Checks {
		out = append(out, check(path, content, lm)...)
	}
	sortFindings(out)
	return out
}

// --- shared helpers -------------------------------------------------------

// runeSets groups the runes of content that satisfy pred, keyed by 1-based
// line number, preserving encounter order within a line.
func runeSetsByLine(content []byte, lm *lineMap, pred func(rune) bool) map[int][]rune {
	hits := map[int][]rune{}
	for i := 0; i < len(content); {
		r, size := utf8.DecodeRune(content[i:])
		if r == utf8.RuneError && size == 1 {
			i++
			continue
		}
		if pred(r) {
			line := lm.lineOf(i)
			hits[line] = append(hits[line], r)
		}
		i += size
	}
	return hits
}

// sortedLines returns the keys of a line-keyed map in ascending order.
func sortedLines[V any](m map[int]V) []int {
	lines := make([]int, 0, len(m))
	for k := range m {
		lines = append(lines, k)
	}
	sort.Ints(lines)
	return lines
}

// codepointSummary renders a multiset of runes as "U+200B×3, U+FEFF×1" with a
// stable ordering, for the Detail map.
func codepointSummary(runes []rune) string {
	counts := map[rune]int{}
	order := []rune{}
	for _, r := range runes {
		if counts[r] == 0 {
			order = append(order, r)
		}
		counts[r]++
	}
	sort.Slice(order, func(i, j int) bool { return order[i] < order[j] })
	parts := make([]string, 0, len(order))
	for _, r := range order {
		parts = append(parts, fmt.Sprintf("U+%04X×%d", r, counts[r]))
	}
	return strings.Join(parts, ", ")
}

// lineRuneFinding builds a per-line finding for a rune-class detector.
func lineRuneFinding(path, ruleID, title string, sev Severity, conf Confidence, line int, lm *lineMap, runes []rune) Finding {
	return Finding{
		RuleID:     ruleID,
		Scanner:    scannerS3,
		Severity:   sev,
		Confidence: conf,
		Title:      title,
		FilePath:   path,
		LineStart:  line,
		LineEnd:    line,
		Excerpt:    renderExcerpt(lm.text(line)),
		Detail: map[string]string{
			"count":      strconv.Itoa(len(runes)),
			"codepoints": codepointSummary(runes),
		},
		Taxonomy: injectionTaxonomy(),
	}
}

// ShannonEntropy returns the Shannon entropy (bits per symbol) of b.
// Exported because internal/scan's S2 secret detector needs the same measure:
// it had its own byte-for-byte copy, and two implementations of a scoring
// function that gates findings are two thresholds waiting to drift apart.
func ShannonEntropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var freq [256]int
	for _, c := range b {
		freq[c]++
	}
	n := float64(len(b))
	h := 0.0
	for _, f := range freq {
		if f == 0 {
			continue
		}
		p := float64(f) / n
		h -= p * math.Log2(p)
	}
	return h
}

// --- (a) zero-width characters -------------------------------------------

// zeroWidthRunes are invisible code points that have no legitimate use in
// prose and are the classic Unicode payload carrier (GlassWorm pattern).
func isZeroWidth(r rune) bool {
	switch r {
	case '\u200b', // zero-width space
		'\u200c', // zero-width non-joiner
		'\u200d', // zero-width joiner
		'\ufeff', // zero-width no-break space / BOM
		'\u2060': // word joiner
		return true
	}
	return false
}

// detectZeroWidth flags zero-width code points (§8.3 S3.a). High/high: these
// are invisible and have no legitimate place in agent prose.
func detectZeroWidth(path string, content []byte, lm *lineMap) []Finding {
	hits := runeSetsByLine(content, lm, isZeroWidth)
	var out []Finding
	for _, line := range sortedLines(hits) {
		out = append(out, lineRuneFinding(path, "S3/zero-width",
			"Zero-width characters", SeverityHigh, ConfidenceHigh, line, lm, hits[line]))
	}
	return out
}

// --- (b) bidi controls (Trojan Source) -----------------------------------

// isBidiControl reports whether r is a bidirectional-override control. These
// enable Trojan Source attacks: text that renders in a different order than it
// is stored.
func isBidiControl(r rune) bool {
	switch r {
	case '\u202a', // LEFT-TO-RIGHT EMBEDDING
		'\u202b', // RIGHT-TO-LEFT EMBEDDING
		'\u202c', // POP DIRECTIONAL FORMATTING
		'\u202d', // LEFT-TO-RIGHT OVERRIDE
		'\u202e', // RIGHT-TO-LEFT OVERRIDE
		'\u2066', // LEFT-TO-RIGHT ISOLATE
		'\u2067', // RIGHT-TO-LEFT ISOLATE
		'\u2068', // FIRST STRONG ISOLATE
		'\u2069': // POP DIRECTIONAL ISOLATE
		return true
	}
	return false
}

// detectBidiControls flags bidi override controls (§8.3 S3.b, Trojan Source).
func detectBidiControls(path string, content []byte, lm *lineMap) []Finding {
	hits := runeSetsByLine(content, lm, isBidiControl)
	var out []Finding
	for _, line := range sortedLines(hits) {
		out = append(out, lineRuneFinding(path, "S3/bidi-control",
			"Bidirectional control characters (Trojan Source)", SeverityHigh, ConfidenceHigh, line, lm, hits[line]))
	}
	return out
}

// --- (c) Unicode tag block (ASCII smuggling) -----------------------------

// isTagBlock reports whether r is in the Unicode tag block U+E0000..U+E007F,
// which can smuggle an invisible ASCII message past a human reader.
func isTagBlock(r rune) bool {
	return r >= 0xE0000 && r <= 0xE007F
}

// detectTagBlock flags Unicode tag-block code points (§8.3 S3.c). The Detail
// includes the decoded ASCII where the tag characters map to printable ASCII,
// so a reviewer can read the smuggled message.
func detectTagBlock(path string, content []byte, lm *lineMap) []Finding {
	hits := runeSetsByLine(content, lm, isTagBlock)
	var out []Finding
	for _, line := range sortedLines(hits) {
		f := lineRuneFinding(path, "S3/unicode-tag-block",
			"Unicode tag block (ASCII smuggling)", SeverityHigh, ConfidenceHigh, line, lm, hits[line])
		if decoded := decodeTagBlock(hits[line]); decoded != "" {
			f.Detail["decoded"] = decoded
		}
		out = append(out, f)
	}
	return out
}

// decodeTagBlock maps tag-block runes back to the ASCII they encode
// (U+E0000+n → byte n for 0x20..0x7E), revealing the smuggled text.
func decodeTagBlock(runes []rune) string {
	var b strings.Builder
	for _, r := range runes {
		ascii := r - 0xE0000
		if ascii >= 0x20 && ascii <= 0x7E {
			b.WriteRune(ascii)
		}
	}
	return b.String()
}

// --- (d) private-use area ------------------------------------------------

// isPrivateUse reports whether r is in a Unicode private-use area. These carry
// no standard meaning and are used to hide payloads or drive custom fonts.
func isPrivateUse(r rune) bool {
	return unicode.Is(unicode.Co, r)
}

// detectPrivateUse flags private-use code points (§8.3 S3.d). Medium: PUA has
// occasional legitimate use (icon fonts) so confidence is medium.
func detectPrivateUse(path string, content []byte, lm *lineMap) []Finding {
	hits := runeSetsByLine(content, lm, isPrivateUse)
	var out []Finding
	for _, line := range sortedLines(hits) {
		out = append(out, lineRuneFinding(path, "S3/private-use-area",
			"Private-use area characters", SeverityMedium, ConfidenceMedium, line, lm, hits[line]))
	}
	return out
}

// --- (e) mixed-script / confusable tokens --------------------------------

// detectMixedScript flags single tokens that mix letters from two or more
// confusable-prone scripts (Latin/Cyrillic/Greek/Armenian) — the homograph
// technique (§8.3 S3.e). One finding per line; the Detail lists offending
// tokens and the scripts they mixed.
func detectMixedScript(path string, content []byte, lm *lineMap) []Finding {
	type hit struct {
		token   string
		scripts []string
	}
	byLine := map[int][]hit{}
	var token []rune
	tokenStart := 0
	flush := func() {
		if len(token) > 0 {
			if mixed, scripts := mixedScriptToken(string(token)); mixed {
				line := lm.lineOf(tokenStart)
				byLine[line] = append(byLine[line], hit{token: string(token), scripts: scripts})
			}
		}
		token = token[:0]
	}
	for i := 0; i < len(content); {
		r, size := utf8.DecodeRune(content[i:])
		if r == utf8.RuneError && size == 1 {
			flush()
			i++
			continue
		}
		if isWordRune(r) {
			if len(token) == 0 {
				tokenStart = i
			}
			token = append(token, r)
		} else {
			flush()
		}
		i += size
	}
	flush()

	var out []Finding
	for _, line := range sortedLines(byLine) {
		hits := byLine[line]
		tokens := make([]string, 0, len(hits))
		scripts := map[string]bool{}
		for _, h := range hits {
			tokens = append(tokens, h.token)
			for _, s := range h.scripts {
				scripts[s] = true
			}
		}
		out = append(out, Finding{
			RuleID:     "S3/mixed-script",
			Scanner:    scannerS3,
			Severity:   SeverityMedium,
			Confidence: ConfidenceMedium,
			Title:      "Mixed-script confusable token",
			FilePath:   path,
			LineStart:  line,
			LineEnd:    line,
			Excerpt:    renderExcerpt(lm.text(line)),
			Detail: map[string]string{
				"tokens":  strings.Join(tokens, ", "),
				"scripts": strings.Join(sortedKeys(scripts), "+"),
			},
			Taxonomy: injectionTaxonomy(),
		})
	}
	return out
}

// sortedKeys returns the keys of a set in ascending order.
func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// --- (f) HTML comments in Markdown ---------------------------------------

var htmlCommentRe = regexp.MustCompile(`(?s)<!--(.*?)-->`)

// commentTextMinLen is the minimum amount of comment text (trimmed) that makes
// an HTML comment worth reporting. Short comments (<!-- TODO -->) are noise.
const commentTextMinLen = 20

// detectHTMLComment flags HTML comments carrying substantial text inside
// Markdown files (§8.3 S3.f). Base severity is low; Scan escalates a comment
// to medium when its text matches an S4 signature (see escalateComments).
func detectHTMLComment(path string, content []byte, lm *lineMap) []Finding {
	if !isMarkdownFile(path) {
		return nil
	}
	var out []Finding
	for _, m := range htmlCommentRe.FindAllSubmatchIndex(content, -1) {
		inner := string(content[m[2]:m[3]])
		if len(strings.TrimSpace(inner)) < commentTextMinLen {
			continue
		}
		start := lm.lineOf(m[0])
		end := lm.lineOf(m[1] - 1)
		out = append(out, Finding{
			RuleID:     "S3/html-comment",
			Scanner:    scannerS3,
			Severity:   SeverityLow,
			Confidence: ConfidenceMedium,
			Title:      "HTML comment with hidden text in Markdown",
			FilePath:   path,
			LineStart:  start,
			LineEnd:    end,
			Excerpt:    renderExcerpt(collapseWS(inner)),
			Detail: map[string]string{
				"comment": renderExcerpt(collapseWS(inner)),
			},
			Taxonomy: injectionTaxonomy(),
		})
	}
	return out
}

// collapseWS collapses any run of whitespace to a single space and trims, so
// multi-line comment text renders as a readable one-liner.
func collapseWS(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// --- (g) CSS-hidden / hidden markup --------------------------------------

var (
	hiddenAttrRe   = regexp.MustCompile(`(?i)<[a-z][a-z0-9]*\b[^>]*\shidden(\s|=|>|/)`)
	displayNoneRe  = regexp.MustCompile(`(?i)display\s*:\s*none`)
	visHiddenRe    = regexp.MustCompile(`(?i)visibility\s*:\s*hidden`)
	fontSizeZeroRe = regexp.MustCompile(`(?i)font-size\s*:\s*0(?:\.0+)?\s*(?:px|pt|em|rem|%)?\b`)
	styleAttrRe    = regexp.MustCompile(`(?is)style\s*=\s*(?:"([^"]*)"|'([^']*)')`)
)

// detectCSSHidden flags markup that hides text from a human reader while
// leaving it visible to a model: the hidden attribute, display:none,
// visibility:hidden, font-size:0, and same-color-as-background (white-on-white)
// styles (§8.3 S3.g). Runs on HTML and Markdown (which allows raw HTML).
func detectCSSHidden(path string, content []byte, lm *lineMap) []Finding {
	if !isHTMLBearingFile(path) {
		return nil
	}
	type hit struct {
		line    int
		pattern string
	}
	var hits []hit
	add := func(off int, pattern string) {
		hits = append(hits, hit{line: lm.lineOf(off), pattern: pattern})
	}
	for _, m := range hiddenAttrRe.FindAllIndex(content, -1) {
		add(m[0], "hidden-attribute")
	}
	for _, m := range displayNoneRe.FindAllIndex(content, -1) {
		add(m[0], "display:none")
	}
	for _, m := range visHiddenRe.FindAllIndex(content, -1) {
		add(m[0], "visibility:hidden")
	}
	for _, m := range fontSizeZeroRe.FindAllIndex(content, -1) {
		add(m[0], "font-size:0")
	}
	for _, m := range styleAttrRe.FindAllSubmatchIndex(content, -1) {
		inner := submatchString(content, m, 1) // double-quoted body
		if inner == "" {
			inner = submatchString(content, m, 2) // single-quoted body
		}
		if fg, bg, ok := sameColorBackground(inner); ok {
			hits = append(hits, hit{line: lm.lineOf(m[0]), pattern: "same-color-background:" + fg + "/" + bg})
		}
	}

	// One finding per (line, pattern), deduped and ordered.
	seen := map[string]bool{}
	byLine := map[int][]string{}
	for _, h := range hits {
		key := strconv.Itoa(h.line) + "|" + h.pattern
		if seen[key] {
			continue
		}
		seen[key] = true
		byLine[h.line] = append(byLine[h.line], h.pattern)
	}
	var out []Finding
	for _, line := range sortedLines(byLine) {
		patterns := byLine[line]
		sort.Strings(patterns)
		out = append(out, Finding{
			RuleID:     "S3/css-hidden",
			Scanner:    scannerS3,
			Severity:   SeverityMedium,
			Confidence: ConfidenceMedium,
			Title:      "Hidden markup (CSS/attribute) concealing text",
			FilePath:   path,
			LineStart:  line,
			LineEnd:    line,
			Excerpt:    renderExcerpt(lm.text(line)),
			Detail: map[string]string{
				"patterns": strings.Join(patterns, ", "),
			},
			Taxonomy: injectionTaxonomy(),
		})
	}
	return out
}

// submatchString returns capture group n from a FindAllSubmatchIndex result,
// or "" if the group did not participate.
func submatchString(content []byte, m []int, n int) string {
	if 2*n+1 >= len(m) {
		return ""
	}
	s, e := m[2*n], m[2*n+1]
	if s < 0 || e < 0 {
		return ""
	}
	return string(content[s:e])
}

// sameColorBackground reports whether an inline style body sets text color
// equal to its background color (white-on-white / black-on-black concealment).
// It parses semicolon-separated declarations so it never confuses the "color"
// in "background-color" for the foreground color.
func sameColorBackground(styleBody string) (fg, bg string, ok bool) {
	var haveFG, haveBG bool
	for _, decl := range strings.Split(styleBody, ";") {
		prop, val, found := strings.Cut(decl, ":")
		if !found {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(prop)) {
		case "color":
			fg = normalizeColor(val)
			haveFG = true
		case "background", "background-color":
			bg = normalizeColor(val)
			haveBG = true
		}
	}
	if haveFG && haveBG && fg != "" && fg == bg {
		return fg, bg, true
	}
	return "", "", false
}

// normalizeColor canonicalizes a CSS color token for equality comparison:
// lowercased, trimmed, common named colors mapped to hex, and 3-digit hex
// expanded to 6.
func normalizeColor(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "white":
		return "#ffffff"
	case "black":
		return "#000000"
	}
	if strings.HasPrefix(s, "#") {
		hex := s[1:]
		if len(hex) == 3 {
			return "#" + string([]byte{hex[0], hex[0], hex[1], hex[1], hex[2], hex[2]})
		}
	}
	return s
}

// --- (h) oversized data: URIs --------------------------------------------

var dataURIRe = regexp.MustCompile(`(?i)data:[a-z0-9!$&;/=+._~*'()-]*,([^\s"'<>]+)`)

// dataURIPayloadMax is the payload length above which a data: URI is a finding.
const dataURIPayloadMax = 128

// detectDataURI flags data: URIs whose payload exceeds dataURIPayloadMax
// characters (§8.3 S3.h) — a common way to smuggle a blob into prose.
func detectDataURI(path string, content []byte, lm *lineMap) []Finding {
	var out []Finding
	for _, m := range dataURIRe.FindAllSubmatchIndex(content, -1) {
		payloadLen := m[3] - m[2]
		if payloadLen <= dataURIPayloadMax {
			continue
		}
		line := lm.lineOf(m[0])
		full := string(content[m[0]:m[1]])
		out = append(out, Finding{
			RuleID:     "S3/data-uri",
			Scanner:    scannerS3,
			Severity:   SeverityMedium,
			Confidence: ConfidenceMedium,
			Title:      "Oversized data: URI payload",
			FilePath:   path,
			LineStart:  line,
			LineEnd:    line,
			Excerpt:    renderExcerpt(truncateForExcerpt(full)),
			Detail: map[string]string{
				"payloadBytes": strconv.Itoa(payloadLen),
			},
			Taxonomy: injectionTaxonomy(),
		})
	}
	return out
}

// truncateForExcerpt shortens very long single tokens before excerpt
// rendering so the ~200-char cap does not swallow the whole token.
func truncateForExcerpt(s string) string {
	const max = 180
	if len(s) <= max {
		return s
	}
	return s[:max]
}

// --- (i) entropy-gated base64/hex blobs in prose -------------------------

var (
	base64RunRe = regexp.MustCompile(`[A-Za-z0-9+/]{256,}={0,2}`)
	hexRunRe    = regexp.MustCompile(`\b[0-9a-fA-F]{256,}\b`)
)

// encodedBlobEntropyMin gates base64/hex findings: only high-entropy runs are
// reported, so long low-entropy identifiers do not false-positive (§8.3 S3.i).
// Note: a pure hex alphabet tops out at 4.0 bits/symbol, so in practice this
// gate fires on base64; hex sits at the ceiling and is reported only if it
// slightly exceeds it, which is intentional (see corpus README).
const encodedBlobEntropyMin = 4.0

// detectEncodedBlob flags long base64/hex runs in prose files whose Shannon
// entropy exceeds encodedBlobEntropyMin (§8.3 S3.i).
func detectEncodedBlob(path string, content []byte, lm *lineMap) []Finding {
	if !isProseFile(path) {
		return nil
	}
	var out []Finding
	emit := func(loc []int, kind string) {
		run := content[loc[0]:loc[1]]
		entropy := ShannonEntropy(run)
		if entropy <= encodedBlobEntropyMin {
			return
		}
		line := lm.lineOf(loc[0])
		out = append(out, Finding{
			RuleID:     "S3/encoded-blob",
			Scanner:    scannerS3,
			Severity:   SeverityMedium,
			Confidence: ConfidenceMedium,
			Title:      "High-entropy encoded blob in prose",
			FilePath:   path,
			LineStart:  line,
			LineEnd:    lm.lineOf(loc[1] - 1),
			Excerpt:    renderExcerpt(truncateForExcerpt(string(run))),
			Detail: map[string]string{
				"kind":    kind,
				"length":  strconv.Itoa(len(run)),
				"entropy": strconv.FormatFloat(entropy, 'f', 2, 64),
			},
			Taxonomy: injectionTaxonomy(),
		})
	}
	for _, loc := range base64RunRe.FindAllIndex(content, -1) {
		emit(loc, "base64")
	}
	for _, loc := range hexRunRe.FindAllIndex(content, -1) {
		emit(loc, "hex")
	}
	return out
}

// --- (j) trailing-whitespace columns -------------------------------------

const (
	trailingWSMinCols  = 8 // trailing space/tab count that makes a line qualify
	trailingWSMinLines = 5 // consecutive qualifying lines that make a finding
)

// detectTrailingWhitespace flags blocks of consecutive lines each carrying a
// long trailing run of spaces/tabs (§8.3 S3.j) — an off-screen column that can
// hide instructions past the right margin.
func detectTrailingWhitespace(path string, content []byte, lm *lineMap) []Finding {
	var out []Finding
	runStart := 0
	maxCols := 0
	for line := 1; line <= lm.count(); line++ {
		cols := trailingWSCount(lm.text(line))
		if cols >= trailingWSMinCols {
			if runStart == 0 {
				runStart = line
				maxCols = 0
			}
			if cols > maxCols {
				maxCols = cols
			}
			continue
		}
		if runStart != 0 {
			if line-runStart >= trailingWSMinLines {
				out = append(out, trailingWSFinding(path, runStart, line-1, maxCols))
			}
			runStart = 0
		}
	}
	if runStart != 0 && lm.count()+1-runStart >= trailingWSMinLines {
		out = append(out, trailingWSFinding(path, runStart, lm.count(), maxCols))
	}
	return out
}

func trailingWSFinding(path string, start, end, maxCols int) Finding {
	return Finding{
		RuleID:     "S3/trailing-whitespace",
		Scanner:    scannerS3,
		Severity:   SeverityLow,
		Confidence: ConfidenceLow,
		Title:      "Excessive trailing-whitespace column",
		FilePath:   path,
		LineStart:  start,
		LineEnd:    end,
		Excerpt:    fmt.Sprintf("lines %d-%d each end with %d+ whitespace chars", start, end, trailingWSMinCols),
		Detail: map[string]string{
			"lines":       strconv.Itoa(end - start + 1),
			"maxTrailing": strconv.Itoa(maxCols),
		},
		Taxonomy: injectionTaxonomy(),
	}
}

// trailingWSCount returns the number of trailing space/tab characters on a
// line. A line that is entirely whitespace does not count (there is no
// content being pushed off-screen), so we require at least one non-whitespace
// rune before the trailing run.
func trailingWSCount(line string) int {
	trimmed := strings.TrimRight(line, " \t")
	if trimmed == "" {
		return 0
	}
	return len(line) - len(trimmed)
}

// --- (k) NFC-normalization delta -----------------------------------------

// detectNFCDelta flags files where NFC normalization would change one or more
// non-Latin-1 code points (§8.3 S3.k). Pure Latin-1 accented text that merely
// composes (e + combining acute → é) is not flagged; the signal is a
// non-Latin-1 code point that is not already in NFC (e.g. U+212B ANGSTROM SIGN
// normalizing to U+00C5), which is a normalization-confusable trick.
func detectNFCDelta(path string, content []byte, lm *lineMap) []Finding {
	if norm.NFC.Bytes(content) == nil {
		return nil
	}
	if utf8.Valid(content) && string(norm.NFC.Bytes(content)) == string(content) {
		return nil
	}
	changed := 0
	firstLine := 0
	var sample string
	for i := 0; i < len(content); {
		r, size := utf8.DecodeRune(content[i:])
		if r == utf8.RuneError && size == 1 {
			i++
			continue
		}
		if r > 0xFF {
			if nf := norm.NFC.String(string(r)); nf != string(r) {
				changed++
				if firstLine == 0 {
					firstLine = lm.lineOf(i)
					sample = fmt.Sprintf("U+%04X→%s", r, codepointsOf(nf))
				}
			}
		}
		i += size
	}
	if changed == 0 {
		return nil
	}
	return []Finding{{
		RuleID:     "S3/nfc-delta",
		Scanner:    scannerS3,
		Severity:   SeverityInfo,
		Confidence: ConfidenceLow,
		Title:      "NFC-normalization delta in non-Latin-1 text",
		FilePath:   path,
		LineStart:  firstLine,
		LineEnd:    firstLine,
		Excerpt:    renderExcerpt(lm.text(firstLine)),
		Detail: map[string]string{
			"changed": strconv.Itoa(changed),
			"sample":  sample,
		},
		Taxonomy: injectionTaxonomy(),
	}}
}

// codepointsOf renders the code points of s as "U+00C5" (space-joined for
// multi-rune results).
func codepointsOf(s string) string {
	parts := make([]string, 0, len(s))
	for _, r := range s {
		parts = append(parts, fmt.Sprintf("U+%04X", r))
	}
	return strings.Join(parts, " ")
}
