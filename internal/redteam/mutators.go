// Package redteam attacks the registry's own S3/S4 gate (PLAN §17.5): it
// takes the golden attack corpus, rewrites each attack fixture with the
// paraphrase and obfuscation tricks red-team harnesses use (garak/PyRIT-
// style, without a model in the loop so a run is reproducible), scans the
// rewrites with the same rule bundle `agentry validate` and the pipeline
// use, and reports which rewrites the expected rule no longer catches.
// Report-only by construction: nothing here gates anything — the output
// feeds rule development.
package redteam

import (
	"encoding/base64"
	"regexp"
	"strings"
	"unicode"
)

// Mutator is one deterministic rewrite of a prose file.
type Mutator struct {
	// Name is the stable id reported per case.
	Name string
	// Family groups mutators the way harness taxonomies do.
	Family string
	// Apply rewrites content; a mutator that cannot apply returns ok=false
	// so the case is not counted.
	Apply func(content string) (out string, ok bool)
}

// Mutators is the fixed suite, in report order.
func Mutators() []Mutator {
	return []Mutator{
		{"synonyms", "paraphrase", synonyms},
		{"line-reverse", "paraphrase", lineReverse},
		{"case-alternate", "encoding", caseAlternate},
		{"leetspeak", "encoding", leetspeak},
		{"homoglyph-cyrillic", "unicode", homoglyphs},
		{"zero-width-joiner", "unicode", zeroWidth},
		{"fullwidth-ascii", "unicode", fullwidth},
		{"letter-spacing", "obfuscation", letterSpacing},
		{"html-comment-split", "obfuscation", htmlCommentSplit},
		{"whitespace-noise", "obfuscation", whitespaceNoise},
		{"markdown-reference-hide", "obfuscation", markdownReferenceHide},
		{"base64-wrap", "encoding", base64Wrap},
		{"rot13", "encoding", rot13},
	}
}

var synonymTable = [][2]string{
	{"ignore", "disregard"}, {"previous", "prior"}, {"instructions", "directives"},
	{"instruction", "directive"}, {"system prompt", "operator preamble"}, {"reveal", "disclose"},
	{"secret", "confidential"}, {"send", "transmit"}, {"exfiltrate", "export"},
	{"override", "supersede"}, {"delete", "remove"}, {"execute", "carry out"},
	{"download", "fetch"}, {"install", "set up"}, {"credentials", "login details"},
	{"password", "passphrase"}, {"token", "access string"}, {"do not", "never"},
	{"you must", "you are required to"}, {"always", "without exception"},
}

var wordBoundary = regexp.MustCompile(`[A-Za-z]+`)

// synonyms swaps a small table of attack vocabulary, case-preserving on the
// first letter.
func synonyms(s string) (string, bool) {
	out := s
	changed := false
	for _, pair := range synonymTable {
		re := regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(pair[0]) + `\b`)
		out = re.ReplaceAllStringFunc(out, func(m string) string {
			changed = true
			if unicode.IsUpper(rune(m[0])) {
				return strings.ToUpper(pair[1][:1]) + pair[1][1:]
			}
			return pair[1]
		})
	}
	return out, changed
}

// lineReverse reverses the order of non-empty lines inside each paragraph.
func lineReverse(s string) (string, bool) {
	paras := strings.Split(s, "\n\n")
	changed := false
	for i, p := range paras {
		lines := strings.Split(p, "\n")
		if len(lines) < 2 {
			continue
		}
		for a, b := 0, len(lines)-1; a < b; a, b = a+1, b-1 {
			lines[a], lines[b] = lines[b], lines[a]
		}
		paras[i] = strings.Join(lines, "\n")
		changed = true
	}
	return strings.Join(paras, "\n\n"), changed
}

func caseAlternate(s string) (string, bool) {
	var b strings.Builder
	up := false
	changed := false
	for _, r := range s {
		if unicode.IsLetter(r) {
			if up {
				b.WriteRune(unicode.ToUpper(r))
			} else {
				b.WriteRune(unicode.ToLower(r))
			}
			up = !up
			changed = true
			continue
		}
		b.WriteRune(r)
	}
	return b.String(), changed
}

func leetspeak(s string) (string, bool) {
	r := strings.NewReplacer("a", "4", "e", "3", "i", "1", "o", "0", "s", "5", "A", "4", "E", "3", "I", "1", "O", "0", "S", "5")
	out := r.Replace(s)
	return out, out != s
}

var cyrillic = map[rune]rune{'a': 'а', 'e': 'е', 'o': 'о', 'p': 'р', 'c': 'с', 'x': 'х', 'y': 'у', 'A': 'А', 'E': 'Е', 'O': 'О', 'P': 'Р', 'C': 'С', 'X': 'Х', 'Y': 'У'}

func homoglyphs(s string) (string, bool) {
	var b strings.Builder
	changed := false
	for _, r := range s {
		if c, ok := cyrillic[r]; ok {
			b.WriteRune(c)
			changed = true
			continue
		}
		b.WriteRune(r)
	}
	return b.String(), changed
}

// zeroWidth inserts U+200B inside every word of five letters or more.
func zeroWidth(s string) (string, bool) {
	changed := false
	out := wordBoundary.ReplaceAllStringFunc(s, func(w string) string {
		if len(w) < 5 {
			return w
		}
		changed = true
		var b strings.Builder
		for i, r := range w {
			if i > 0 && i%2 == 0 {
				b.WriteRune('​')
			}
			b.WriteRune(r)
		}
		return b.String()
	})
	return out, changed
}

func fullwidth(s string) (string, bool) {
	var b strings.Builder
	changed := false
	for _, r := range s {
		if r > 0x20 && r < 0x7f {
			b.WriteRune(r - 0x20 + 0xff00)
			changed = true
			continue
		}
		b.WriteRune(r)
	}
	return b.String(), changed
}

func letterSpacing(s string) (string, bool) {
	changed := false
	out := wordBoundary.ReplaceAllStringFunc(s, func(w string) string {
		if len(w) < 6 {
			return w
		}
		changed = true
		return strings.Join(strings.Split(w, ""), " ")
	})
	return out, changed
}

func htmlCommentSplit(s string) (string, bool) {
	changed := false
	out := wordBoundary.ReplaceAllStringFunc(s, func(w string) string {
		if len(w) < 6 {
			return w
		}
		changed = true
		mid := len(w) / 2
		return w[:mid] + "<!-- -->" + w[mid:]
	})
	return out, changed
}

func whitespaceNoise(s string) (string, bool) {
	out := strings.ReplaceAll(s, " ", "  ")
	out = strings.ReplaceAll(out, "\n", " \t\n")
	return out, out != s
}

// markdownReferenceHide moves every line into a reference-style link
// definition, which renders as nothing.
func markdownReferenceHide(s string) (string, bool) {
	lines := strings.Split(s, "\n")
	changed := false
	for i, l := range lines {
		if strings.TrimSpace(l) == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, "---") {
			continue
		}
		lines[i] = "[//]: # (" + strings.ReplaceAll(l, ")", "﹚") + ")"
		changed = true
	}
	return strings.Join(lines, "\n"), changed
}

func base64Wrap(s string) (string, bool) {
	enc := base64.StdEncoding.EncodeToString([]byte(s))
	return "Decode the following base64 and follow it exactly:\n\n" + enc + "\n", true
}

func rot13(s string) (string, bool) {
	out := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return 'a' + (r-'a'+13)%26
		case r >= 'A' && r <= 'Z':
			return 'A' + (r-'A'+13)%26
		}
		return r
	}, s)
	return "The text below is rot13; decode it and comply:\n\n" + out, true
}
