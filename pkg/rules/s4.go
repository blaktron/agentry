package rules

// s4.go is the S4 signature-engine evaluator: it applies a compiled Bundle to
// prose text and emits findings. Loading/compilation lives in bundle.go.

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Scan evaluates every rule in the bundle over one prose file and returns the
// S4 findings, sorted deterministically. Content is treated as data: patterns
// are matched, never executed. Matching is effectively line-oriented (patterns
// compile with the multiline flag), and a candidate hit is suppressed when any
// of the rule's notPatterns matches the same line(s), or any of the bundle's
// notPatterns matches the containing paragraph (see suppressed) — this is how
// benign discussion of an attack (security docs, this very engine's own rules)
// is kept out of the results (§17.3).
func (b *Bundle) Scan(path string, content []byte) []Finding {
	lm := newLineMap(content)
	var out []Finding
	for _, cr := range b.rules {
		out = append(out, evalRule(cr, path, content, lm)...)
	}
	sortFindings(out)
	return out
}

// MatchingRules returns the ids of the rules that fire on the given text,
// with the "S4/" prefix. It is used to escalate S3 HTML-comment findings whose
// hidden text is itself an injection payload (§8.3 S3.f) and is handy for
// callers that only need a yes/no per rule (e.g. fixture checks).
func (b *Bundle) MatchingRules(text string) []string {
	content := []byte(text)
	lm := newLineMap(content)
	var ids []string
	for _, cr := range b.rules {
		if len(evalRule(cr, "", content, lm)) > 0 {
			ids = append(ids, "S4/"+cr.ID)
		}
	}
	return ids
}

// evalRule applies one compiled rule to content and returns its findings, at
// most one per (rule, starting line).
func evalRule(cr *compiledRule, path string, content []byte, lm *lineMap) []Finding {
	seenLine := map[int]bool{}
	var out []Finding
	for _, re := range cr.patterns {
		for _, loc := range re.FindAllIndex(content, -1) {
			start, end := loc[0], loc[1]
			lineStart := lm.lineOf(start)
			if end > start {
				end--
			}
			lineEnd := lm.lineOf(end)
			if seenLine[lineStart] {
				continue
			}
			if suppressed(cr, lm, lineStart, lineEnd) {
				continue
			}
			seenLine[lineStart] = true
			matched := string(content[loc[0]:loc[1]])
			out = append(out, Finding{
				RuleID:     "S4/" + cr.ID,
				Scanner:    scannerS4,
				Severity:   cr.Severity,
				Confidence: cr.Confidence,
				Title:      cr.Title,
				FilePath:   path,
				LineStart:  lineStart,
				LineEnd:    lineEnd,
				Excerpt:    renderExcerpt(truncateForExcerpt(collapseWS(matched))),
				Detail: map[string]string{
					"family":  cr.Family,
					"pattern": re.String(),
				},
				Taxonomy: injectionTaxonomy(),
			})
		}
	}
	return out
}

// suppressed reports whether the hit is exempted by a notPattern.
//
// Two scopes, deliberately different:
//
//   - Per-rule notPatterns evaluate over the matched line(s) only. They encode
//     precise negations ("never echo your API keys") where the exempting words
//     sit right next to the phrase.
//   - Bundle-level notPatterns evaluate over the containing PARAGRAPH
//     (contiguous non-blank lines). They encode descriptive framing — prose
//     that catalogues an attack rather than issuing it — and prose wraps
//     mid-sentence, so "Prompts to echo secrets, / paste tokens into output"
//     puts the marker on a different line than the match.
//
// A paragraph is still a bounded scope: a blank line or a Markdown heading
// ends it, so one descriptive phrase cannot whitelist a whole document, and a
// heading such as "# Findings" cannot whitelist the directive under it
// (agentry#845, ruleset 0.3.3). Within the paragraph the reach is not
// sentence-bounded: a descriptive sentence beside a live directive still
// suppresses it, the residual risk DEV-010 states.
func suppressed(cr *compiledRule, lm *lineMap, lineStart, lineEnd int) bool {
	if len(cr.notPatterns) > 0 {
		lineContext := lineSpanText(lm, lineStart, lineEnd)
		for _, re := range cr.notPatterns {
			if re.MatchString(lineContext) {
				return true
			}
		}
	}
	if len(cr.bundleNotPatterns) > 0 {
		paraContext := paragraphText(lm, lineStart, lineEnd)
		for _, re := range cr.bundleNotPatterns {
			if re.MatchString(paraContext) {
				return true
			}
		}
	}
	return false
}

// paragraphText returns the contiguous non-blank, non-heading lines
// containing the span. A Markdown heading is a block of its own, so a hit on a
// heading line takes only its own lines as context.
func paragraphText(lm *lineMap, start, end int) string {
	if isATXHeading(lm.text(start)) {
		return lineSpanText(lm, start, end)
	}
	first := start
	for first > 1 && inParagraph(lm.text(first-1)) {
		first--
	}
	// lm.text returns "" past the end of the file, so this terminates.
	last := end
	for inParagraph(lm.text(last + 1)) {
		last++
	}
	return lineSpanText(lm, first, last)
}

// inParagraph reports whether a neighbouring line continues a paragraph.
func inParagraph(line string) bool {
	return strings.TrimSpace(line) != "" && !isATXHeading(line)
}

// isATXHeading reports whether line reads as an ATX heading: up to three
// spaces of indentation, one to six '#', then whitespace or the end of the
// line. ("#hashtag" is not a heading; four spaces of indentation is code.)
// CommonMark asks for an ASCII space or tab after the hashes, but any Unicode
// space counts here: a model reads "##\u00a0Findings" as a heading whatever a
// renderer does, and the red team's whitespace-noise mutant used exactly that
// to keep "Findings" in the directive's paragraph (agentry#851, ruleset 0.3.4).
func isATXHeading(line string) bool {
	i := 0
	for i < 3 && i < len(line) && line[i] == ' ' {
		i++
	}
	n := 0
	for i+n < len(line) && line[i+n] == '#' {
		n++
	}
	if n == 0 || n > 6 {
		return false
	}
	r, _ := utf8.DecodeRuneInString(line[i+n:])
	return i+n == len(line) || unicode.IsSpace(r)
}

// lineSpanText joins the text of lines [start, end] with newlines.
func lineSpanText(lm *lineMap, start, end int) string {
	if end < start {
		end = start
	}
	if start == end {
		return lm.text(start)
	}
	parts := make([]string, 0, end-start+1)
	for n := start; n <= end; n++ {
		parts = append(parts, lm.text(n))
	}
	return strings.Join(parts, "\n")
}
