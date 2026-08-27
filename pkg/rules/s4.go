package rules

// s4.go is the S4 signature-engine evaluator: it applies a compiled Bundle to
// prose text and emits findings. Loading/compilation lives in bundle.go.

import "strings"

// Scan evaluates every rule in the bundle over one prose file and returns the
// S4 findings, sorted deterministically. Content is treated as data: patterns
// are matched, never executed. Matching is effectively line-oriented (patterns
// compile with the multiline flag), and a candidate hit is suppressed when any
// of the rule's notPatterns matches the same line(s) — this is how benign
// discussion of an attack (security docs, this very engine's own rules) is
// kept out of the results (§17.3).
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

// suppressed reports whether any notPattern matches the text of the lines the
// hit spans. Suppression context is the matched line(s), so a discussion
// marker on the same line as an attack phrase exempts it.
func suppressed(cr *compiledRule, lm *lineMap, lineStart, lineEnd int) bool {
	if len(cr.notPatterns) == 0 {
		return false
	}
	context := lineSpanText(lm, lineStart, lineEnd)
	for _, re := range cr.notPatterns {
		if re.MatchString(context) {
			return true
		}
	}
	return false
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
