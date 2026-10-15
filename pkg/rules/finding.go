package rules

import (
	"fmt"
	"sort"
	"unicode"
	"unicode/utf8"
)

// Severity ranks how dangerous a finding is. It mirrors the pipeline
// gate vocabulary.
type Severity string

// Severity levels, ordered least to most severe.
const (
	// SeverityInfo is advisory only; never gates a publish on its own.
	SeverityInfo Severity = "info"
	// SeverityLow is a minor concern surfaced on the report.
	SeverityLow Severity = "low"
	// SeverityMedium routes a version to human review.
	SeverityMedium Severity = "medium"
	// SeverityHigh routes a version to human review (platform queue if public).
	SeverityHigh Severity = "high"
	// SeverityCritical auto-rejects a version.
	SeverityCritical Severity = "critical"
)

// Confidence expresses how sure the detector is that the match is a
// true positive. Low-confidence findings never gate alone; they surface
// to reviewers.
type Confidence string

// Confidence levels.
const (
	// ConfidenceLow marks heuristic matches that need a human look.
	ConfidenceLow Confidence = "low"
	// ConfidenceMedium marks matches with a reasonable false-positive rate.
	ConfidenceMedium Confidence = "medium"
	// ConfidenceHigh marks matches with no legitimate explanation in prose.
	ConfidenceHigh Confidence = "high"
)

// OWASP taxonomy ids attached to findings. S3 and S4 both map to prompt
// injection (LLM01) and memory/context poisoning (ASI06).
const (
	// TaxonomyLLM01 is OWASP Top 10 for LLM Applications 2025: Prompt Injection.
	TaxonomyLLM01 = "LLM01"
	// TaxonomyASI06 is OWASP Top 10 for Agentic Applications 2026:
	// Memory & Context Poisoning.
	TaxonomyASI06 = "ASI06"
)

// injectionTaxonomy is the taxonomy slice shared by every S3/S4 finding.
// A fresh copy is handed out per finding so callers cannot mutate the shared
// backing array.
func injectionTaxonomy() []string {
	return []string{TaxonomyLLM01, TaxonomyASI06}
}

// Finding is one detector hit on one file. It is the unit the pipeline
// persists (findings rows) and the CLI prints. Findings are value types with
// no pointers into scanned content, so they are safe to copy and sort.
type Finding struct {
	// RuleID is the stable identifier of the detector or signature that
	// fired, e.g. "S3/unicode-tag-block" or "S4/instruction-override-001".
	RuleID string
	// Scanner is the pipeline stage that produced the finding: "S3" or "S4".
	Scanner string
	// Severity is the gate-facing severity.
	Severity Severity
	// Confidence is the detector's confidence in the match.
	Confidence Confidence
	// Title is a short human-readable summary.
	Title string
	// FilePath is the repo-relative path of the scanned file.
	FilePath string
	// LineStart is the 1-based first line of the match (0 if not line-scoped).
	LineStart int
	// LineEnd is the 1-based last line of the match (== LineStart for a
	// single-line match).
	LineEnd int
	// Excerpt is a capped, single-line rendering of the offending text with
	// invisible and control characters shown as <U+XXXX> escapes so the hit
	// is legible in reports and terminals.
	Excerpt string
	// Detail carries structured, detector-specific context (counts, decoded
	// code points, matched pattern, and so on). Always non-nil on emitted
	// findings.
	Detail map[string]string
	// Taxonomy holds the OWASP ids for the finding.
	Taxonomy []string
}

// excerptMaxRunes caps rendered excerpts. ~200 characters keeps reports and
// webhook payloads bounded even when a line is pathologically long.
const excerptMaxRunes = 200

// renderExcerpt produces a single-line, length-capped rendering of s in which
// every non-graphic rune (zero-width, bidi, tag-block, private-use, control,
// and other format characters) is replaced by a visible <U+XXXX> escape.
// Ordinary spaces are preserved; tabs and newlines are escaped so the excerpt
// stays on one line. Invalid UTF-8 bytes are rendered as <U+FFFD>.
func renderExcerpt(s string) string {
	var b []rune
	count := 0
	appendRune := func(r rune) bool {
		if count >= excerptMaxRunes {
			return false
		}
		b = append(b, r)
		count++
		return true
	}
	appendStr := func(str string) bool {
		for _, r := range str {
			if !appendRune(r) {
				return false
			}
		}
		return true
	}

	truncated := false
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			if !appendStr("<U+FFFD>") {
				truncated = true
				break
			}
			i++
			continue
		}
		switch {
		case r == ' ':
			if !appendRune(' ') {
				truncated = true
			}
		case unicode.IsGraphic(r):
			if !appendRune(r) {
				truncated = true
			}
		default:
			if !appendStr(fmt.Sprintf("<U+%04X>", r)) {
				truncated = true
			}
		}
		if truncated {
			break
		}
		i += size
	}
	out := string(b)
	if truncated {
		out += "…"
	}
	return out
}

// sortFindings orders findings deterministically so scan output and report
// digests are reproducible: by file, then line, then rule id, then excerpt.
func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.FilePath != b.FilePath {
			return a.FilePath < b.FilePath
		}
		if a.LineStart != b.LineStart {
			return a.LineStart < b.LineStart
		}
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		return a.Excerpt < b.Excerpt
	})
}
