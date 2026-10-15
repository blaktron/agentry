package rules

import (
	"bytes"
	"path"
	"strings"
	"unicode/utf8"
)

// lineMap maps byte offsets in a file to 1-based line numbers and back to the
// text of a line. Lines are split on '\n'; a trailing '\r' is trimmed when a
// line's text is read so CRLF files report clean excerpts.
type lineMap struct {
	content []byte
	starts  []int // starts[i] is the byte offset of line i+1
}

// newLineMap indexes content by line.
func newLineMap(content []byte) *lineMap {
	starts := []int{0}
	for i, c := range content {
		if c == '\n' {
			starts = append(starts, i+1)
		}
	}
	return &lineMap{content: content, starts: starts}
}

// lineOf returns the 1-based line number containing byte offset off.
func (lm *lineMap) lineOf(off int) int {
	// Binary search for the greatest start <= off.
	lo, hi := 0, len(lm.starts)-1
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if lm.starts[mid] <= off {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	return lo + 1
}

// text returns the text of 1-based line n without its line terminator.
func (lm *lineMap) text(n int) string {
	if n < 1 || n > len(lm.starts) {
		return ""
	}
	start := lm.starts[n-1]
	end := len(lm.content)
	if n < len(lm.starts) {
		end = lm.starts[n] - 1 // exclude '\n'
	}
	line := lm.content[start:end]
	line = bytes.TrimSuffix(line, []byte("\r"))
	return string(line)
}

// count returns the number of lines.
func (lm *lineMap) count() int { return len(lm.starts) }

// proseExtensions are the file extensions the S4 signature engine
// scans. S4 targets prose and prompt files; code is handled by S6, not
// here.
var proseExtensions = map[string]bool{
	".md":       true,
	".markdown": true,
	".txt":      true,
	".text":     true,
	".yaml":     true,
	".yml":      true,
	".json":     true,
}

// isProseFile reports whether p should be scanned by S4. Files with no
// extension (LICENSE, NOTICE, skill entrypoints, etc.) count as prose.
func isProseFile(p string) bool {
	ext := strings.ToLower(path.Ext(p))
	if ext == "" {
		return true
	}
	return proseExtensions[ext]
}

// isMarkdownFile reports whether p is a Markdown document.
func isMarkdownFile(p string) bool {
	switch strings.ToLower(path.Ext(p)) {
	case ".md", ".markdown":
		return true
	default:
		return false
	}
}

// isHTMLBearingFile reports whether p may contain HTML markup that S3's
// CSS-hidden detector should inspect: HTML files and Markdown (which allows
// embedded raw HTML).
func isHTMLBearingFile(p string) bool {
	switch strings.ToLower(path.Ext(p)) {
	case ".html", ".htm", ".md", ".markdown":
		return true
	default:
		return false
	}
}

// isTextFile reports whether content looks like decodable text rather
// than a binary blob. S3 runs on all text files; binaries are S1's
// concern. The heuristic: no NUL byte and valid UTF-8 (empty content
// counts as text).
func isTextFile(content []byte) bool {
	if bytes.IndexByte(content, 0) >= 0 {
		return false
	}
	return utf8.Valid(content)
}
