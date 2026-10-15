package rules

import "strings"

// File is one file handed to Scan: a repo-relative path and its raw bytes.
type File struct {
	// Path is the repo-relative, slash-separated file path.
	Path string
	// Content is the exact file bytes to scan.
	Content []byte
}

// Scan runs the S3 deterministic detectors and the S4 signature engine
// over a set of files and returns all findings, sorted
// deterministically. It is the convenience entry point used by both the
// server pipeline and `agentry validate`.
//
// Scanner reach:
//   - S3 runs on every text file.
//   - S4 runs only on prose-ish files (.md .markdown .txt .text .yaml .yml
//     .json and extensionless files).
//
// After both scanners run, Scan escalates any S3 HTML-comment finding
// whose hidden text matches an S4 signature from low to medium
// severity: a comment that hides an injection payload is worse than one
// that merely hides prose.
//
// bundle may be nil, in which case only S3 runs (useful for tests and for the
// hidden-content pass in isolation).
func Scan(bundle *Bundle, files []File) []Finding {
	var out []Finding
	for _, f := range files {
		s3 := ScanS3(f.Path, f.Content)
		if bundle != nil {
			escalateComments(bundle, s3)
		}
		out = append(out, s3...)
		if bundle != nil && isProseFile(f.Path) && isTextFile(f.Content) {
			out = append(out, bundle.Scan(f.Path, f.Content)...)
		}
	}
	sortFindings(out)
	return out
}

// escalateComments raises an HTML-comment finding to medium severity when its
// hidden comment text matches an S4 rule, recording the matched rule ids in
// the finding's Detail. It mutates the findings in place.
func escalateComments(bundle *Bundle, findings []Finding) {
	for i := range findings {
		f := &findings[i]
		if f.RuleID != "S3/html-comment" {
			continue
		}
		comment := f.Detail["comment"]
		if comment == "" {
			continue
		}
		if ids := bundle.MatchingRules(comment); len(ids) > 0 {
			f.Severity = SeverityMedium
			f.Detail["s4Match"] = strings.Join(ids, ", ")
		}
	}
}
