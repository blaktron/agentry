package rules

import "testing"

func TestIsATXHeading(t *testing.T) {
	for line, want := range map[string]bool{
		"# Findings":         true,
		"###### Six":         true,
		"#":                  true,
		"## Review\r":        true,
		"   # three spaces":  true,
		"#\tTabbed":          true,
		"    # code block":   false,
		"####### seven":      false,
		"#hashtag":           false,
		"##\u00a0Findings":   true,
		"#\u3000Ideographic": true,
		"###\u2003Em space":  true,
		"#\u200bzero-width":  false,
		"Findings":           false,
		"":                   false,
	} {
		if got := isATXHeading(line); got != want {
			t.Errorf("isATXHeading(%q) = %v, want %v", line, got, want)
		}
	}
}
