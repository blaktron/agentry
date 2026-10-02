package rules

import "testing"

func TestIsATXHeading(t *testing.T) {
	for line, want := range map[string]bool{
		"# Findings":        true,
		"###### Six":        true,
		"#":                 true,
		"## Review\r":       true,
		"   # three spaces": true,
		"#\tTabbed":         true,
		"    # code block":  false,
		"####### seven":     false,
		"#hashtag":          false,
		"Findings":          false,
		"":                  false,
	} {
		if got := isATXHeading(line); got != want {
			t.Errorf("isATXHeading(%q) = %v, want %v", line, got, want)
		}
	}
}
