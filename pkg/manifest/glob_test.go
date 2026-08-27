package manifest

import (
	"strings"
	"testing"
)

func TestMatchGlob(t *testing.T) {
	cases := []struct {
		pattern string
		path    string
		want    bool
	}{
		{"agent.yaml", "agent.yaml", true},
		{"agent.yaml", "agent.yml", false},
		{"agent.yaml", "sub/agent.yaml", false},
		{"*.md", "README.md", true},
		{"*.md", "docs/README.md", false},
		{"prompts/**", "prompts/system.md", true},
		{"prompts/**", "prompts/a/b/c.md", true},
		{"prompts/**", "prompts", true}, // "**" matches zero segments
		{"prompts/**", "prompt/system.md", false},
		{"**", "any/depth/file.txt", true},
		{"**/*.md", "README.md", true},
		{"**/*.md", "a/b/README.md", true},
		{"**/*.md", "a/b/README.txt", false},
		{"src/**/test/*.js", "src/a/b/test/x.js", true},
		{"src/**/test/*.js", "src/test/x.js", true},
		{"src/**/test/*.js", "src/a/test/sub/x.js", false},
		{"a?c/*", "abc/d", true},
		{"a?c/*", "abbc/d", false},
		{"[a-c]*/x", "b1/x", true},
		{"[a-c]*/x", "d1/x", false},
		{"a**b", "aXXb", true}, // inner ** is plain path.Match stars
		{"a**b", "a/b", false},
	}
	for _, tc := range cases {
		t.Run(tc.pattern+" vs "+tc.path, func(t *testing.T) {
			got, err := matchGlob(tc.pattern, tc.path)
			if err != nil {
				t.Fatalf("matchGlob: %v", err)
			}
			if got != tc.want {
				t.Fatalf("matchGlob(%q, %q) = %v, want %v", tc.pattern, tc.path, got, tc.want)
			}
		})
	}
}

func TestMatchGlobBadPattern(t *testing.T) {
	if _, err := matchGlob("docs/[a-", "docs/a"); err == nil {
		t.Fatalf("expected ErrBadPattern")
	}
}

// TestMatchGlobAdversarial guards the memoized matcher against
// exponential blowup on repeated "**" and alternating segments.
func TestMatchGlobAdversarial(t *testing.T) {
	pattern := strings.TrimSuffix(strings.Repeat("**/a/", 500), "/")
	p := strings.TrimSuffix(strings.Repeat("a/", 30), "/")
	if _, err := matchGlob(pattern, p); err != nil {
		t.Fatalf("matchGlob: %v", err)
	}
	pattern = strings.TrimSuffix(strings.Repeat("**/", 2000), "/") + "z"
	if got, err := matchGlob(pattern, p); err != nil || got {
		t.Fatalf("matchGlob = %v, %v", got, err)
	}
}

func TestScanPatternSegmentMatchesPathMatch(t *testing.T) {
	// scanPatternSegment must agree with path.Match's ErrBadPattern for
	// these shapes.
	bad := []string{`\`, `a\`, `[`, `[a-`, `[]`, `[a`, `[^`, `[-a]`}
	for _, seg := range bad {
		if err := scanPatternSegment(seg); err == nil {
			t.Errorf("scanPatternSegment(%q) = nil, want error", seg)
		}
	}
	good := []string{`a`, `*`, `?`, `[a-z]`, `[^a-z]`, `[abc]`, `\*`, `[\]]`, `a*b?c`, `[a-z][0-9]`}
	for _, seg := range good {
		if err := scanPatternSegment(seg); err != nil {
			t.Errorf("scanPatternSegment(%q) = %v, want nil", seg, err)
		}
	}
}
