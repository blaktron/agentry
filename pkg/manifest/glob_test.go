package manifest

import (
	"errors"
	"path"
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
	_, err := matchGlob("docs/[a-", "docs/a")
	if !errors.Is(err, path.ErrBadPattern) {
		t.Fatalf("expected ErrBadPattern, got %v", err)
	}
	if err == nil || !strings.Contains(err.Error(), `include pattern "docs/[a-"`) {
		t.Fatalf("the error does not name the pattern: %v", err)
	}
}

// TestMatchGlobAdversarial guards the memoized matcher against
// exponential blowup on repeated "**" and alternating segments.
func TestMatchGlobAdversarial(t *testing.T) {
	pattern := strings.TrimSuffix(strings.Repeat("**/a/", 500), "/")
	p := strings.TrimSuffix(strings.Repeat("a/", 30), "/")
	// 500 "a" segments cannot match a path of 30, so the answer is no.
	if got, err := matchGlob(pattern, p); err != nil || got {
		t.Fatalf("matchGlob = %v, %v, want false, nil", got, err)
	}
	// The same shape that does match: 30 "a" segments against 30.
	if got, err := matchGlob(strings.TrimSuffix(strings.Repeat("**/a/", 30), "/"), p); err != nil || !got {
		t.Fatalf("matchGlob = %v, %v, want true, nil", got, err)
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
	// An escape consumes the character after it, whatever that character
	// is: an escaped bracket is a literal, not the start of a class.
	good := []string{`a`, `*`, `?`, `[a-z]`, `[^a-z]`, `[abc]`, `\*`, `[\]]`, `a*b?c`, `[a-z][0-9]`, `\[`, `\\`, `a\[b`}
	for _, seg := range good {
		if err := scanPatternSegment(seg); err != nil {
			t.Errorf("scanPatternSegment(%q) = %v, want nil", seg, err)
		}
	}
	// And the verdict is path.Match's own, for every one of them.
	for _, seg := range append(append([]string(nil), bad...), good...) {
		_, want := path.Match(seg, "x")
		if got := scanPatternSegment(seg); (got != nil) != (want != nil) {
			t.Errorf("scanPatternSegment(%q) = %v, but path.Match says %v", seg, got, want)
		}
	}
}
