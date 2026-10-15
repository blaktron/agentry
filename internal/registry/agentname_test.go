package registry

// CreateAgent's refusal states the whole rule AgentNameRe enforces rather
// than "invalid agent name", and the API renders that tail as
// the 422's detail. This test is what stops the sentence drifting from the
// pattern: widen or narrow AgentNameRe and the bound asserted here fails.

import (
	"strings"
	"testing"
)

func TestAgentNameGlossMatchesAgentNameRe(t *testing.T) {
	accept := []struct {
		name  string
		value string
	}{
		{"one character", "a"},
		{"one digit", "7"},
		{"hyphen inside", "code-reviewer"},
		{"the stated maximum", strings.Repeat("a", 65)},
	}
	for _, c := range accept {
		if !AgentNameRe.MatchString(c.value) {
			t.Errorf("AgentNameRe rejects %s (%d chars), which the refusal promises is valid", c.name, len(c.value))
		}
	}
	reject := []struct {
		name  string
		value string
	}{
		{"one over the stated maximum", strings.Repeat("a", 66)},
		{"empty", ""},
		{"leading hyphen", "-reviewer"},
		{"trailing hyphen", "reviewer-"},
		{"uppercase", "Reviewer"},
		{"underscore", "code_reviewer"},
		{"slash", "acme/reviewer"},
	}
	for _, c := range reject {
		if AgentNameRe.MatchString(c.value) {
			t.Errorf("AgentNameRe accepts %s (%q), which the refusal says is invalid", c.name, c.value)
		}
	}
}
