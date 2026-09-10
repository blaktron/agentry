package api

// The handle FieldError states the whole rule reHandle enforces rather than
// printing the pattern (agentry#260): a reader can act on "1-39 lowercase
// letters, digits and hyphens, starting and ending with a letter or digit",
// and cannot act on a regex. This test is what stops the sentence drifting
// from the pattern — widen reHandle and the bound asserted here fails.

import (
	"strings"
	"testing"
)

func TestHandleGlossMatchesReHandle(t *testing.T) {
	accept := []struct {
		name  string
		value string
	}{
		{"one character", "a"},
		{"one digit", "0"},
		{"hyphen inside", "acme-corp"},
		{"the stated maximum", strings.Repeat("a", 39)},
	}
	for _, c := range accept {
		if !reHandle.MatchString(c.value) {
			t.Errorf("reHandle rejects %s (%d chars), which the gloss promises is valid", c.name, len(c.value))
		}
	}
	reject := []struct {
		name  string
		value string
	}{
		{"one over the stated maximum", strings.Repeat("a", 40)},
		{"empty", ""},
		{"leading hyphen", "-acme"},
		{"trailing hyphen", "acme-"},
		{"uppercase", "Acme"},
		{"underscore", "acme_corp"},
	}
	for _, c := range reject {
		if reHandle.MatchString(c.value) {
			t.Errorf("reHandle accepts %s (%q), which the gloss says is invalid", c.name, c.value)
		}
	}
}
