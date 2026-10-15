package api

// sentence() is the seam where a Go error's text becomes a problem detail.
// It is in-package because the style it
// enforces — capitalised, punctuated, no internal sentinel prefix — is the
// wire contract of every detail built from an error, and the handlers that
// call it are Postgres-gated.

import (
	"errors"
	"fmt"
	"testing"

	"github.com/blaktron/agentry/internal/registry"
)

func TestSentence(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"sentinel prefix stripped", fmt.Errorf("%w: visibility must be public or private", registry.ErrDenied).Error(),
			"Visibility must be public or private."},
		{"lowercase fragment capitalised", "an oidc connection needs an issuer and a clientId",
			"An oidc connection needs an issuer and a clientId."},
		{"period appended", "the submission has no agent.yaml", "The submission has no agent.yaml."},
		{"terminal period kept", "Must be an https:// URL.", "Must be an https:// URL."},
		{"terminal question mark kept", "which namespace?", "Which namespace?"},
		{"terminal exclamation kept", "Stop!", "Stop!"},
		{"surrounding space trimmed", "  needs a rationale  ", "Needs a rationale."},
		{"empty stays empty", "", ""},
		{"bare sentinel stays empty", registry.ErrDenied.Error(), ""},
		{"already capitalised is untouched apart from the period", "The gate rejected this version",
			"The gate rejected this version."},
		{"digits and code spans survive", "manifest V1: kind: unknown kind \"tool\"",
			"Manifest V1: kind: unknown kind \"tool\"."},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := sentence(c.in); got != c.want {
				t.Fatalf("sentence(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// The sentinel prefix must come from the sentinel, not from a literal: a
// change to ErrDenied's own text must not leave the prefix on the wire.
func TestSentenceStripsWhateverErrDeniedSays(t *testing.T) {
	wrapped := fmt.Errorf("%w: %s", registry.ErrDenied, "the daily version quota is reached")
	if got, want := sentence(wrapped.Error()), "The daily version quota is reached."; got != want {
		t.Fatalf("sentence(%q) = %q, want %q", wrapped, got, want)
	}
	// A different sentinel keeps its own words: only ErrDenied's label is a
	// pure prefix with no information in it.
	other := fmt.Errorf("%w: published → yanked", errors.New("registry: illegal state transition"))
	if got, want := sentence(other.Error()), "Registry: illegal state transition: published → yanked."; got != want {
		t.Fatalf("sentence(%q) = %q, want %q", other, got, want)
	}
}
