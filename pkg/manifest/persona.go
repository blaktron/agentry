package manifest

import (
	"slices"
	"strings"
	"unicode/utf8"
)

// Persona is the name and the text a persistent agent takes on (v2,
// V17). The text is a file in the archive, read by the scanners as they
// read the instruction; a tool it calls for needs its grant as one the
// instruction calls for does.
type Persona struct {
	// Name is the agent's name, shown to the person: one plain line of at
	// most MaxPersonaNameBytes.
	Name string `yaml:"name" json:"name"`
	// File is the persona's text in the archive, at most
	// MaxPersonaFileBytes; empty means DefaultPersonaFile.
	File string `yaml:"file,omitempty" json:"file,omitempty"`
	// Editable lets the person replace the persona's text; nil means
	// true. A locked persona can still be renamed.
	Editable *bool `yaml:"editable,omitempty" json:"editable,omitempty"`
}

// DefaultPersonaFile is the persona's file when the manifest names none.
const DefaultPersonaFile = "PERSONA.md"

// The persona's bounds, the ones a runner keeps for a person's own name
// and personality.
const (
	MaxPersonaNameBytes = 64
	MaxPersonaFileBytes = 32 << 10
)

// PersonaFile returns the persona's file in the archive; "" when the
// release ships no persona.
func (m *Manifest) PersonaFile() string {
	if m.Persona == nil {
		return ""
	}
	if m.Persona.File == "" {
		return DefaultPersonaFile
	}
	return m.Persona.File
}

// IsEditable reports whether the person may replace the persona's text.
func (p *Persona) IsEditable() bool { return p == nil || p.Editable == nil || *p.Editable }

// validatePersona is V17: persona is a v2 field, valid only with the
// persistent mode; its name is one plain line of at most
// MaxPersonaNameBytes; its file is a repository path other than the
// instruction.
func validatePersona(s *issues, m *Manifest) {
	p := m.Persona
	if p == nil {
		return
	}
	if m.Major() != 2 {
		s.errf("V1", "persona", "persona is a v2 field; set schemaVersion: 2")
		return
	}
	if !m.IsPersistent() {
		s.errf("V17", "persona", "a persona is for a persistent agent: add persistent to modes, or remove it")
	}
	switch {
	case strings.TrimSpace(p.Name) == "":
		s.errf("V17", "persona.name", "the persona's name must not be empty")
	case len(p.Name) > MaxPersonaNameBytes:
		s.errf("V17", "persona.name", "the persona's name is %d bytes; the maximum is %d", len(p.Name), MaxPersonaNameBytes)
	default:
		if msg := notPlain("the persona's name", p.Name); msg != "" {
			s.errf("V17", "persona.name", "%s", msg)
		}
	}
	f := m.PersonaFile()
	if err := checkRelFilePath(f); err != nil {
		s.errf("V17", "persona.file", "%v", err)
		return
	}
	if slices.Contains(m.InstructionCandidates(), f) {
		s.errf("V17", "persona.file", "%q is the instruction; the persona is a file of its own", f)
	}
}

// validatePersonaInContext is V17's archive half: the persona's file is in
// the repository, matched by publish.include, at most MaxPersonaFileBytes
// and UTF-8 text.
func validatePersonaInContext(s *issues, m *Manifest, ctx Context, resolved []FileInfo) {
	f := m.PersonaFile()
	if f == "" || checkRelFilePath(f) != nil {
		return
	}
	var found, included bool
	var size int64
	for _, c := range ctx.Files {
		if c.Path == f {
			found, size = true, c.Size
		}
	}
	for _, c := range resolved {
		if c.Path == f {
			included = true
		}
	}
	switch {
	case !found:
		s.errf("V17", "persona.file", "the persona's file %q is not in the repo", f)
		return
	case !included:
		s.errf("V17", "publish.include", "the persona's file %q is not matched by publish.include", f)
		return
	case size > MaxPersonaFileBytes:
		s.errf("V17", "persona.file", "the persona's file is %d bytes; the maximum is %d", size, MaxPersonaFileBytes)
		return
	}
	if ctx.ReadFile == nil {
		return
	}
	data, err := ctx.ReadFile(f)
	if err != nil {
		s.errf("V17", "persona.file", "reading the persona's file: %v", err)
		return
	}
	if !utf8.Valid(data) || slices.Contains(data, 0) {
		s.errf("V17", "persona.file", "the persona's file must be UTF-8 text")
	}
}
