package manifest

import (
	"fmt"
	"slices"
)

// A QuickAgent may say what files it takes and how its agent reads them
// (plan quickagents-that-run.md M6, D1; agentry#892; DEV-218). The runner
// offers every input in two views since agentry-cli#631: `text`, the
// decoded text (a document's, HTML's Markdown), and `original`, the file
// as uploaded. Without a declaration each file keeps its own default (a
// document's text, anything else as uploaded) and any kind of file is
// taken, which is how every release published before the block reads.
// The kinds tell the run setup and the Drafter what to ask for; the view
// tells the runner which one the agent is pointed at first. Neither grants
// anything: attaching a file is the grant, so the block is outside the
// contract, as the guide is.

// InputKind is one kind of file a QuickAgent takes.
type InputKind string

// The closed set of input kinds (V12).
const (
	// InputKindDocuments is prose to read: PDFs, office documents, e-books,
	// rich text.
	InputKindDocuments InputKind = "documents"
	// InputKindCode is a codebase or its files: source, markup, build and
	// configuration files, a repository.
	InputKindCode InputKind = "code"
	// InputKindData is structured data: CSV, JSON, YAML, spreadsheets, logs.
	InputKindData InputKind = "data"
	// InputKindImages is pictures: photographs, scans, screenshots,
	// diagrams.
	InputKindImages InputKind = "images"
	// InputKindAny is no particular kind, and is declared alone.
	InputKindAny InputKind = "any"
)

// InputView is the view of an input the agent reads by default.
type InputView string

// The closed set of input views (V12).
const (
	// InputViewText points the agent at each input's decoded text, and at
	// the upload for a file that has none.
	InputViewText InputView = "text"
	// InputViewOriginal points the agent at each input as uploaded.
	InputViewOriginal InputView = "original"
	// InputViewBoth keeps each file's own default (a document's text,
	// anything else as uploaded) and says the agent uses both views. It is
	// what an undeclared view means.
	InputViewBoth InputView = "both"
)

// InputKinds returns the closed set of input kinds, in order.
func InputKinds() []InputKind {
	return []InputKind{InputKindDocuments, InputKindCode, InputKindData, InputKindImages, InputKindAny}
}

// InputViews returns the closed set of input views, in order.
func InputViews() []InputView {
	return []InputView{InputViewText, InputViewOriginal, InputViewBoth}
}

// Inputs is the manifest's inputs block (v2, V12).
type Inputs struct {
	// Kinds are the kinds of file the QuickAgent takes; absent means any.
	Kinds []InputKind `yaml:"kinds,omitempty" json:"kinds,omitempty"`
	// View is the view the agent reads an input in by default; absent
	// means both.
	View InputView `yaml:"view,omitempty" json:"view,omitempty"`
}

// InputKinds returns the kinds of file the release takes: its declared
// kinds, or [any] when it declares none. The slice is the caller's own.
func (m *Manifest) InputKinds() []InputKind {
	if m == nil || m.Inputs == nil || len(m.Inputs.Kinds) == 0 {
		return []InputKind{InputKindAny}
	}
	return slices.Clone(m.Inputs.Kinds)
}

// InputView returns the view the agent reads an input in by default: the
// declared view, or InputViewBoth (each file's own default) when the
// release declares none.
func (m *Manifest) InputView() InputView {
	if m == nil || m.Inputs == nil || m.Inputs.View == "" {
		return InputViewBoth
	}
	return m.Inputs.View
}

// validateInputs is V12: the block's shape.
func validateInputs(s *issues, m *Manifest) {
	in := m.Inputs
	if in == nil {
		return
	}
	if m.Major() != 2 {
		s.errf("V1", "inputs", "inputs is a v2 field; set schemaVersion: 2")
		return
	}
	if len(in.Kinds) == 0 && in.View == "" {
		s.errf("V12", "inputs", "inputs must declare kinds or a view")
	}
	seen := make(map[InputKind]bool, len(in.Kinds))
	for i, k := range in.Kinds {
		p := fmt.Sprintf("inputs.kinds[%d]", i)
		switch {
		case !slices.Contains(InputKinds(), k):
			s.errf("V12", p, "unknown input kind %q (documents | code | data | images | any)", k)
		case seen[k]:
			s.errf("V12", p, "input kind %q is declared twice", k)
		}
		seen[k] = true
	}
	if seen[InputKindAny] && len(in.Kinds) > 1 {
		s.errf("V12", "inputs.kinds", "any is declared alone: it already takes every kind")
	}
	if in.View != "" && !slices.Contains(InputViews(), in.View) {
		s.errf("V12", "inputs.view", "unknown input view %q (text | original | both)", in.View)
	}
}
