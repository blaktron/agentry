package manifest

import (
	"fmt"
	"slices"
)

// Input sources. An input source is where a run's inputs come from: the
// upload every run has, and the kinds an intake question asks for by
// its type, one type value per kind. A repository answer is an https
// git URL and an optional ref; a url answer is one https URL. A runner
// that supports sources fetches each answer before the run into
// /inputs/<question id>/, so the question's id names the folder, and
// the run setup asks for an optional access token beside it. The token
// belongs to the run, not to the manifest.
//
// A source is outside the contract, as an attached file is: giving the
// source is the grant. A source question declares no egress and no
// secret, needs no capabilities entry, and the scanner does not diff
// it. A later kind (a SharePoint library, say) is its IntakeType
// constant, its line in sourceTypes and in the schema's enum, its rule
// here where it needs one, and its fetch in the runner.

// sourceTypes are the intake types that ask for an input source.
var sourceTypes = []IntakeType{IntakeRepository, IntakeURL}

// IsSource reports whether an intake question of type t asks for an
// input source.
func (t IntakeType) IsSource() bool {
	return slices.Contains(sourceTypes, t)
}

// SourceTypes returns the intake types that ask for an input source. The
// slice is the caller's own.
func SourceTypes() []IntakeType {
	return slices.Clone(sourceTypes)
}

// validateSources is V13: what a source question says beyond V10's shape.
// It grants nothing, so nothing in capabilities is asked of it. A
// repository question stages a codebase, so it warns, without failing,
// when the release says it takes files but not code.
func validateSources(s *issues, m *Manifest) {
	if m.Major() != 2 || m.TakesKind(InputKindCode) {
		return
	}
	for i, q := range m.Intake {
		if q.Type == IntakeRepository {
			p := fmt.Sprintf("intake[%d]", i)
			s.warnf("V13", p+".type", "repository question %q stages a codebase in /inputs/%s/, but inputs.kinds does not take code: add code to inputs.kinds so the run setup and the Drafter say so", q.ID, q.ID)
		}
	}
}
