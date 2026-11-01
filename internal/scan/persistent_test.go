package scan

import (
	"slices"
	"strings"
	"testing"

	"github.com/blaktron/agentry/pkg/gatecases"
	"github.com/blaktron/agentry/pkg/manifest"
)

// A persistent release in the scanner: the gate's tokens for its block and
// its subagents, S6 reading its instruction and its persona against the
// block, and S9 counting a new key or a new or changed subagent.

const persistentScanYAML = `schemaVersion: "2"
name: helper
namespace: alice
version: 1.1.0
summary: "Keeps your week"
modes: [persistent]
capabilities:
  persistent:
    clock: true
persona:
  name: Ada
dependencies:
  agents:
    - ref: acme/pdf-summary
      version: ^1.4.0
      why: Summarises the PDFs in the share
publish:
  include: [agent.yaml, AGENT.md, PERSONA.md]
`

// persistentInput is a persistent release's scan input with the given
// manifest (persistentScanYAML when empty), instruction and persona.
func persistentInput(t *testing.T, doc, instruction, persona string) *Input {
	t.Helper()
	if doc == "" {
		doc = persistentScanYAML
	}
	m, err := manifest.Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := manifest.CanonicalJSON(m)
	if err != nil {
		t.Fatal(err)
	}
	return &Input{ManifestJSON: canonical, Files: []FileEntry{
		{Path: "agent.yaml", IsText: true, Content: []byte(doc)},
		{Path: "AGENT.md", IsText: true, Content: []byte(instruction)},
		{Path: "PERSONA.md", IsText: true, Content: []byte(persona)},
	}}
}

func TestAPersistentReleaseDeclaresAGateTokenPerKey(t *testing.T) {
	in := persistentInput(t, "", "", "")
	caps := declaredCaps(in.ManifestJSON)
	if !caps[gatecases.CapPersistent("clock")] || !caps[gatecases.CapSubagents] || caps[gatecases.CapPersistent("coder")] {
		t.Fatalf("declared = %v", caps)
	}
}

// The task tools need the clock and the helper tools need helper; an
// instruction or a persona that calls for either without it holds the
// version, one finding per file and key.
func TestS6ReadsTheInstructionAndThePersonaAgainstThePersistentBlock(t *testing.T) {
	in := persistentInput(t, "", "Add a task with `task_add` when asked. List what is installed with installed_list.",
		"You are Ada. You recall what was said with the `recall` tool.")
	got := map[string][]string{}
	for _, f := range s6UngrantedTools(in) {
		path, _ := f.Detail["path"].(string)
		got[f.FilePath] = append(got[f.FilePath], path)
		if f.Severity != SevHigh {
			t.Errorf("%s: severity %s", f.Title, f.Severity)
		}
		if f.FilePath == "PERSONA.md" && !strings.HasPrefix(f.Title, "The persona calls for") {
			t.Errorf("a persona's finding reads %q", f.Title)
		}
	}
	if !slices.Equal(got["AGENT.md"], []string{"capabilities.persistent.helper"}) {
		t.Errorf("the instruction's findings name %v; want only helper (the clock is declared)", got["AGENT.md"])
	}
	if !slices.Equal(got["PERSONA.md"], []string{"capabilities.persistent.memory"}) {
		t.Errorf("the persona's findings name %v; want memory", got["PERSONA.md"])
	}

	declared := persistentInput(t, strings.Replace(persistentScanYAML, "    clock: true\n", "    clock: true\n    memory: true\n    helper: true\n", 1),
		"Add a task with `task_add`. List what is installed with installed_list.", "You recall what was said with the `recall` tool.")
	if f := s6UngrantedTools(declared); len(f) != 0 {
		t.Fatalf("a release declaring each key is held: %+v", f)
	}
}

func TestS9CountsANewPersistentKeyAndANewOrChangedSubagent(t *testing.T) {
	prev := persistentInput(t, "", "", "")
	next := persistentInput(t, strings.NewReplacer(
		"    clock: true\n", "    clock: true\n    coder: true\n",
		"      why: Summarises the PDFs in the share\n", "      why: Summarises the PDFs in the share\n    - ref: acme/translate\n      version: ~1.1.0\n      why: Translates\n",
		"version: ^1.4.0", "version: ^2.0.0",
	).Replace(persistentScanYAML), "", "")
	next.PrevManifestJSON = prev.ManifestJSON

	var titles []string
	for _, f := range s9ManifestDiff(next) {
		if f.Scanner != "S9/capability-widened" || f.Severity != SevMedium {
			t.Errorf("unexpected finding %+v", f)
		}
		titles = append(titles, f.Title)
	}
	want := []string{
		"Capability newly declared this release: persistent.coder",
		"Subagent's versions changed this release: acme/pdf-summary ^1.4.0 → ^2.0.0",
		"Subagent newly declared this release: acme/translate ~1.1.0",
	}
	if !slices.Equal(titles, want) {
		t.Fatalf("S9 titles\n %q\nwant\n %q", titles, want)
	}

	same := persistentInput(t, "", "", "")
	same.PrevManifestJSON = prev.ManifestJSON
	if got := s9ManifestDiff(same); len(got) != 0 {
		t.Fatalf("the same release widens: %+v", got)
	}

	// The first subagent of a release that had none is reported by name,
	// not as a bare token.
	none := persistentInput(t, strings.Replace(persistentScanYAML,
		"dependencies:\n  agents:\n    - ref: acme/pdf-summary\n      version: ^1.4.0\n      why: Summarises the PDFs in the share\n", "", 1), "", "")
	first := persistentInput(t, "", "", "")
	first.PrevManifestJSON = none.ManifestJSON
	got := s9ManifestDiff(first)
	if len(got) != 1 || got[0].Title != "Subagent newly declared this release: acme/pdf-summary ^1.4.0" {
		t.Fatalf("the first subagent: %+v", got)
	}
}
