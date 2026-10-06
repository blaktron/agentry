package manifest

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
)

// The inputs declaration (V12; plan quickagents-that-run.md M6, D1;
// agentry#892): what files a QuickAgent takes and which view of them the
// agent reads by default. These tests pin its shape, that a manifest
// without it reads exactly as before (any kind, each file's own default),
// that it is a v2 field, and that it changes nothing about the contract.

const inputsYAML = v2YAML + `
inputs:
  kinds: [code, data]
  view: original
`

func inputsIssues(t *testing.T, m *Manifest) []*Issue {
	t.Helper()
	var out []*Issue
	for _, is := range blockingIssues(Validate(m)) {
		if is.Rule == "V12" || strings.HasPrefix(is.Path, "inputs") {
			out = append(out, is)
		}
	}
	return out
}

func TestInputsParsesAndValidates(t *testing.T) {
	m := mustParse(t, inputsYAML)
	if m.Inputs == nil || !slices.Equal(m.Inputs.Kinds, []InputKind{InputKindCode, InputKindData}) || m.Inputs.View != InputViewOriginal {
		t.Fatalf("inputs = %+v", m.Inputs)
	}
	if errs := inputsIssues(t, m); len(errs) != 0 {
		t.Fatalf("a valid inputs declaration is refused: %v", errs)
	}
	if got := m.InputKinds(); !slices.Equal(got, []InputKind{InputKindCode, InputKindData}) {
		t.Fatalf("InputKinds = %v", got)
	}
	if got := m.InputView(); got != InputViewOriginal {
		t.Fatalf("InputView = %q", got)
	}
}

// TestInputsAbsentKeepsTodaysBehaviour is D1's compatibility rule: a
// manifest without the block, which is every release published before it,
// takes any kind of file and leaves each file's own default view (a
// document's text, anything else as uploaded), which is what "both" means.
func TestInputsAbsentKeepsTodaysBehaviour(t *testing.T) {
	m := mustParse(t, v2YAML)
	if m.Inputs != nil {
		t.Fatalf("inputs = %+v", m.Inputs)
	}
	if got := m.InputKinds(); !slices.Equal(got, []InputKind{InputKindAny}) {
		t.Fatalf("InputKinds = %v, want [any]", got)
	}
	if got := m.InputView(); got != InputViewBoth {
		t.Fatalf("InputView = %q, want both", got)
	}
	// Half a declaration defaults the other half.
	m.Inputs = &Inputs{View: InputViewText}
	if got := m.InputKinds(); !slices.Equal(got, []InputKind{InputKindAny}) {
		t.Fatalf("InputKinds with only a view = %v, want [any]", got)
	}
	m.Inputs = &Inputs{Kinds: []InputKind{InputKindDocuments}}
	if got := m.InputView(); got != InputViewBoth {
		t.Fatalf("InputView with only kinds = %q, want both", got)
	}
	var nilM *Manifest
	if nilM.InputView() != InputViewBoth || !slices.Equal(nilM.InputKinds(), []InputKind{InputKindAny}) {
		t.Fatal("a nil manifest does not read as undeclared")
	}
}

// TestInputsKindsAreTheCallersOwn: the slice InputKinds returns may be
// changed without changing the manifest.
func TestInputsKindsAreTheCallersOwn(t *testing.T) {
	m := mustParse(t, inputsYAML)
	got := m.InputKinds()
	got[0] = InputKindImages
	if m.Inputs.Kinds[0] != InputKindCode {
		t.Fatal("InputKinds aliases the manifest's slice")
	}
}

func TestInputsAccepts(t *testing.T) {
	for name, in := range map[string]*Inputs{
		"kinds only":         {Kinds: []InputKind{InputKindDocuments}},
		"view only":          {View: InputViewText},
		"every kind but any": {Kinds: []InputKind{InputKindDocuments, InputKindCode, InputKindData, InputKindImages}, View: InputViewBoth},
		"any alone":          {Kinds: []InputKind{InputKindAny}, View: InputViewOriginal},
	} {
		t.Run(name, func(t *testing.T) {
			m := mustParse(t, v2YAML)
			m.Inputs = in
			if errs := inputsIssues(t, m); len(errs) != 0 {
				t.Fatalf("refused: %v", errs)
			}
		})
	}
}

func TestInputsRefusals(t *testing.T) {
	cases := []struct {
		name string
		in   *Inputs
		path string
	}{
		{"empty block", &Inputs{}, "inputs"},
		{"unknown kind", &Inputs{Kinds: []InputKind{"spreadsheets"}}, "inputs.kinds[0]"},
		{"kind in the wrong case", &Inputs{Kinds: []InputKind{"Code"}}, "inputs.kinds[0]"},
		{"duplicate kind", &Inputs{Kinds: []InputKind{InputKindCode, InputKindData, InputKindCode}}, "inputs.kinds[2]"},
		{"any beside another kind", &Inputs{Kinds: []InputKind{InputKindDocuments, InputKindAny}}, "inputs.kinds"},
		{"unknown view", &Inputs{View: "raw"}, "inputs.view"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := mustParse(t, v2YAML)
			m.Inputs = c.in
			var hit bool
			for _, is := range blockingIssues(Validate(m)) {
				if is.Rule == "V12" && is.Path == c.path {
					hit = true
				}
			}
			if !hit {
				t.Fatalf("no V12 error at %s: %v", c.path, Validate(m))
			}
		})
	}
}

func TestInputsIsAV2Field(t *testing.T) {
	m := mustParse(t, normativeYAML) // schema 1
	m.Inputs = &Inputs{View: InputViewText}
	if !hasIssue(blockingIssues(Validate(m)), "V1", "inputs is a v2 field") {
		t.Fatalf("a v1 manifest may carry inputs: %v", Validate(m))
	}
}

// TestInputsChangesNothingAboutTheContract: the declaration says how the
// agent reads what a person hands it, and attaching a file is the grant,
// so a release that changes only its inputs asks no consent again, and a
// manifest without the block encodes exactly as before.
func TestInputsChangesNothingAboutTheContract(t *testing.T) {
	with := mustParse(t, inputsYAML)
	without := mustParse(t, v2YAML)
	if d := DiffCapabilities(without.Capabilities, with.Capabilities); !d.Empty() {
		t.Fatalf("an inputs-only change widened or narrowed the contract: %+v", d)
	}
	if !slices.Equal(with.Contract().Secrets, without.Contract().Secrets) {
		t.Fatal("inputs changed the contract")
	}
	raw, err := CanonicalJSON(without)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"inputs"`) {
		t.Fatalf("a manifest without inputs encodes one: %s", raw)
	}
	raw, err = CanonicalJSON(with)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"inputs":{"kinds":["code","data"],"view":"original"}`) {
		t.Fatalf("the declaration does not ride the canonical JSON: %s", raw)
	}
}

// TestInputsDecodingStaysStrict: the block is closed.
func TestInputsDecodingStaysStrict(t *testing.T) {
	if _, err := Parse([]byte(inputsYAML + "  archives: unpack\n")); err == nil {
		t.Fatal("an unknown field inside inputs was accepted")
	}
}

// TestV2SchemaInputsShape pins the JSON schema's inputs block to the Go
// vocabulary.
func TestV2SchemaInputsShape(t *testing.T) {
	raw, err := os.ReadFile("../../schemas/agent-manifest-2.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Properties struct {
			Inputs struct {
				AdditionalProperties *bool `json:"additionalProperties"`
				MinProperties        int   `json:"minProperties"`
				Properties           struct {
					Kinds struct {
						UniqueItems bool `json:"uniqueItems"`
						Items       struct {
							Enum []string `json:"enum"`
						} `json:"items"`
					} `json:"kinds"`
					View struct {
						Enum []string `json:"enum"`
					} `json:"view"`
				} `json:"properties"`
			} `json:"inputs"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	in := schema.Properties.Inputs
	if in.AdditionalProperties == nil || *in.AdditionalProperties || in.MinProperties != 1 || !in.Properties.Kinds.UniqueItems {
		t.Fatalf("the schema's inputs block is not closed, may be empty, or allows repeats: %+v", in)
	}
	var kinds, views []string
	for _, k := range InputKinds() {
		kinds = append(kinds, string(k))
	}
	for _, v := range InputViews() {
		views = append(views, string(v))
	}
	if !slices.Equal(in.Properties.Kinds.Items.Enum, kinds) || !slices.Equal(in.Properties.View.Enum, views) {
		t.Fatalf("schema kinds %v views %v; Go kinds %v views %v", in.Properties.Kinds.Items.Enum, in.Properties.View.Enum, kinds, views)
	}
}
