package manifest

import (
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// The inputs declaration (V12): what files a QuickAgent takes and which
// view of them the agent reads by default. These tests pin its shape,
// that a manifest without it reads exactly as before (any kind, each
// file's own default), that it is a v2 field, and that it changes
// nothing about the contract.

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
	if got := m.TakesKinds(); !slices.Equal(got, []InputKind{InputKindCode, InputKindData}) {
		t.Fatalf("TakesKinds = %v", got)
	}
	if got := m.DefaultInputView(); got != InputViewOriginal {
		t.Fatalf("DefaultInputView = %q", got)
	}
}

// TestInputsAbsentKeepsTodaysBehaviour pins the compatibility rule: a
// manifest without the block takes any kind of file and leaves each
// file's own default view (a document's text, anything else as
// uploaded), which is what "both" means.
func TestInputsAbsentKeepsTodaysBehaviour(t *testing.T) {
	m := mustParse(t, v2YAML)
	if m.Inputs != nil {
		t.Fatalf("inputs = %+v", m.Inputs)
	}
	if got := m.TakesKinds(); !slices.Equal(got, []InputKind{InputKindAny}) {
		t.Fatalf("TakesKinds = %v, want [any]", got)
	}
	if got := m.DefaultInputView(); got != InputViewBoth {
		t.Fatalf("DefaultInputView = %q, want both", got)
	}
	// Half a declaration defaults the other half.
	m.Inputs = &Inputs{View: InputViewText}
	if got := m.TakesKinds(); !slices.Equal(got, []InputKind{InputKindAny}) {
		t.Fatalf("TakesKinds with only a view = %v, want [any]", got)
	}
	m.Inputs = &Inputs{Kinds: []InputKind{InputKindDocuments}}
	if got := m.DefaultInputView(); got != InputViewBoth {
		t.Fatalf("DefaultInputView with only kinds = %q, want both", got)
	}
	var nilM *Manifest
	if nilM.DefaultInputView() != InputViewBoth || !slices.Equal(nilM.TakesKinds(), []InputKind{InputKindAny}) {
		t.Fatal("a nil manifest does not read as undeclared")
	}
}

// TestInputsKindsAreTheCallersOwn: the slice TakesKinds returns may be
// changed without changing the manifest.
func TestInputsKindsAreTheCallersOwn(t *testing.T) {
	m := mustParse(t, inputsYAML)
	got := m.TakesKinds()
	got[0] = InputKindImages
	if m.Inputs.Kinds[0] != InputKindCode {
		t.Fatal("TakesKinds aliases the manifest's slice")
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
		{"empty kinds beside a view", &Inputs{Kinds: []InputKind{}, View: InputViewText}, "inputs.kinds"},
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
	// The whole contract a person consents to, not a field or two of it.
	if !reflect.DeepEqual(without.Contract(), with.Contract()) {
		t.Fatalf("inputs changed the contract:\n without: %+v\n with:    %+v", without.Contract(), with.Contract())
	}
	if d := DiffCapabilities(without.Contract(), with.Contract()); !d.Empty() {
		t.Fatalf("an inputs-only change widened or narrowed the contract: %+v", d)
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
	if _, err := Parse([]byte(inputsYAML + "  archives: unpack\n")); err == nil || !strings.Contains(err.Error(), "field archives not found") {
		t.Fatalf("an unknown field inside inputs was not refused by name: %v", err)
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
						MinItems    int  `json:"minItems"`
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
	if in.AdditionalProperties == nil || *in.AdditionalProperties || in.MinProperties != 1 || in.Properties.Kinds.MinItems != 1 || !in.Properties.Kinds.UniqueItems {
		t.Fatalf("the schema's inputs block is not closed, may be empty, or allows repeats: %+v", in)
	}
	kinds := []InputKind{InputKindDocuments, InputKindCode, InputKindData, InputKindImages, InputKindAny}
	views := []InputView{InputViewText, InputViewOriginal, InputViewBoth}
	var wantKinds, wantViews []string
	for _, k := range kinds {
		wantKinds = append(wantKinds, string(k))
	}
	for _, v := range views {
		wantViews = append(wantViews, string(v))
	}
	if !slices.Equal(in.Properties.Kinds.Items.Enum, wantKinds) || !slices.Equal(in.Properties.View.Enum, wantViews) {
		t.Fatalf("schema kinds %v views %v; Go kinds %v views %v", in.Properties.Kinds.Items.Enum, in.Properties.View.Enum, wantKinds, wantViews)
	}
	// Valid is the closed set the schema's enums name, and nothing else.
	for _, k := range kinds {
		if !k.Valid() {
			t.Errorf("%q is not Valid", k)
		}
	}
	for _, v := range views {
		if !v.Valid() {
			t.Errorf("%q is not Valid", v)
		}
	}
	if InputKind("Code").Valid() || InputKind("").Valid() || InputView("raw").Valid() || InputView("").Valid() {
		t.Error("Valid admits a value outside the closed set")
	}
}

// TestInputsEmptyKindsInYAMLIsRefused: `kinds: []` written out is refused
// as the schema refuses it (minItems), not read as "any".
func TestInputsEmptyKindsInYAMLIsRefused(t *testing.T) {
	m := mustParse(t, v2YAML+"\ninputs:\n  kinds: []\n  view: text\n")
	var hit bool
	for _, is := range blockingIssues(Validate(m)) {
		if is.Rule == "V12" && is.Path == "inputs.kinds" {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("kinds: [] was accepted: %v", Validate(m))
	}
}
