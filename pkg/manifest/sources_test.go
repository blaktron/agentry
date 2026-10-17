package manifest

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
)

// Input sources (V13): the intake types repository and url ask for a
// source the runner fetches into /inputs/<id>/. These tests pin that
// both types validate, that a source question grants nothing and asks
// nothing of capabilities, that a repository question warns without
// failing when the release does not take code, and that the schema's
// enum is the Go set.

// sourcesManifest is v2YAML with a repository and a url question appended
// to its intake.
func sourcesManifest(t *testing.T) *Manifest {
	t.Helper()
	y := strings.Replace(v2YAML, "\ninteractive:", `  - id: repo
    prompt: "The repository to audit"
    type: repository
    required: true
  - id: advisory
    prompt: "The advisory to check against"
    type: url

interactive:`, 1)
	return mustParse(t, y)
}

// sourceIssues splits Validate's result into every blocking issue and the
// V13 warnings.
func sourceIssues(errs []error) (blocking, warnings []*Issue) {
	for _, err := range errs {
		is, ok := AsIssue(err)
		switch {
		case !ok:
			continue
		case is.Severity == SeverityError:
			blocking = append(blocking, is)
		case is.Rule == "V13":
			warnings = append(warnings, is)
		}
	}
	return blocking, warnings
}

func TestSourceQuestionsParseAndValidate(t *testing.T) {
	m := sourcesManifest(t)
	var got []IntakeQuestion
	for _, q := range m.Intake {
		if q.Type.IsSource() {
			got = append(got, q)
		}
	}
	if len(got) != 2 || got[0].ID != "repo" || got[0].Type != IntakeRepository || !got[0].Required || got[1].ID != "advisory" || got[1].Type != IntakeURL {
		t.Fatalf("source questions = %+v", got)
	}
	if b, w := sourceIssues(Validate(m)); len(b) != 0 || len(w) != 0 {
		t.Fatalf("a release that takes any kind is refused or warned: %v %v", b, w)
	}
}

// TestSourceQuestionIDsKeepV10: the id names the source's folder under
// /inputs, so V10's id rules hold for a source question as for any other:
// the pattern (no dot, no slash, nothing a folder name could escape with)
// and uniqueness.
func TestSourceQuestionIDsKeepV10(t *testing.T) {
	for _, c := range []struct {
		name string
		ids  []string
		path string
	}{
		{"escaping id", []string{"../repo"}, "intake[0].id"},
		{"dotted id", []string{"repo.git"}, "intake[0].id"},
		{"duplicate id", []string{"repo", "repo"}, "intake[1].id"},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := validV2Manifest(t)
			m.Intake = nil
			for _, id := range c.ids {
				m.Intake = append(m.Intake, IntakeQuestion{ID: id, Prompt: "p", Type: IntakeRepository})
			}
			wantIssue(t, Validate(m), "V10", SeverityError, c.path)
		})
	}
}

func TestSourceTypesAreTheClosedSet(t *testing.T) {
	if !slices.Equal(SourceTypes(), []IntakeType{IntakeRepository, IntakeURL}) {
		t.Fatalf("SourceTypes() = %v", SourceTypes())
	}
	for _, typ := range []IntakeType{"", IntakeText, IntakeSecret, IntakeChoice, IntakeFile, "sharepoint-library"} {
		if typ.IsSource() {
			t.Errorf("%q is a source type", typ)
		}
	}
	st := SourceTypes()
	st[0] = IntakeText
	if !IntakeRepository.IsSource() || SourceTypes()[0] != IntakeRepository {
		t.Fatal("mutating the result of SourceTypes() changed the package's set")
	}
}

// TestSourceQuestionGrantsNothing: a source question is outside the
// contract: adding one widens nothing, and it validates with no egress,
// no secret and no capabilities entry of its own.
func TestSourceQuestionGrantsNothing(t *testing.T) {
	with := sourcesManifest(t)
	without := mustParse(t, v2YAML)
	if d := DiffCapabilities(without.Capabilities, with.Capabilities); !d.Empty() {
		t.Fatalf("adding source questions widened or narrowed the contract: %+v", d)
	}
	if !slices.Equal(with.Contract().Secrets, without.Contract().Secrets) || !slices.Equal(with.Contract().Network.Egress.Hosts, without.Contract().Network.Egress.Hosts) {
		t.Fatal("source questions changed the contract")
	}

	// No egress to the source's host, no secret for its token, nothing at all.
	m := validV2Manifest(t)
	m.Capabilities = Capabilities{}
	m.Intake = []IntakeQuestion{
		{ID: "repo", Prompt: "Repository", Type: IntakeRepository, Required: true},
		{ID: "doc", Prompt: "Document", Type: IntakeURL},
	}
	if b, _ := sourceIssues(Validate(m)); len(b) != 0 {
		t.Fatalf("a source question asked something of capabilities: %v", b)
	}
	// The publish-time secret rule does not read a source question as a
	// secret, even where a secret of its upper-cased id is declared.
	m.Capabilities.Secrets = []string{"REPO"}
	var s issues
	validateSecretIntakeAgreement(&s, m)
	if len(s.list) != 0 {
		t.Fatalf("a source question was held to the secret rule: %v", s.list)
	}
}

// TestRepositoryQuestionWarnsWithoutCode: a repository question in a
// release whose inputs.kinds lacks code warns, never fails. Any, code and
// an absent block take code; a url question never warns.
func TestRepositoryQuestionWarnsWithoutCode(t *testing.T) {
	cases := []struct {
		name  string
		in    *Inputs
		typ   IntakeType
		warns bool
	}{
		{"no inputs block", nil, IntakeRepository, false},
		{"view only", &Inputs{View: InputViewOriginal}, IntakeRepository, false},
		{"code", &Inputs{Kinds: []InputKind{InputKindDocuments, InputKindCode}}, IntakeRepository, false},
		{"any", &Inputs{Kinds: []InputKind{InputKindAny}}, IntakeRepository, false},
		{"documents only", &Inputs{Kinds: []InputKind{InputKindDocuments}}, IntakeRepository, true},
		{"data and images", &Inputs{Kinds: []InputKind{InputKindData, InputKindImages}}, IntakeRepository, true},
		{"url, documents only", &Inputs{Kinds: []InputKind{InputKindDocuments}}, IntakeURL, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := validV2Manifest(t)
			m.Inputs = c.in
			m.Intake = []IntakeQuestion{{ID: "first", Prompt: "p"}, {ID: "src", Prompt: "p", Type: c.typ}}
			errs := Validate(m)
			b, w := sourceIssues(errs)
			if len(b) != 0 {
				t.Fatalf("a source question is refused: %v", b)
			}
			if !c.warns {
				if len(w) != 0 {
					t.Fatalf("unexpected warning: %v", w)
				}
				return
			}
			wantIssue(t, errs, "V13", SeverityWarning, "intake[1].type")
			if len(w) != 1 || !strings.Contains(w[0].Message, `"src"`) || !strings.Contains(w[0].Message, "/inputs/src/") {
				t.Fatalf("the warning does not name the question and its folder: %v", w)
			}
		})
	}
}

// TestV2SchemaIntakeTypes: the schema's type enum is the Go set, in order.
func TestV2SchemaIntakeTypes(t *testing.T) {
	raw, err := os.ReadFile("../../schemas/agent-manifest-2.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Defs struct {
			IntakeQuestion struct {
				Properties struct {
					Type struct {
						Enum []string `json:"enum"`
					} `json:"type"`
				} `json:"properties"`
			} `json:"intakeQuestion"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, typ := range intakeTypes {
		want = append(want, string(typ))
	}
	if !slices.Equal(intakeTypes[len(intakeTypes)-len(SourceTypes()):], SourceTypes()) {
		t.Fatalf("the source types are not the last of the intake types: %v", intakeTypes)
	}
	if got := schema.Defs.IntakeQuestion.Properties.Type.Enum; !slices.Equal(got, want) {
		t.Fatalf("schema intake types %v; Go %v", got, want)
	}
}

// TestV2SchemaRefusesControlCharactersInIntakeAndOpening pins the schema's
// patterns beside V10: a prompt and a choice are single plain lines, as the
// guide's one-line parts are, and the opening keeps newlines and tabs, as
// the guide's overview does.
func TestV2SchemaRefusesControlCharactersInIntakeAndOpening(t *testing.T) {
	raw, err := os.ReadFile("../../schemas/agent-manifest-2.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	type str struct {
		Pattern string `json:"pattern"`
	}
	var schema struct {
		Properties struct {
			Interactive struct {
				Properties struct {
					Opening str `json:"opening"`
				} `json:"properties"`
			} `json:"interactive"`
			Guide struct {
				Properties struct {
					Overview str `json:"overview"`
					Task     str `json:"task"`
				} `json:"properties"`
			} `json:"guide"`
		} `json:"properties"`
		Defs struct {
			IntakeQuestion struct {
				Properties struct {
					Prompt  str `json:"prompt"`
					Choices struct {
						Items str `json:"items"`
					} `json:"choices"`
				} `json:"properties"`
			} `json:"intakeQuestion"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	line, markdown := schema.Properties.Guide.Properties.Task.Pattern, schema.Properties.Guide.Properties.Overview.Pattern
	if line == "" || markdown == "" {
		t.Fatal("the guide's patterns are not where this test reads them")
	}
	q := schema.Defs.IntakeQuestion.Properties
	for name, got := range map[string]string{"intake prompt": q.Prompt.Pattern, "intake choice": q.Choices.Items.Pattern} {
		if got != line {
			t.Errorf("schema %s pattern is %q, want the guide's one-line %q", name, got, line)
		}
	}
	if got := schema.Properties.Interactive.Properties.Opening.Pattern; got != markdown {
		t.Errorf("schema opening pattern is %q, want the guide overview's %q", got, markdown)
	}
}
