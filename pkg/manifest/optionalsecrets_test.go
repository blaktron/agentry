package manifest

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
)

// capabilities.optionalSecrets (V5, V10): the declared secrets a run
// can do without. These tests pin that the list names only declared
// secrets (so it never adds a name outside the contract), that it is a
// v2 field, that a manifest without it encodes exactly as before, that
// a flip between optional and required is no capability change, and
// that a secret intake question's required agrees with the secret that
// carries it.

const optionalSecretsYAML = `schemaVersion: "2"
name: repo-reader
namespace: acme
version: 1.0.0
summary: "Reads public repositories, and private ones with a token"
modes: [autonomous]
entrypoints:
  instruction: AGENT.md
intake:
  - id: github_token
    prompt: "A GitHub token, for private repositories"
    type: secret
capabilities:
  network:
    egress: [api.github.com]
  secrets: [GITHUB_TOKEN, ORG_TOKEN]
  optionalSecrets: [GITHUB_TOKEN, SEARCH_API_KEY]
  mcpServers:
    - npm: some-search-server
      version: 1.2.3
      secrets: [SEARCH_API_KEY]
publish:
  include: [agent.yaml, AGENT.md]
`

// errorIssues is every blocking issue Validate reports.
func errorIssues(t *testing.T, m *Manifest) []*Issue {
	t.Helper()
	return blockingIssues(Validate(m))
}

// publishIssues is every blocking issue the publish check reports:
// Validate plus the context rules, the secret-intake rule among them.
func publishIssues(t *testing.T, m *Manifest) []*Issue {
	t.Helper()
	return blockingIssues(ValidateInContext(m, Context{
		Namespace: m.Namespace,
		Name:      m.Name,
		Files:     []FileInfo{{Path: "agent.yaml", Size: 1}, {Path: "AGENT.md", Size: 1}},
	}))
}

func TestOptionalSecretsParseAndValidate(t *testing.T) {
	m := mustParse(t, optionalSecretsYAML)
	if got := m.Capabilities.OptionalSecrets; !slices.Equal(got, []string{"GITHUB_TOKEN", "SEARCH_API_KEY"}) {
		t.Fatalf("optionalSecrets = %v", got)
	}
	if errs := errorIssues(t, m); len(errs) != 0 {
		t.Fatalf("a valid optionalSecrets is refused: %v", errs)
	}
}

func TestOptionalSecretsRefusals(t *testing.T) {
	cases := []struct {
		name string
		list []string
		path string
		want string
	}{
		{"undeclared", []string{"GITHUB_TOKEN", "NOT_DECLARED"}, "capabilities.optionalSecrets[1]", "not a secret this release declares"},
		{"duplicate", []string{"GITHUB_TOKEN", "GITHUB_TOKEN"}, "capabilities.optionalSecrets[1]", "duplicate"},
		{"grammar", []string{"1BAD"}, "capabilities.optionalSecrets[0]", "not a valid environment variable name"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := mustParse(t, optionalSecretsYAML)
			m.Capabilities.OptionalSecrets = tc.list
			var hit bool
			for _, is := range errorIssues(t, m) {
				if is.Rule == "V5" && is.Path == tc.path && strings.Contains(is.Message, tc.want) {
					hit = true
				}
			}
			if !hit {
				t.Fatalf("%v not refused at %s with %q: %v", tc.list, tc.path, tc.want, errorIssues(t, m))
			}
		})
	}
}

// TestOptionalSecretsAddNothingToTheContract pins that a name may be
// optional only where the release already declares it, its own or a
// declared server's, so the list can never widen what a person consents
// to.
func TestOptionalSecretsAddNothingToTheContract(t *testing.T) {
	m := mustParse(t, optionalSecretsYAML)
	m.Capabilities.MCPServers = nil
	for _, is := range errorIssues(t, m) {
		if is.Rule == "V5" && is.Path == "capabilities.optionalSecrets[1]" && strings.Contains(is.Message, "not a secret this release declares") {
			return
		}
	}
	t.Fatalf("a server's secret stayed optional after the server was dropped: %v", errorIssues(t, m))
}

func TestOptionalSecretsIsAV2Field(t *testing.T) {
	m := mustParse(t, normativeYAML) // schema 1
	m.Capabilities.Secrets = []string{"GITHUB_TOKEN"}
	m.Capabilities.OptionalSecrets = []string{"GITHUB_TOKEN"}
	var hit bool
	for _, is := range errorIssues(t, m) {
		if is.Rule == "V1" && is.Path == "capabilities.optionalSecrets" {
			hit = true
		}
	}
	if !hit {
		t.Fatal("a v1 manifest may carry optionalSecrets")
	}
}

// TestNoOptionalSecretsEncodesAsBefore pins that a manifest that does
// not use the field has the same canonical JSON, and so the same digest
// and stored contract.
func TestNoOptionalSecretsEncodesAsBefore(t *testing.T) {
	without := mustParse(t, v2YAML)
	raw, err := CanonicalJSON(without)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "optionalSecrets") {
		t.Fatalf("a manifest without optionalSecrets encodes one: %s", raw)
	}
	contract, err := json.Marshal(without.Contract())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(contract), "optionalSecrets") {
		t.Fatalf("a contract without optionalSecrets carries one: %s", contract)
	}

	with := mustParse(t, optionalSecretsYAML)
	raw, err = CanonicalJSON(with)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"optionalSecrets":["GITHUB_TOKEN","SEARCH_API_KEY"]`) {
		t.Fatalf("optionalSecrets is not in the canonical JSON: %s", raw)
	}
	// The stored contract is read back into Capabilities by the account
	// install's diff; it keeps the marking, and an empty list encodes as
	// no list at all.
	var back Capabilities
	if contract, err = json.Marshal(with.Contract()); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(contract, &back); err != nil || !slices.Equal(back.OptionalSecrets, with.Capabilities.OptionalSecrets) {
		t.Fatalf("the stored contract loses optionalSecrets: %s (%v)", contract, err)
	}
	empty := mustParse(t, v2YAML)
	empty.Capabilities.OptionalSecrets = []string{}
	a, _ := CanonicalJSON(without)
	b, err := CanonicalJSON(empty)
	if err != nil || string(a) != string(b) {
		t.Fatalf("an empty optionalSecrets encodes differently from none:\n%s\n%s (%v)", a, b, err)
	}
}

// TestFlippingOptionalChangesNoCapability pins that the names and how
// each is scoped are the contract's access, and neither changes when a
// secret moves between optional and required, in either direction. A
// newly declared secret is still a widening, optional or not.
func TestFlippingOptionalChangesNoCapability(t *testing.T) {
	required := mustParse(t, optionalSecretsYAML)
	required.Capabilities.OptionalSecrets = nil
	optional := mustParse(t, optionalSecretsYAML)
	if d := DiffCapabilities(required.Capabilities, optional.Capabilities); !d.Empty() {
		t.Fatalf("required → optional changed the contract: %+v", d)
	}
	if d := DiffCapabilities(optional.Capabilities, required.Capabilities); !d.Empty() {
		t.Fatalf("optional → required changed the contract: %+v", d)
	}

	more := mustParse(t, optionalSecretsYAML)
	more.Capabilities.Secrets = append(more.Capabilities.Secrets, "EXTRA_TOKEN")
	more.Capabilities.OptionalSecrets = append(more.Capabilities.OptionalSecrets, "EXTRA_TOKEN")
	d := DiffCapabilities(optional.Capabilities, more.Capabilities)
	if !slices.Contains(d.Widened, "asks for a new secret: EXTRA_TOKEN") {
		t.Fatalf("a new optional secret did not widen: %+v", d)
	}
}

// TestSecretIntakeAgreesWithItsSecret pins that a secret question is
// carried by the release's own declared secret of its upper-cased id
// (the runner's rule), and its required must say what that secret's
// marking says, so the two can never disagree about whether a run may
// start without it.
func TestSecretIntakeAgreesWithItsSecret(t *testing.T) {
	t.Run("optional secret, optional question", func(t *testing.T) {
		if errs := publishIssues(t, mustParse(t, optionalSecretsYAML)); len(errs) != 0 {
			t.Fatalf("refused: %v", errs)
		}
	})
	t.Run("optional secret, required question", func(t *testing.T) {
		m := mustParse(t, optionalSecretsYAML)
		m.Intake[0].Required = true
		assertIntakeAgreement(t, m, "is required but the secret GITHUB_TOKEN that carries it is optional")
	})
	t.Run("required secret, optional question", func(t *testing.T) {
		m := mustParse(t, optionalSecretsYAML)
		m.Intake[0].ID = "org_token"
		assertIntakeAgreement(t, m, "is not required but the secret ORG_TOKEN that carries it is required")
	})
	t.Run("required secret, required question", func(t *testing.T) {
		m := mustParse(t, optionalSecretsYAML)
		m.Intake[0].ID = "org_token"
		m.Intake[0].Required = true
		if errs := publishIssues(t, m); len(errs) != 0 {
			t.Fatalf("refused: %v", errs)
		}
	})
	t.Run("no secret of that name", func(t *testing.T) {
		// Left to the runner, which refuses a secret question with nowhere
		// to go; the core's V10 has never judged it.
		m := mustParse(t, optionalSecretsYAML)
		m.Intake[0].ID = "unrelated"
		if errs := publishIssues(t, m); len(errs) != 0 {
			t.Fatalf("refused: %v", errs)
		}
	})
	t.Run("a server's secret does not carry a question", func(t *testing.T) {
		m := mustParse(t, optionalSecretsYAML)
		m.Intake[0].ID = "search_api_key"
		m.Intake[0].Required = true
		if errs := publishIssues(t, m); len(errs) != 0 {
			t.Fatalf("refused: %v", errs)
		}
	})
}

// TestAnInstalledReleaseKeepsRunning: the secret-intake rule is the
// publish check's alone. A release published without optionalSecrets,
// whose secret question does not say required over a (then necessarily
// required) secret, still passes Validate, which the CLI and the
// desktop run at install and at run, so it keeps running as it did;
// only its next publish is refused.
func TestAnInstalledReleaseKeepsRunning(t *testing.T) {
	m := mustParse(t, optionalSecretsYAML)
	m.Capabilities.OptionalSecrets = nil
	m.Capabilities.MCPServers = nil
	if errs := errorIssues(t, m); len(errs) != 0 {
		t.Fatalf("Validate refuses a pre-optionalSecrets release: %v", errs)
	}
	var hit bool
	for _, is := range publishIssues(t, m) {
		if is.Rule == "V10" && is.Path == "intake[0].required" {
			hit = true
		}
	}
	if !hit {
		t.Fatal("its next publish is not refused")
	}
}

func assertIntakeAgreement(t *testing.T, m *Manifest, want string) {
	t.Helper()
	for _, is := range publishIssues(t, m) {
		if is.Rule == "V10" && is.Path == "intake[0].required" && strings.Contains(is.Message, want) {
			return
		}
	}
	t.Fatalf("no V10 issue %q: %v", want, publishIssues(t, m))
}

// TestV2SchemaOptionalSecretsShape pins the JSON schema beside the Go rule.
func TestV2SchemaOptionalSecretsShape(t *testing.T) {
	raw, err := os.ReadFile("../../schemas/agent-manifest-2.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Properties struct {
			Capabilities struct {
				Properties map[string]struct {
					Type        string `json:"type"`
					UniqueItems bool   `json:"uniqueItems"`
					Items       struct {
						Pattern string `json:"pattern"`
					} `json:"items"`
				} `json:"properties"`
			} `json:"capabilities"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	props := schema.Properties.Capabilities.Properties
	got, ok := props["optionalSecrets"]
	if !ok {
		t.Fatal("the v2 schema has no capabilities.optionalSecrets")
	}
	if got.Type != "array" || !got.UniqueItems || got.Items.Pattern != props["secrets"].Items.Pattern {
		t.Fatalf("optionalSecrets = %+v; secrets' pattern %q", got, props["secrets"].Items.Pattern)
	}
	// Both are the environment variable name rule V5 holds a secret to, so
	// the two patterns cannot both drift, or both go empty, unnoticed.
	for name, pattern := range map[string]string{"secrets": props["secrets"].Items.Pattern, "optionalSecrets": got.Items.Pattern} {
		if pattern != envNameRE.String() {
			t.Errorf("schema %s item pattern is %q, want V5's %q", name, pattern, envNameRE.String())
		}
	}
}
