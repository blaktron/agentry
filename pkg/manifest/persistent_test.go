package manifest

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
)

// A persistent release: capabilities.persistent (V16) with its memory/ and
// skills/ folders, the persona (V17) and the subagents (V18). These tests
// pin each rule's refusals and passes, that the block and the subagents
// are in the contract and the capability diff, and the schema.

const persistentYAML = `schemaVersion: "2"
name: helper
namespace: alice
version: 1.0.0
summary: "Keeps your notes and your week in order"
license: MIT
modes: [persistent]

capabilities:
  network:
    egress: none
  secrets: [NOTES_API_KEY]
  persistent:
    clock: true
    memory: true
    skills: true
    secrets: [GITHUB_TOKEN]
    selfConfigure: true
    calendars: true
    meetings: true
    mail: [google, fastmail]
    imageServers: [google-workspace]
    coder: true
    web: true
    helper: true
    review: true

persona:
  name: Ada

dependencies:
  agents:
    - ref: acme/pdf-summary
      version: ^1.4.0
      why: Summarises the PDFs you drop in the share

publish:
  include: [agent.yaml, README.md, AGENT.md, PERSONA.md, LICENSE, memory/**, skills/**]
`

func persistentManifest(t *testing.T) *Manifest {
	t.Helper()
	return mustParse(t, persistentYAML)
}

// persistentContext is a publish context under which persistentManifest
// validates with no issue at all.
func persistentContext(files map[string]string) Context {
	all := map[string]string{
		"agent.yaml":                  "x",
		"README.md":                   "# Helper",
		"AGENT.md":                    "Keep the person's week.",
		"PERSONA.md":                  "You are Ada: brisk, warm and exact.",
		"LICENSE":                     "MIT",
		"memory/SCHEMA.md":            "# The memory",
		"skills/weekly-plan/SKILL.md": "---\nname: weekly-plan\ndescription: Plan the week\n---\nPlan it.",
	}
	for k, v := range files {
		if v == "" {
			delete(all, k)
			continue
		}
		all[k] = v
	}
	var infos []FileInfo
	for p, c := range all {
		infos = append(infos, FileInfo{Path: p, Size: int64(len(c)), IsText: true})
	}
	return Context{
		Namespace: "alice", Name: "helper", Public: true, Files: infos,
		ReadFile: func(p string) ([]byte, error) {
			if c, ok := all[p]; ok {
				return []byte(c), nil
			}
			return nil, os.ErrNotExist
		},
	}
}

func TestAPersistentReleaseParsesAndValidates(t *testing.T) {
	m := persistentManifest(t)
	p := m.Capabilities.Persistent
	want := []string{"clock", "memory", "skills", "secrets", "selfConfigure", "calendars", "meetings", "mail", "imageServers", "coder", "web", "helper", "review"}
	if got := p.Keys(); !slices.Equal(got, want) {
		t.Fatalf("Keys() = %v; want %v", got, want)
	}
	if m.Persona == nil || m.Persona.Name != "Ada" || m.PersonaFile() != DefaultPersonaFile || !m.Persona.IsEditable() {
		t.Fatalf("persona = %+v, file %q", m.Persona, m.PersonaFile())
	}
	if got := m.Subagents(); len(got) != 1 || got[0].Ref != "acme/pdf-summary" || got[0].Why == "" {
		t.Fatalf("Subagents() = %+v", got)
	}
	wantClean(t, Validate(m))
	wantClean(t, ValidateInContext(m, persistentContext(nil)))
}

// Every key the block can name is one of PersistentCapabilities, so the
// closed set and its words cannot drift apart.
func TestEveryPersistentKeyHasWords(t *testing.T) {
	all := &Persistent{Clock: true, Memory: true, Skills: true, Secrets: []string{"A"}, SelfConfigure: true, Calendars: true,
		Meetings: true, Mail: []string{"fastmail"}, ImageServers: []string{"microsoft-365"}, Coder: true, Web: true, Helper: true, Review: true}
	caps := PersistentCapabilities()
	if got := all.Keys(); len(got) != len(caps) {
		t.Fatalf("a block declaring everything has keys %v; the set has %d", got, len(caps))
	}
	for _, c := range caps {
		if c.Words == "" || !all.Declares(c.Key) {
			t.Errorf("key %q: words %q, declared %v", c.Key, c.Words, all.Declares(c.Key))
		}
	}
	if (*Persistent)(nil).Declares("clock") || all.Declares("teleport") {
		t.Fatal("a nil block or an unknown key is declared")
	}
}

func TestV16RefusesWhatTheBlockCannotMean(t *testing.T) {
	cases := []struct {
		name string
		edit func(m *Manifest)
		path string
	}{
		{"not a persistent agent", func(m *Manifest) { m.Modes = []Mode{ModeAutonomous} }, "capabilities.persistent"},
		{"declares nothing", func(m *Manifest) { m.Capabilities.Persistent = &Persistent{} }, "capabilities.persistent"},
		{"a secret that is no variable name", func(m *Manifest) { m.Capabilities.Persistent.Secrets = []string{"GITHUB-TOKEN"} }, "capabilities.persistent.secrets[0]"},
		{"a secret twice", func(m *Manifest) { m.Capabilities.Persistent.Secrets = []string{"A", "A"} }, "capabilities.persistent.secrets[1]"},
		{"a stored secret that is also a run secret", func(m *Manifest) { m.Capabilities.Persistent.Secrets = []string{"NOTES_API_KEY"} }, "capabilities.persistent.secrets[0]"},
		{"too many secrets", func(m *Manifest) {
			m.Capabilities.Persistent.Secrets = nil
			for i := 0; i <= MaxPersistentSecrets; i++ {
				m.Capabilities.Persistent.Secrets = append(m.Capabilities.Persistent.Secrets, "S"+strings.Repeat("X", i))
			}
		}, "capabilities.persistent.secrets"},
		{"an unknown mail provider", func(m *Manifest) { m.Capabilities.Persistent.Mail = []string{"yahoo"} }, "capabilities.persistent.mail[0]"},
		{"a mail provider twice", func(m *Manifest) { m.Capabilities.Persistent.Mail = []string{"fastmail", "fastmail"} }, "capabilities.persistent.mail[1]"},
		{"an unknown image server", func(m *Manifest) { m.Capabilities.Persistent.ImageServers = []string{"gog"} }, "capabilities.persistent.imageServers[0]"},
		{"google mail without its server", func(m *Manifest) { m.Capabilities.Persistent.ImageServers = nil }, "capabilities.persistent.mail[0]"},
		{"microsoft mail without its server", func(m *Manifest) { m.Capabilities.Persistent.Mail = []string{"microsoft"} }, "capabilities.persistent.mail[0]"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := persistentManifest(t)
			c.edit(m)
			wantIssue(t, Validate(m), "V16", SeverityError, c.path)
		})
	}

	m := persistentManifest(t)
	m.SchemaVersion = "1"
	m.Modes, m.Kind = nil, v1KindPromptAgent
	wantIssue(t, Validate(m), "V1", SeverityError, "capabilities.persistent")
}

func TestV16ReadsTheFoldersOnlyWithTheirKeys(t *testing.T) {
	// Without memory and skills, the folders are left unread: a warning
	// each, never a refusal, so a release that carries them for another
	// reason still publishes.
	m := persistentManifest(t)
	m.Capabilities.Persistent.Memory, m.Capabilities.Persistent.Skills = false, false
	errs := ValidateInContext(m, persistentContext(nil))
	wantIssue(t, errs, "V16", SeverityWarning, "publish.include")
	if len(Blocking(errs)) != 0 {
		t.Fatalf("folders without their keys block: %s", issueStrings(errs))
	}
	if n := strings.Count(issueStrings(errs), "V16"); n != 2 {
		t.Fatalf("want a warning for memory/ and one for skills/:%s", issueStrings(errs))
	}

	// With skills, each folder is a skill with its SKILL.md.
	for name, files := range map[string]map[string]string{
		"a skill without SKILL.md":   {"skills/weekly-plan/SKILL.md": "", "skills/weekly-plan/notes.md": "x"},
		"a file beside the folders":  {"skills/README.md": "x"},
		"a second skill without one": {"skills/inbox/steps.md": "x"},
	} {
		t.Run(name, func(t *testing.T) {
			wantIssue(t, ValidateInContext(persistentManifest(t), persistentContext(files)), "V16", SeverityError, "publish.include")
		})
	}

	// An autonomous release's folders are its own business.
	auto := persistentManifest(t)
	auto.Modes = []Mode{ModeAutonomous}
	auto.Capabilities.Persistent, auto.Persona = nil, nil
	for _, err := range ValidateInContext(auto, persistentContext(map[string]string{"skills/README.md": "x"})) {
		if is, _ := AsIssue(err); is.Rule == "V16" {
			t.Fatalf("an autonomous release's skills/ is read by V16: %v", is)
		}
	}
}

func TestV17RefusesWhatThePersonaCannotBe(t *testing.T) {
	cases := []struct {
		name string
		edit func(m *Manifest)
		rule string
		path string
	}{
		{"not a persistent agent", func(m *Manifest) { m.Modes = []Mode{ModeAutonomous}; m.Capabilities.Persistent = nil }, "V17", "persona"},
		{"no name", func(m *Manifest) { m.Persona.Name = "  " }, "V17", "persona.name"},
		{"a name too long", func(m *Manifest) { m.Persona.Name = strings.Repeat("a", MaxPersonaNameBytes+1) }, "V17", "persona.name"},
		{"a name with an escape", func(m *Manifest) { m.Persona.Name = "Ada\x1b[31m" }, "V17", "persona.name"},
		{"a name with a bidi override", func(m *Manifest) { m.Persona.Name = "Ada\u202e" }, "V17", "persona.name"},
		{"the instruction as the persona", func(m *Manifest) { m.Persona.File = "AGENT.md" }, "V17", "persona.file"},
		{"a path out of the repo", func(m *Manifest) { m.Persona.File = "../PERSONA.md" }, "V17", "persona.file"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := persistentManifest(t)
			c.edit(m)
			wantIssue(t, Validate(m), c.rule, SeverityError, c.path)
		})
	}

	inContext := []struct {
		name  string
		edit  func(m *Manifest)
		files map[string]string
		path  string
	}{
		{"the file missing", nil, map[string]string{"PERSONA.md": ""}, "persona.file"},
		{"the file not included", func(m *Manifest) {
			m.Publish.Include = slices.DeleteFunc(m.Publish.Include, func(p string) bool { return p == "PERSONA.md" })
		}, nil, "publish.include"},
		{"the file too big", nil, map[string]string{"PERSONA.md": strings.Repeat("a", MaxPersonaFileBytes+1)}, "persona.file"},
		{"the file not text", nil, map[string]string{"PERSONA.md": "Ada\x00"}, "persona.file"},
	}
	for _, c := range inContext {
		t.Run(c.name, func(t *testing.T) {
			m := persistentManifest(t)
			if c.edit != nil {
				c.edit(m)
			}
			wantIssue(t, ValidateInContext(m, persistentContext(c.files)), "V17", SeverityError, c.path)
		})
	}

	m := persistentManifest(t)
	locked := false
	m.Persona = &Persona{Name: "Ada", File: "persona/ada.md", Editable: &locked}
	if m.PersonaFile() != "persona/ada.md" || m.Persona.IsEditable() {
		t.Fatalf("a named, locked persona reads file %q, editable %v", m.PersonaFile(), m.Persona.IsEditable())
	}
	m.Publish.Include = append(m.Publish.Include, "persona/**")
	wantClean(t, ValidateInContext(m, persistentContext(map[string]string{"PERSONA.md": "", "persona/ada.md": "You are Ada."})))
}

func TestV18MakesAPersistentReleasesDependenciesSubagents(t *testing.T) {
	cases := []struct {
		name string
		edit func(d *AgentDependency)
		path string
	}{
		{"no constraint", func(d *AgentDependency) { d.Version = "" }, ".version"},
		{"no why", func(d *AgentDependency) { d.Why = "" }, ".why"},
		{"a why too long", func(d *AgentDependency) { d.Why = strings.Repeat("a", MaxSubagentWhyChars+1) }, ".why"},
		{"a why on two lines", func(d *AgentDependency) { d.Why = "one\ntwo" }, ".why"},
		{"itself", func(d *AgentDependency) { d.Ref = "alice/helper" }, ".ref"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := persistentManifest(t)
			c.edit(&m.Dependencies.Agents[0])
			wantIssue(t, Validate(m), "V18", SeverityError, "dependencies.agents[0]")
		})
	}

	m := persistentManifest(t)
	m.Dependencies.Agents = append(m.Dependencies.Agents, m.Dependencies.Agents[0])
	wantIssue(t, Validate(m), "V18", SeverityError, "dependencies.agents[1].ref")

	m = persistentManifest(t)
	for i := 0; i < MaxSubagents; i++ {
		m.Dependencies.Agents = append(m.Dependencies.Agents, AgentDependency{Ref: "acme/a" + strings.Repeat("b", i), Version: "^1.0.0", Why: "One more"})
	}
	wantIssue(t, Validate(m), "V18", SeverityError, "dependencies.agents")

	// An autonomous release's dependencies stay informational: no
	// constraint or why is required, none is a subagent, but a why given
	// is still one plain line.
	auto := persistentManifest(t)
	auto.Modes = []Mode{ModeAutonomous}
	auto.Capabilities.Persistent, auto.Persona = nil, nil
	auto.Dependencies.Agents = []AgentDependency{{Ref: "acme/pdf-summary"}}
	wantClean(t, Validate(auto))
	if auto.Subagents() != nil || auto.Contract().Subagents != nil {
		t.Fatal("an autonomous release has subagents")
	}
	auto.Dependencies.Agents[0].Why = "a\x1bb"
	wantIssue(t, Validate(auto), "V18", SeverityError, "dependencies.agents[0].why")
}

func TestASubagentsConstraintAllowsVersions(t *testing.T) {
	d := AgentDependency{Ref: "acme/pdf-summary", Version: "^1.4.0"}
	for v, want := range map[string]bool{"1.4.0": true, "1.9.2": true, "1.3.9": false, "2.0.0": false, "v1.4.0": false, "nope": false} {
		if got := d.SubagentAllows(v); got != want {
			t.Errorf("^1.4.0 allows %s: %v; want %v", v, got, want)
		}
	}
	if (AgentDependency{Version: "not a range"}).SubagentAllows("1.0.0") {
		t.Error("a constraint that does not parse allows a version")
	}
}

// The block and the subagents are in the contract and the canonical JSON,
// so consent, search and the judge's declared capabilities read them; the
// persona is not a grant and stays outside it.
func TestThePersistentBlockAndSubagentsAreInTheContract(t *testing.T) {
	m := persistentManifest(t)
	c := m.Contract()
	if c.Persistent == nil || !c.Persistent.Coder || len(c.Subagents) != 1 || c.Subagents[0].Version != "^1.4.0" {
		t.Fatalf("Contract() = %+v", c)
	}
	raw, err := CanonicalJSON(m)
	if err != nil {
		t.Fatal(err)
	}
	var back Manifest
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(back.Capabilities.Persistent.Keys(), m.Capabilities.Persistent.Keys()) || back.Persona.Name != "Ada" ||
		back.Dependencies.Agents[0].Why != m.Dependencies.Agents[0].Why {
		t.Fatalf("the canonical form does not read back: %s", raw)
	}
	contract, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(contract), `"persistent":{`) || !strings.Contains(string(contract), `"subagents":[`) {
		t.Fatalf("the contract's JSON lacks the block or the subagents: %s", contract)
	}
}

func TestDiffCapabilitiesPersistent(t *testing.T) {
	old := persistentManifest(t).Contract()

	next := persistentManifest(t)
	next.Capabilities.Persistent.Coder = false
	next.Capabilities.Persistent.Mail = []string{"google", "fastmail", "microsoft"}
	next.Capabilities.Persistent.ImageServers = []string{"google-workspace", "microsoft-365"}
	next.Capabilities.Persistent.Secrets = nil
	next.Dependencies.Agents[0].Version = "^2.0.0"
	next.Dependencies.Agents = append(next.Dependencies.Agents, AgentDependency{Ref: "acme/translate", Version: "~1.1.0", Why: "Translates"})

	d := DiffCapabilities(old, next.Contract())
	for _, want := range []string{"adds a mail provider: microsoft", "adds a image server: microsoft-365", "adds a subagent: acme/translate ~1.1.0",
		"changes the versions it may run of subagent acme/pdf-summary: ^1.4.0 → ^2.0.0"} {
		if !slices.Contains(d.Widened, want) {
			t.Errorf("Widened %q missing from %v", want, d.Widened)
		}
	}
	for _, want := range []string{"drops a persistent capability: coder", "drops a persistent capability: secrets"} {
		if !slices.Contains(d.Narrowed, want) {
			t.Errorf("Narrowed %q missing from %v", want, d.Narrowed)
		}
	}

	back := DiffCapabilities(next.Contract(), old)
	if !slices.Contains(back.Widened, "adds a persistent capability: coder ("+persistentCapabilities[9].Words+")") ||
		!slices.Contains(back.Narrowed, "drops a subagent: acme/translate") {
		t.Fatalf("the reverse diff = %+v", back)
	}

	none := Capabilities{}
	if d := DiffCapabilities(none, old); len(d.Widened) != len(old.Persistent.Keys())+2 {
		t.Fatalf("a whole new block widens by %d lines; want one per key, the run secret and the subagent: %v", len(d.Widened), d.Widened)
	}
	if !DiffCapabilities(old, persistentManifest(t).Contract()).Empty() {
		t.Fatal("the same contract differs")
	}
	why := persistentManifest(t)
	why.Dependencies.Agents[0].Why = "Reads the PDFs"
	if !DiffCapabilities(old, why.Contract()).Empty() {
		t.Fatal("a new why asks again; it is words, not reach")
	}
}

// TestV2SchemaPersistentShape pins the JSON schema beside the Go rule: the
// block's keys are the closed set, its enums are the names a runner
// carries, and the persona and the why are there.
func TestV2SchemaPersistentShape(t *testing.T) {
	raw, err := os.ReadFile("../../schemas/agent-manifest-2.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Properties struct {
			Capabilities struct {
				Properties struct {
					Persistent struct {
						AdditionalProperties bool `json:"additionalProperties"`
						Properties           map[string]struct {
							Items struct {
								Enum []string `json:"enum"`
							} `json:"items"`
						} `json:"properties"`
					} `json:"persistent"`
				} `json:"properties"`
			} `json:"capabilities"`
			Persona struct {
				Required   []string                   `json:"required"`
				Properties map[string]json.RawMessage `json:"properties"`
			} `json:"persona"`
		} `json:"properties"`
		Defs struct {
			AgentDependency struct {
				Properties map[string]json.RawMessage `json:"properties"`
			} `json:"agentDependency"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	p := schema.Properties.Capabilities.Properties.Persistent
	if p.AdditionalProperties {
		t.Fatal("the schema's persistent block is open")
	}
	var keys []string
	for k := range p.Properties {
		keys = append(keys, k)
	}
	var want []string
	for _, c := range PersistentCapabilities() {
		want = append(want, c.Key)
	}
	slices.Sort(keys)
	slices.Sort(want)
	if !slices.Equal(keys, want) {
		t.Fatalf("schema keys %v; Go keys %v", keys, want)
	}
	if got := p.Properties["mail"].Items.Enum; !slices.Equal(got, MailProviderNames) {
		t.Errorf("schema mail %v; Go %v", got, MailProviderNames)
	}
	if got := p.Properties["imageServers"].Items.Enum; !slices.Equal(got, ImageServerNames) {
		t.Errorf("schema imageServers %v; Go %v", got, ImageServerNames)
	}
	for _, k := range []string{"name", "file", "editable"} {
		if _, ok := schema.Properties.Persona.Properties[k]; !ok {
			t.Errorf("the schema's persona has no %s", k)
		}
	}
	if !slices.Equal(schema.Properties.Persona.Required, []string{"name"}) {
		t.Errorf("the schema's persona requires %v", schema.Properties.Persona.Required)
	}
	if _, ok := schema.Defs.AgentDependency.Properties["why"]; !ok {
		t.Error("the schema's agentDependency has no why")
	}
}
