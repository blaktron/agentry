// Schema major 2 (DEV-088): modes, the single instruction entrypoint,
// intake and interactive hints, and the v1 reading path that maps the old
// kinds onto them. Every rule in the modes plan §3 has a failing and a
// passing case here.
package manifest

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
)

// v2YAML is the plan's §3 example: both modes, a named instruction file,
// one intake question, session hints.
const v2YAML = `schemaVersion: "2"
name: incident-summarizer
namespace: acme
version: 1.5.0
summary: "Summarizes PagerDuty incidents into postmortem drafts"
license: Apache-2.0
authors:
  - name: Jane Doe

modes: [autonomous, interactive]

entrypoints:
  instruction: AGENT.md

intake:
  - id: incident
    prompt: "Incident id or a path to its export"
    type: text
    required: true
  - id: region
    prompt: "Which region?"
    type: choice
    choices: [emea, apac, amer]

interactive:
  opening: "Which incident, and what do you need from it?"
  idleTimeoutSeconds: 900

runtime:
  models: ["claude-*"]
  interfaces: [claude-skill, agents-md]

capabilities:
  network:
    egress: [api.pagerduty.com]
  filesystem:
    read: workspace
    write:
      paths: [out]
  exec: none
  secrets: [PAGERDUTY_TOKEN]

publish:
  include: [agent.yaml, README.md, AGENT.md, prompts/**, LICENSE]
`

func validV2Manifest(t *testing.T) *Manifest {
	t.Helper()
	return mustParse(t, v2YAML)
}

// v2Context returns a Context under which validV2Manifest validates with
// zero issues, with the instruction file readable for V9.
func v2Context() Context {
	files := map[string]string{
		"AGENT.md": "---\nname: incident-summarizer\ndescription: Summarizes PagerDuty incidents into postmortem drafts\n---\nDo the work.\n",
	}
	return Context{
		Namespace:  "acme",
		Name:       "incident-summarizer",
		TagVersion: "v1.5.0",
		ExistingVersions: map[Channel][]string{
			ChannelStable: {"1.4.2"},
		},
		Public: true,
		Files: []FileInfo{
			{Path: "agent.yaml", Size: 500},
			{Path: "README.md", Size: 1200},
			{Path: "AGENT.md", Size: 5000},
			{Path: "prompts/system.md", Size: 900},
			{Path: "LICENSE", Size: 11000},
		},
		ReadFile: func(p string) ([]byte, error) {
			if c, ok := files[p]; ok {
				return []byte(c), nil
			}
			return nil, os.ErrNotExist
		},
	}
}

func TestV2ExampleParsesAndValidatesClean(t *testing.T) {
	m := validV2Manifest(t)
	if m.Major() != 2 || m.Kind != "" || len(m.Modes) != 2 {
		t.Fatalf("identity: major=%d kind=%q modes=%v", m.Major(), m.Kind, m.Modes)
	}
	if m.Entrypoints.Instruction != "AGENT.md" || len(m.Intake) != 2 || m.Interactive == nil || m.Interactive.IdleTimeoutSeconds != 900 {
		t.Fatalf("v2 fields: %+v %+v %+v", m.Entrypoints, m.Intake, m.Interactive)
	}
	wantClean(t, Validate(m))
	wantClean(t, ValidateInContext(m, v2Context()))
}

func TestV2ClosedSchemaOnNewFields(t *testing.T) {
	cases := map[string]string{
		"intake key":      strings.Replace(v2YAML, "required: true", "required: true\n    placeholder: x", 1),
		"interactive key": strings.Replace(v2YAML, "idleTimeoutSeconds: 900", "idleTimeoutSeconds: 900\n  theme: dark", 1),
		"entrypoints key": strings.Replace(v2YAML, "instruction: AGENT.md", "instruction: AGENT.md\n  binary: a.out", 1),
	}
	for name, y := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(y)); err == nil {
				t.Fatalf("expected unknown-key error")
			}
		})
	}
}

// TestV2ClassificationRules: V1's v2 half — modes required and closed,
// nothing kind-shaped, one instruction entrypoint, export interfaces only.
func TestV2ClassificationRules(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Manifest)
		pathSub string
	}{
		{"kind on v2", func(m *Manifest) { m.Kind = "skill" }, "kind"},
		{"missing modes", func(m *Manifest) { m.Modes = nil }, "modes"},
		{"empty modes", func(m *Manifest) { m.Modes = []Mode{} }, "modes"},
		{"unknown mode", func(m *Manifest) { m.Modes = []Mode{"batch"} }, "modes[0]"},
		{"duplicate mode", func(m *Manifest) { m.Modes = []Mode{ModeAutonomous, ModeAutonomous} }, "modes[1]"},
		{"v1 skill entrypoint", func(m *Manifest) { m.Entrypoints.Skill = "SKILL.md" }, "entrypoints.skill"},
		{"mcp entrypoint", func(m *Manifest) {
			m.Entrypoints.MCP = &MCPEntrypoint{Command: "node", Transport: TransportStdio}
		}, "entrypoints.mcp"},
		{"absolute instruction", func(m *Manifest) { m.Entrypoints.Instruction = "/etc/passwd" }, "entrypoints.instruction"},
		{"mcp interface", func(m *Manifest) { m.Runtime.Interfaces = []string{InterfaceMCP} }, "runtime.interfaces[0]"},
		{"unknown interface", func(m *Manifest) { m.Runtime.Interfaces = []string{"vscode"} }, "runtime.interfaces[0]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := validV2Manifest(t)
			tc.mutate(m)
			wantIssue(t, Validate(m), "V1", SeverityError, tc.pathSub)
		})
	}
}

func TestV2ClassificationPasses(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Manifest)
	}{
		{"autonomous only", func(m *Manifest) { m.Modes = []Mode{ModeAutonomous}; m.Interactive = nil }},
		{"interactive only", func(m *Manifest) { m.Modes = []Mode{ModeInteractive} }},
		{"no entrypoints block: AGENT.md by default", func(m *Manifest) { m.Entrypoints = Entrypoints{} }},
		{"SKILL.md-shaped instruction", func(m *Manifest) { m.Entrypoints.Instruction = "SKILL.md" }},
		{"no intake", func(m *Manifest) { m.Intake = nil }},
		{"no interfaces", func(m *Manifest) { m.Runtime.Interfaces = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := validV2Manifest(t)
			tc.mutate(m)
			wantClean(t, Validate(m))
		})
	}
}

// TestV1RefusesV2Fields: a v1 document may not smuggle in v2 shape.
func TestV1RefusesV2Fields(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Manifest)
		pathSub string
	}{
		{"modes", func(m *Manifest) { m.Modes = []Mode{ModeAutonomous} }, "modes"},
		{"intake", func(m *Manifest) { m.Intake = []IntakeQuestion{{ID: "x", Prompt: "x"}} }, "intake"},
		{"interactive", func(m *Manifest) { m.Interactive = &InteractiveHints{Opening: "hi"} }, "interactive"},
		{"instruction entrypoint", func(m *Manifest) { m.Entrypoints.Instruction = "AGENT.md" }, "entrypoints.instruction"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := validSkillManifest()
			tc.mutate(m)
			wantIssue(t, Validate(m), "V1", SeverityError, tc.pathSub)
		})
	}
}

// TestIntakeRules is V10's intake half.
func TestIntakeRules(t *testing.T) {
	q := func(id string, typ IntakeType, choices ...string) IntakeQuestion {
		return IntakeQuestion{ID: id, Prompt: "p", Type: typ, Choices: choices}
	}
	cases := []struct {
		name    string
		intake  []IntakeQuestion
		pathSub string
	}{
		{"missing id", []IntakeQuestion{{Prompt: "p"}}, "intake[0].id"},
		{"bad id", []IntakeQuestion{q("Data Set", IntakeText)}, "intake[0].id"},
		{"duplicate id", []IntakeQuestion{q("a", IntakeText), q("a", IntakeText)}, "intake[1].id"},
		{"missing prompt", []IntakeQuestion{{ID: "a", Prompt: "  "}}, "intake[0].prompt"},
		{"choice without choices", []IntakeQuestion{q("a", IntakeChoice)}, "intake[0].choices"},
		{"choices on text", []IntakeQuestion{q("a", IntakeText, "x")}, "intake[0].choices"},
		{"choices on secret", []IntakeQuestion{q("a", IntakeSecret, "x")}, "intake[0].choices"},
		{"empty choice", []IntakeQuestion{q("a", IntakeChoice, "x", "")}, "intake[0].choices[1]"},
		{"duplicate choice", []IntakeQuestion{q("a", IntakeChoice, "x", "x")}, "intake[0].choices[1]"},
		{"unknown type", []IntakeQuestion{q("a", "date")}, "intake[0].type"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := validV2Manifest(t)
			m.Intake = tc.intake
			wantIssue(t, Validate(m), "V10", SeverityError, tc.pathSub)
		})
	}
	t.Run("too many", func(t *testing.T) {
		m := validV2Manifest(t)
		m.Intake = nil
		for i := 0; i <= MaxIntakeQuestions; i++ {
			m.Intake = append(m.Intake, q("q"+strings.Repeat("a", i%5)+string(rune('a'+i%26))+string(rune('a'+i/26)), IntakeText))
		}
		wantIssue(t, Validate(m), "V10", SeverityError, "intake")
	})
	t.Run("every type passes", func(t *testing.T) {
		m := validV2Manifest(t)
		m.Intake = []IntakeQuestion{
			q("plain", ""), q("text", IntakeText), q("secret", IntakeSecret),
			q("file", IntakeFile), q("pick", IntakeChoice, "x", "y"),
		}
		wantClean(t, Validate(m))
	})
}

// TestInteractiveHints is V10's session-hints half.
func TestInteractiveHints(t *testing.T) {
	t.Run("opening too long", func(t *testing.T) {
		m := validV2Manifest(t)
		m.Interactive.Opening = strings.Repeat("x", MaxOpeningChars+1)
		wantIssue(t, Validate(m), "V10", SeverityError, "interactive.opening")
	})
	t.Run("negative idle timeout", func(t *testing.T) {
		m := validV2Manifest(t)
		m.Interactive.IdleTimeoutSeconds = -1
		wantIssue(t, Validate(m), "V10", SeverityError, "interactive.idleTimeoutSeconds")
	})
	t.Run("hints without the mode warn, not block", func(t *testing.T) {
		m := validV2Manifest(t)
		m.Modes = []Mode{ModeAutonomous}
		errs := Validate(m)
		wantIssue(t, errs, "V10", SeverityWarning, "interactive")
		if got := Blocking(errs); len(got) != 0 {
			t.Fatalf("hint mismatch must not block:%s", issueStrings(got))
		}
	})
}

// TestSupportedModes: the one place the v1 kinds are still interpreted.
func TestSupportedModes(t *testing.T) {
	v1 := func(kind string) *Manifest {
		m := validSkillManifest()
		m.Kind = kind
		return m
	}
	cases := []struct {
		name string
		m    *Manifest
		want []Mode
	}{
		{"v2 both", validV2Manifest(t), []Mode{ModeAutonomous, ModeInteractive}},
		{"v1 skill", v1("skill"), []Mode{ModeAutonomous}},
		{"v1 prompt-agent", v1("prompt-agent"), []Mode{ModeAutonomous}},
		{"v1 mcp-server", v1("mcp-server"), nil},
		{"v1 unknown", v1("binary"), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.m.SupportedModes()
			if strings.Join(modeStrings(got), ",") != strings.Join(modeStrings(tc.want), ",") {
				t.Fatalf("SupportedModes = %v, want %v", got, tc.want)
			}
		})
	}
	if !validV2Manifest(t).Supports(ModeInteractive) || v1("skill").Supports(ModeInteractive) {
		t.Fatal("Supports disagrees with SupportedModes")
	}
	// The returned slice is a copy: a caller cannot mutate the manifest.
	m := validV2Manifest(t)
	m.SupportedModes()[0] = "x"
	if m.Modes[0] != ModeAutonomous {
		t.Fatal("SupportedModes exposed the manifest's slice")
	}
}

func modeStrings(ms []Mode) []string {
	out := make([]string, len(ms))
	for i, m := range ms {
		out[i] = string(m)
	}
	return out
}

func TestInstructionCandidates(t *testing.T) {
	v1 := func(kind, skill string) *Manifest {
		m := validSkillManifest()
		m.Kind = kind
		m.Entrypoints.Skill = skill
		return m
	}
	v2 := validV2Manifest(t)
	v2Default := validV2Manifest(t)
	v2Default.Entrypoints = Entrypoints{}
	cases := []struct {
		name string
		m    *Manifest
		want string
	}{
		{"v2 named", v2, "AGENT.md"},
		{"v2 default", v2Default, DefaultInstructionFile},
		{"v1 skill", v1("skill", "SKILL.md"), "SKILL.md"},
		{"v1 skill without entrypoint", v1("skill", ""), ""},
		{"v1 prompt-agent", v1("prompt-agent", ""), "AGENT.md,PROMPT.md"},
		{"v1 prompt-agent with skill file", v1("prompt-agent", "SKILL.md"), "SKILL.md"},
		{"v1 mcp-server", v1("mcp-server", ""), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := strings.Join(tc.m.InstructionCandidates(), ","); got != tc.want {
				t.Fatalf("InstructionCandidates = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestV2InstructionMustShip: V4 requires the instruction file — named or
// the default — to exist and to be matched by publish.include.
func TestV2InstructionMustShip(t *testing.T) {
	t.Run("default AGENT.md missing", func(t *testing.T) {
		m := validV2Manifest(t)
		m.Entrypoints = Entrypoints{}
		ctx := v2Context()
		ctx.Files = deleteFile(ctx.Files, "AGENT.md")
		wantIssue(t, ValidateInContext(m, ctx), "V4", SeverityError, "entrypoints")
	})
	t.Run("named file not included", func(t *testing.T) {
		m := validV2Manifest(t)
		m.Entrypoints.Instruction = "docs/NOTES.md"
		ctx := v2Context()
		ctx.Files = append(ctx.Files, FileInfo{Path: "docs/NOTES.md", Size: 100}) // present, not in publish.include
		wantIssue(t, ValidateInContext(m, ctx), "V4", SeverityError, "publish.include")
	})
	t.Run("named file missing", func(t *testing.T) {
		m := validV2Manifest(t)
		m.Entrypoints.Instruction = "INSTRUCTIONS.md"
		wantIssue(t, ValidateInContext(m, v2Context()), "V4", SeverityError, "entrypoints")
	})
}

// TestV9OnInstructionFile: frontmatter is compared against the manifest
// for the v2 instruction file, under its own path label.
func TestV9OnInstructionFile(t *testing.T) {
	m := validV2Manifest(t)
	ctx := v2Context()
	ctx.ReadFile = func(string) ([]byte, error) {
		return []byte("---\nname: something-else\n---\nDo the work.\n"), nil
	}
	wantIssue(t, ValidateInContext(m, ctx), "V9", SeverityError, "entrypoints.instruction")
}

func TestCanonicalJSONV2(t *testing.T) {
	m := &Manifest{
		SchemaVersion: "2",
		Name:          "tiny",
		Namespace:     "acme",
		Modes:         []Mode{ModeInteractive},
		Version:       "0.1.0",
		Summary:       "Tiny interactive agent",
		Intake:        []IntakeQuestion{{ID: "topic", Prompt: "Topic?", Required: true}},
		Publish:       Publish{Include: []string{"agent.yaml", "AGENT.md"}},
	}
	got, err := CanonicalJSON(m)
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	want := `{"intake":[{"id":"topic","prompt":"Topic?","required":true}],"modes":["interactive"],"name":"tiny","namespace":"acme","publish":{"include":["agent.yaml","AGENT.md"]},"schemaVersion":"2","summary":"Tiny interactive agent","version":"0.1.0"}`
	if string(got) != want {
		t.Fatalf("canonical v2:\n got: %s\nwant: %s", got, want)
	}
	var back Manifest
	if err := json.Unmarshal(got, &back); err != nil {
		t.Fatalf("round trip: %v", err)
	}
	if back.Major() != 2 || !back.Supports(ModeInteractive) || back.Kind != "" {
		t.Fatalf("round trip lost v2 shape: %+v", back)
	}
}

// TestV2SchemaFileShape pins the JSON schema beside the Go rules: what is
// required, what is gone, and that the file is the closed shape V1 wants.
func TestV2SchemaFileShape(t *testing.T) {
	raw, err := os.ReadFile("../../schemas/agent-manifest-2.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Required             []string                   `json:"required"`
		AdditionalProperties bool                       `json:"additionalProperties"`
		Properties           map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	if schema.AdditionalProperties {
		t.Fatal("schema must be closed")
	}
	req := strings.Join(schema.Required, ",")
	if !strings.Contains(req, "modes") || strings.Contains(req, "kind") {
		t.Fatalf("required = %v", schema.Required)
	}
	for _, key := range []string{"modes", "intake", "interactive", "entrypoints"} {
		if _, ok := schema.Properties[key]; !ok {
			t.Fatalf("schema lacks %q", key)
		}
	}
	if _, ok := schema.Properties["kind"]; ok {
		t.Fatal("schema still has kind")
	}
	var ep struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(schema.Properties["entrypoints"], &ep); err != nil {
		t.Fatal(err)
	}
	if len(ep.Properties) != 1 || ep.Properties["instruction"] == nil {
		t.Fatalf("entrypoints must allow exactly instruction, got %v", ep.Properties)
	}
}

// TestV2SchemaEnvShape pins the mcpServer.env schema beside the Go rules:
// the count cap, the name grammar and the value limits are the constants
// pkg/manifest enforces. (The secret/env collision is a cross-list rule
// JSON schema cannot express; TestMCPServerEnvRefusals holds it.)
func TestV2SchemaEnvShape(t *testing.T) {
	raw, err := os.ReadFile("../../schemas/agent-manifest-2.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Defs struct {
			MCPServer struct {
				Properties struct {
					Env struct {
						Type          string `json:"type"`
						MaxProperties int    `json:"maxProperties"`
						PropertyNames struct {
							Pattern string `json:"pattern"`
						} `json:"propertyNames"`
						AdditionalProperties struct {
							Type      string `json:"type"`
							MaxLength int    `json:"maxLength"`
							Pattern   string `json:"pattern"`
						} `json:"additionalProperties"`
					} `json:"env"`
				} `json:"properties"`
			} `json:"mcpServer"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	env := schema.Defs.MCPServer.Properties.Env
	if env.Type != "object" || env.MaxProperties != MaxMCPServerEnv {
		t.Fatalf("env: type %q, maxProperties %d (want object, %d)", env.Type, env.MaxProperties, MaxMCPServerEnv)
	}
	if env.PropertyNames.Pattern != envNameRE.String() {
		t.Fatalf("env name pattern %q != %s", env.PropertyNames.Pattern, envNameRE)
	}
	ap := env.AdditionalProperties
	if ap.Type != "string" || ap.MaxLength != MaxMCPServerEnvValue {
		t.Fatalf("env value: type %q, maxLength %d (want string, %d)", ap.Type, ap.MaxLength, MaxMCPServerEnvValue)
	}
	valueRE := regexp.MustCompile(ap.Pattern)
	if !valueRE.MatchString("read-only") || valueRE.MatchString("a\nb") || valueRE.MatchString("a\tb") {
		t.Fatalf("env value pattern %q does not refuse exactly the control characters", ap.Pattern)
	}
}

// TestCanonicalJSONV2Env: a declared server's env is canonicalised with
// sorted keys, whatever order the YAML wrote them in.
func TestCanonicalJSONV2Env(t *testing.T) {
	doc := `schemaVersion: "2"
name: tiny
namespace: acme
modes: [autonomous]
version: 0.1.0
summary: "Tiny agent on a declared server"
capabilities:
  mcpServers:
    - npm: github-mcp-server-js
      version: 0.1.7
      env:
        LOGS_DIR: /tmp/logs
        GITHUB_PERMISSION: read-only
      tools: [list_issues]
      secrets: [GITHUB_TOKEN]
      egress: [api.github.com]
publish:
  include: [agent.yaml, AGENT.md]
`
	m := mustParse(t, doc)
	wantClean(t, Validate(m))
	got, err := CanonicalJSON(m)
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	want := `{"capabilities":{"mcpServers":[{"egress":["api.github.com"],"env":{"GITHUB_PERMISSION":"read-only","LOGS_DIR":"/tmp/logs"},"npm":"github-mcp-server-js","secrets":["GITHUB_TOKEN"],"tools":["list_issues"],"version":"0.1.7"}]},"modes":["autonomous"],"name":"tiny","namespace":"acme","publish":{"include":["agent.yaml","AGENT.md"]},"schemaVersion":"2","summary":"Tiny agent on a declared server","version":"0.1.0"}`
	if string(got) != want {
		t.Fatalf("canonical v2 env:\n got: %s\nwant: %s", got, want)
	}
}
