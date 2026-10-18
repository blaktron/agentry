package manifest

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"unicode/utf8"
)

// The guide block (V10): the author's words for the run setup, shown to
// people before a run. These tests pin its bounds, that a connect key
// names a declared secret, that it is a v2 field, and that it changes
// nothing about the security contract: two releases that differ only in
// their guide have an empty capability diff.

const guideYAML = v2YAML + `
guide:
  overview: |
    Reads an incident's export and writes a postmortem draft.

    It **never** pages anyone.
  prepare:
    - The incident's export, as JSON
    - Who was on call
  files: "The incident export, and optionally the chat log."
  task: "e.g. INC-4821, focus on the timeline"
  connect:
    PAGERDUTY_TOKEN: "A read-only API key: PagerDuty → Integrations → API Access Keys"
`

func guideIssues(t *testing.T, y string) []*Issue {
	t.Helper()
	var out []*Issue
	for _, err := range Validate(mustParse(t, y)) {
		if is, ok := AsIssue(err); ok && is.Severity == SeverityError {
			out = append(out, is)
		}
	}
	return out
}

func TestGuideParsesAndValidates(t *testing.T) {
	m := mustParse(t, guideYAML)
	g := m.Guide
	if g == nil || !strings.Contains(g.Overview, "postmortem draft") || len(g.Prepare) != 2 ||
		g.Files == "" || g.Task == "" || g.Connect["PAGERDUTY_TOKEN"] == "" {
		t.Fatalf("guide = %+v", g)
	}
	if errs := guideIssues(t, guideYAML); len(errs) != 0 {
		t.Fatalf("a valid guide is refused: %v", errs)
	}
}

func TestGuideRefusals(t *testing.T) {
	base := mustParse(t, guideYAML)
	cases := []struct {
		name string
		edit func(g *Guide)
		path string
	}{
		{"overview too long", func(g *Guide) { g.Overview = strings.Repeat("a", MaxGuideOverviewBytes+1) }, "guide.overview"},
		{"overview with NUL", func(g *Guide) { g.Overview = "a\x00b" }, "guide.overview"},
		{"too many prepare items", func(g *Guide) {
			g.Prepare = make([]string, MaxGuidePrepare+1)
			for i := range g.Prepare {
				g.Prepare[i] = "x"
			}
		}, "guide.prepare"},
		{"empty prepare item", func(g *Guide) { g.Prepare = []string{""} }, "guide.prepare[0]"},
		{"prepare item too long", func(g *Guide) { g.Prepare = []string{strings.Repeat("é", MaxGuidePrepareChars+1)} }, "guide.prepare[0]"},
		{"prepare item on two lines", func(g *Guide) { g.Prepare = []string{"one\ntwo"} }, "guide.prepare[0]"},
		{"files too long", func(g *Guide) { g.Files = strings.Repeat("a", MaxGuideFilesChars+1) }, "guide.files"},
		{"task with a control character", func(g *Guide) { g.Task = "a\tb" }, "guide.task"},
		{"task of spaces", func(g *Guide) { g.Task = "   " }, "guide.task"},
		{"prepare item of spaces", func(g *Guide) { g.Prepare = []string{" "} }, "guide.prepare[0]"},
		{"connect help with a bidi override", func(g *Guide) {
			g.Connect = map[string]string{"PAGERDUTY_TOKEN": "paste it at https://evil.example/\u202Etxt.moc.ytudrepgap"}
		}, "guide.connect.PAGERDUTY_TOKEN"},
		{"files with a zero-width space", func(g *Guide) { g.Files = "the con\u200Btract" }, "guide.files"},
		{"overview with a C1 control", func(g *Guide) { g.Overview = "a\u0085b" }, "guide.overview"},
		// ESC starts a terminal escape sequence (colours, OSC 8 links,
		// OSC 52 clipboard writes); CR rewrites a printed line.
		{"overview with ESC", func(g *Guide) { g.Overview = "a\x1b]52;c;ZXZpbA==\x07b" }, "guide.overview"},
		{"overview with CR", func(g *Guide) { g.Overview = "first line\rrewritten" }, "guide.overview"},
		{"overview with BEL", func(g *Guide) { g.Overview = "a\x07b" }, "guide.overview"},
		{"overview with DEL", func(g *Guide) { g.Overview = "a\x7fb" }, "guide.overview"},
		{"connect for an undeclared secret", func(g *Guide) { g.Connect = map[string]string{"AWS_SECRET": "x"} }, "guide.connect.AWS_SECRET"},
		{"empty connect help", func(g *Guide) { g.Connect = map[string]string{"PAGERDUTY_TOKEN": ""} }, "guide.connect.PAGERDUTY_TOKEN"},
		{"connect help too long", func(g *Guide) {
			g.Connect = map[string]string{"PAGERDUTY_TOKEN": strings.Repeat("é", MaxGuideConnectChars+1)}
		}, "guide.connect.PAGERDUTY_TOKEN"},
		// The help is Markdown over several lines, and keeps the
		// overview's character rule.
		{"connect help of blank lines", func(g *Guide) { g.Connect = map[string]string{"PAGERDUTY_TOKEN": "\n\t\n"} }, "guide.connect.PAGERDUTY_TOKEN"},
		{"connect help with ESC", func(g *Guide) {
			g.Connect = map[string]string{"PAGERDUTY_TOKEN": "Create a key\x1b]8;;https://evil.example/\x07here"}
		}, "guide.connect.PAGERDUTY_TOKEN"},
		{"connect help with CR", func(g *Guide) { g.Connect = map[string]string{"PAGERDUTY_TOKEN": "read-only\rread-write"} }, "guide.connect.PAGERDUTY_TOKEN"},
		{"connect help with NUL", func(g *Guide) { g.Connect = map[string]string{"PAGERDUTY_TOKEN": "a\x00b"} }, "guide.connect.PAGERDUTY_TOKEN"},
		{"connect help with a C1 control", func(g *Guide) { g.Connect = map[string]string{"PAGERDUTY_TOKEN": "a\u0085b"} }, "guide.connect.PAGERDUTY_TOKEN"},
		{"connect help with a zero-width space", func(g *Guide) { g.Connect = map[string]string{"PAGERDUTY_TOKEN": "read\u200B-only"} }, "guide.connect.PAGERDUTY_TOKEN"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := *base
			g := *base.Guide
			c.edit(&g)
			m.Guide = &g
			var hit bool
			for _, err := range Validate(&m) {
				if is, ok := AsIssue(err); ok && is.Severity == SeverityError && is.Rule == "V10" && is.Path == c.path {
					hit = true
				}
			}
			if !hit {
				t.Fatalf("no V10 error at %s: %v", c.path, Validate(&m))
			}
		})
	}
}

// TestGuideOverviewKeepsNewlinesAndTabs: the overview is markdown over
// several lines, so a newline and a tab are the two control characters
// it may carry.
func TestGuideOverviewKeepsNewlinesAndTabs(t *testing.T) {
	m := mustParse(t, guideYAML)
	m.Guide.Overview = "Reads the export.\n\n- one\n\t- nested\n"
	for _, err := range Validate(m) {
		if is, ok := AsIssue(err); ok && is.Severity == SeverityError && is.Path == "guide.overview" {
			t.Fatalf("a newline or a tab is refused: %v", is)
		}
	}
}

// TestGuideConnectIsMarkdownOfUpTo2000Characters: a key's help is
// Markdown a person reads, never an agent, of up to 2,000 characters
// (runes, not bytes), with line breaks and tabs.
func TestGuideConnectIsMarkdownOfUpTo2000Characters(t *testing.T) {
	if MaxGuideConnectChars != 2000 {
		t.Fatalf("MaxGuideConnectChars = %d, want 2000", MaxGuideConnectChars)
	}
	md := "1. Open **PagerDuty → Integrations → API Access Keys**.\n" +
		"2. Create a *read-only* key.\n\n" +
		"\t- [Their guide](https://support.pagerduty.com/)\n"
	for name, help := range map[string]string{
		"markdown over lines":  md,
		"2,000 characters":     md + strings.Repeat("é", MaxGuideConnectChars-utf8.RuneCountInString(md)),
		"2,000 two-byte runes": strings.Repeat("é", MaxGuideConnectChars),
	} {
		t.Run(name, func(t *testing.T) {
			m := mustParse(t, guideYAML)
			m.Guide.Connect = map[string]string{"PAGERDUTY_TOKEN": help}
			for _, err := range Validate(m) {
				if is, ok := AsIssue(err); ok && is.Severity == SeverityError && is.Path == "guide.connect.PAGERDUTY_TOKEN" {
					t.Fatalf("valid help is refused: %v", is)
				}
			}
		})
	}
}

func TestGuideConnectTakesAnMCPServersSecret(t *testing.T) {
	m := mustParse(t, guideYAML)
	m.Capabilities.Secrets = nil
	m.Capabilities.MCPServers = []MCPServer{{NPM: "github-mcp-server-js", Version: "0.1.7", Secrets: []string{"GITHUB_TOKEN"}}}
	m.Guide.Connect = map[string]string{"GITHUB_TOKEN": "A fine-grained token with read access to pull requests"}
	for _, err := range Validate(m) {
		if is, ok := AsIssue(err); ok && strings.HasPrefix(is.Path, "guide") {
			t.Fatalf("a declared MCP server's secret is refused as a connect key: %v", is)
		}
	}
}

func TestGuideIsAV2Field(t *testing.T) {
	m := mustParse(t, normativeYAML) // schema 1
	m.Guide = &Guide{Overview: "x"}
	var hit bool
	for _, err := range Validate(m) {
		if is, ok := AsIssue(err); ok && is.Rule == "V1" && is.Path == "guide" {
			hit = true
		}
	}
	if !hit {
		t.Fatal("a v1 manifest may carry a guide")
	}
}

// TestGuideChangesNothingAboutTheContract pins that the guide is text
// for people, so a release that changes only its guide asks no consent
// again, and a manifest without one encodes exactly as before.
func TestGuideChangesNothingAboutTheContract(t *testing.T) {
	with := mustParse(t, guideYAML)
	without := mustParse(t, v2YAML)
	if d := DiffCapabilities(without.Capabilities, with.Capabilities); !d.Empty() {
		t.Fatalf("a guide-only change widened or narrowed the contract: %+v", d)
	}
	other := mustParse(t, guideYAML)
	other.Guide.Overview = "Something else entirely."
	other.Guide.Connect["PAGERDUTY_TOKEN"] = "Different help"
	if d := DiffCapabilities(with.Capabilities, other.Capabilities); !d.Empty() {
		t.Fatalf("a changed guide changed the contract: %+v", d)
	}
	raw, err := CanonicalJSON(without)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "guide") {
		t.Fatalf("a manifest without a guide encodes one: %s", raw)
	}
}

// TestGuideDecodingStaysStrict: the new block is closed, and every other
// unknown field is still refused by name.
func TestGuideDecodingStaysStrict(t *testing.T) {
	if _, err := Parse([]byte(guideYAML + "  extra: nope\n")); err == nil {
		t.Fatal("an unknown field inside guide was accepted")
	}
	if _, err := Parse([]byte(v2YAML + "guidance: {}\n")); err == nil {
		t.Fatal("an unknown top-level field was accepted")
	}
}

// TestV2SchemaGuideShape pins the JSON schema's guide beside the Go bounds.
func TestV2SchemaGuideShape(t *testing.T) {
	raw, err := os.ReadFile("../../schemas/agent-manifest-2.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Properties struct {
			Guide struct {
				AdditionalProperties bool `json:"additionalProperties"`
				Properties           struct {
					Overview struct {
						MaxLength int    `json:"maxLength"`
						Pattern   string `json:"pattern"`
					} `json:"overview"`
					Prepare struct {
						MaxItems int `json:"maxItems"`
						Items    struct {
							MaxLength int `json:"maxLength"`
						} `json:"items"`
					} `json:"prepare"`
					Files struct {
						MaxLength int `json:"maxLength"`
					} `json:"files"`
					Task struct {
						MaxLength int `json:"maxLength"`
					} `json:"task"`
					Connect struct {
						AdditionalProperties struct {
							MaxLength int    `json:"maxLength"`
							Pattern   string `json:"pattern"`
						} `json:"additionalProperties"`
					} `json:"connect"`
				} `json:"properties"`
			} `json:"guide"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	g := schema.Properties.Guide
	if g.AdditionalProperties {
		t.Fatal("guide must be closed")
	}
	p := g.Properties
	// The overview keeps newlines and tabs and refuses every other C0
	// control and DEL.
	if want := `^[^\u0000-\u0008\u000b-\u001f\u007f]*$`; p.Overview.Pattern != want {
		t.Errorf("schema overview pattern is %q, want %q", p.Overview.Pattern, want)
	}
	// A key's help is Markdown too, under the same character rule.
	if p.Connect.AdditionalProperties.Pattern != p.Overview.Pattern {
		t.Errorf("schema connect pattern is %q, want the overview's %q", p.Connect.AdditionalProperties.Pattern, p.Overview.Pattern)
	}
	for name, pair := range map[string][2]int{
		"overview":     {p.Overview.MaxLength, MaxGuideOverviewBytes},
		"prepare":      {p.Prepare.MaxItems, MaxGuidePrepare},
		"prepare item": {p.Prepare.Items.MaxLength, MaxGuidePrepareChars},
		"files":        {p.Files.MaxLength, MaxGuideFilesChars},
		"task":         {p.Task.MaxLength, MaxGuideTaskChars},
		"connect":      {p.Connect.AdditionalProperties.MaxLength, MaxGuideConnectChars},
	} {
		if pair[0] != pair[1] {
			t.Errorf("schema %s bound is %d, pkg/manifest says %d", name, pair[0], pair[1])
		}
	}
}

// TestGuideConnectTakesAServerThatSignsIn: help for making the OAuth
// client a vendor needs is keyed by the server's id, for a remote server
// with auth: oauth and a package server with an oauth block alike, and
// ServerConnect finds it.
func TestGuideConnectTakesAServerThatSignsIn(t *testing.T) {
	remote := MCPServer{URL: "https://mcp.linear.app/mcp", Auth: AuthOAuth, Scopes: []string{"read"}}
	pkg := MCPServer{PyPI: "workspace-mcp", Version: "2.0.1", Egress: []string{"gmail.googleapis.com"}, OAuth: &MCPOAuth{
		Issuer: "https://accounts.google.com",
		Scopes: []string{"https://www.googleapis.com/auth/gmail.readonly"},
		Env:    map[string]string{"GOOGLE_ACCESS_TOKEN": "{access_token}"},
	}}
	m := mustParse(t, guideYAML)
	m.Capabilities.MCPServers = append(m.Capabilities.MCPServers, remote, pkg)
	m.Guide.Connect["url:https://mcp.linear.app/mcp"] = "Linear signs you in with its own app; nothing to make."
	m.Guide.Connect["pypi:workspace-mcp"] = "Make a **Desktop app** client in your Google Cloud project."
	for _, err := range Validate(m) {
		if is, ok := AsIssue(err); ok && is.Severity == SeverityError {
			t.Fatalf("a server that signs in is refused as a connect key: %v", is)
		}
	}
	if got := m.Guide.ServerConnect(remote); got != m.Guide.Connect["url:https://mcp.linear.app/mcp"] {
		t.Fatalf("ServerConnect(remote) = %q", got)
	}
	if got := m.Guide.ServerConnect(pkg); got != m.Guide.Connect["pypi:workspace-mcp"] {
		t.Fatalf("ServerConnect(package) = %q", got)
	}
	if got := (*Guide)(nil).ServerConnect(remote); got != "" {
		t.Fatalf("a missing guide has help: %q", got)
	}
}

// TestGuideConnectRefusesAServerThatAsksNoSignIn: a server keyed by id
// must be declared and must sign in by OAuth; one that takes a secret is
// helped under its secret's name, and one that is not declared at all is
// refused.
func TestGuideConnectRefusesAServerThatAsksNoSignIn(t *testing.T) {
	m := mustParse(t, guideYAML)
	m.Capabilities.MCPServers = append(m.Capabilities.MCPServers,
		MCPServer{URL: "https://mcp.example.com/mcp", Auth: AuthNone},
		MCPServer{NPM: "github-mcp-server-js", Version: "0.1.7", Secrets: []string{"GITHUB_TOKEN"}},
	)
	for _, key := range []string{"url:https://mcp.example.com/mcp", "npm:github-mcp-server-js", "url:https://mcp.linear.app/mcp", "https://mcp.example.com/mcp"} {
		t.Run(key, func(t *testing.T) {
			m.Guide.Connect = map[string]string{key: "Some help"}
			var hit bool
			for _, err := range Validate(m) {
				if is, ok := AsIssue(err); ok && is.Rule == "V10" && is.Path == "guide.connect."+key {
					hit = true
				}
			}
			if !hit {
				t.Fatalf("connect help keyed %q is accepted", key)
			}
		})
	}
}
