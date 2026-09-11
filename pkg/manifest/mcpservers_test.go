package manifest

// capabilities.mcpServers (V5, RUNNER-PLAN-3): parse + validation pins.
// The load-bearing rules are the EXACT-version requirement (pins ride the
// release archive) and the closed source union (exactly one of npm/pypi).

import (
	"fmt"
	"strings"
	"testing"
)

func mcpManifest(serversYAML string) string {
	return `schemaVersion: "1"
name: needs-servers
namespace: acme
kind: skill
version: 1.0.0
summary: "mcpServers validation fixture"
entrypoints:
  skill: SKILL.md
capabilities:
  mcpServers:
` + serversYAML + `
publish:
  include: [agent.yaml, SKILL.md]
`
}

func issuesFor(t *testing.T, doc string) []error {
	t.Helper()
	m, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return Validate(m)
}

func blockingText(errs []error) string {
	var b strings.Builder
	for _, e := range Blocking(errs) {
		b.WriteString(e.Error())
		b.WriteString("\n")
	}
	return b.String()
}

func TestMCPServersValid(t *testing.T) {
	doc := mcpManifest(`    - npm: github-mcp-server-js
      version: 0.1.7
      tools: [list_issues, create_issue_comment]
      secrets: [GITHUB_TOKEN]
      egress: [api.github.com]
    - pypi: mcp-server-fetch
      version: 0.6.2
      egress: ["*"]
`)
	errs := issuesFor(t, doc)
	if blocking := Blocking(errs); len(blocking) > 0 {
		t.Fatalf("valid mcpServers rejected: %v", blocking)
	}
	// The "*" server egress is warned, exactly like agent-level egress.
	warned := false
	for _, e := range errs {
		if IsWarning(e) && strings.Contains(e.Error(), "unrestricted network access for this server") {
			warned = true
		}
	}
	if !warned {
		t.Fatal("wildcard server egress did not warn")
	}

	m, _ := Parse([]byte(doc))
	if got := m.Capabilities.MCPServers[0].SourceID(); got != "npm:github-mcp-server-js" {
		t.Fatalf("SourceID = %q", got)
	}
}

func TestMCPServersRefusals(t *testing.T) {
	cases := map[string]struct {
		yaml string
		want string
	}{
		"range version npm": {
			`    - npm: server-x
      version: ^1.2.0
`, "exact semver release"},
		"range version pypi": {
			`    - pypi: server-x
      version: ">=0.6"
`, "exact PEP-440 release"},
		"missing version": {
			`    - npm: server-x
`, "version is required"},
		"both sources": {
			`    - npm: server-x
      pypi: server-x
      version: 1.0.0
`, "exactly one of npm or pypi"},
		"neither source": {
			`    - version: 1.0.0
`, "exactly one of npm or pypi"},
		"bad npm name": {
			`    - npm: "UpperCase"
      version: 1.0.0
`, "not a valid npm package name"},
		"bad pypi name": {
			`    - pypi: "Not_Normalized_"
      version: 1.0.0
`, "PEP-503 normalized"},
		"duplicate": {
			`    - npm: server-x
      version: 1.0.0
    - npm: server-x
      version: 1.0.1
`, "duplicate MCP server"},
		"bad secret": {
			`    - npm: server-x
      version: 1.0.0
      secrets: ["not a var"]
`, "environment variable name"},
		"bad tool": {
			`    - npm: server-x
      version: 1.0.0
      tools: ["two words"]
`, "single token"},
		"bad egress host": {
			`    - npm: server-x
      version: 1.0.0
      egress: ["not a host"]
`, "not a valid DNS host name"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			text := blockingText(issuesFor(t, mcpManifest(tc.yaml)))
			if !strings.Contains(text, tc.want) {
				t.Fatalf("expected a blocking issue containing %q, got:\n%s", tc.want, text)
			}
		})
	}
}

func TestMCPServersOnWithdrawnKindRefused(t *testing.T) {
	doc := `schemaVersion: "1"
name: composed
namespace: acme
kind: mcp-server
version: 1.0.0
summary: "server-of-servers refusal"
entrypoints:
  mcp:
    command: node
    args: [server.js]
    transport: stdio
capabilities:
  mcpServers:
    - npm: server-x
      version: 1.0.0
publish:
  include: [agent.yaml, server.js]
`
	text := blockingText(issuesFor(t, doc))
	if !strings.Contains(text, "withdrawn") {
		t.Fatalf("withdrawn mcp-server kind not refused:\n%s", text)
	}
}

func TestMCPServersCapAtMax(t *testing.T) {
	var b strings.Builder
	for i := 0; i <= MaxMCPServers; i++ {
		b.WriteString("    - npm: server-")
		b.WriteRune(rune('a' + i))
		b.WriteString("\n      version: 1.0.0\n")
	}
	text := blockingText(issuesFor(t, mcpManifest(b.String())))
	if !strings.Contains(text, "at most") {
		t.Fatalf("server count cap not enforced:\n%s", text)
	}
}

func TestMCPServersUnknownKeyRejected(t *testing.T) {
	doc := mcpManifest(`    - npm: server-x
      version: 1.0.0
      image: docker.io/x
`)
	if _, err := Parse([]byte(doc)); err == nil || !strings.Contains(err.Error(), "field image not found") {
		t.Fatalf("unknown mcpServers key survived the closed schema: %v", err)
	}
}

// mcpManifestV2 is mcpManifest's v2 twin: `env` is a v2 field.
func mcpManifestV2(serversYAML string) string {
	return `schemaVersion: "2"
name: needs-servers
namespace: acme
modes: [autonomous]
version: 1.0.0
summary: "mcpServers env validation fixture"
capabilities:
  secrets: [SHARED_TOKEN]
  mcpServers:
` + serversYAML + `
publish:
  include: [agent.yaml, AGENT.md]
`
}

// TestMCPServerEnvValid: a plain env map rides the entry and parses into
// the struct as written.
func TestMCPServerEnvValid(t *testing.T) {
	doc := mcpManifestV2(`    - npm: github-mcp-server-js
      version: 0.1.7
      tools: [list_issues]
      secrets: [GITHUB_TOKEN]
      env:
        GITHUB_PERMISSION: read-only
        LOGS_DIR: /tmp/logs
      egress: [api.github.com]
`)
	errs := issuesFor(t, doc)
	if blocking := Blocking(errs); len(blocking) > 0 {
		t.Fatalf("valid env rejected: %v", blocking)
	}
	m, _ := Parse([]byte(doc))
	env := m.Capabilities.MCPServers[0].Env
	if len(env) != 2 || env["GITHUB_PERMISSION"] != "read-only" || env["LOGS_DIR"] != "/tmp/logs" {
		t.Fatalf("env = %v", env)
	}
}

// TestMCPServerEnvRefusals: one failing fixture per rule of §4.2.
func TestMCPServerEnvRefusals(t *testing.T) {
	var tooMany strings.Builder
	tooMany.WriteString("    - npm: server-x\n      version: 1.0.0\n      env:\n")
	for i := 0; i <= MaxMCPServerEnv; i++ {
		fmt.Fprintf(&tooMany, "        KEY_%d: v\n", i)
	}
	cases := map[string]struct {
		yaml string
		want string
	}{
		"too many keys": {tooMany.String(), "at most 16 env entries"},
		"bad name": {
			`    - npm: server-x
      version: 1.0.0
      env: {"not a var": x}
`, "not a valid environment variable name"},
		"value too long": {
			`    - npm: server-x
      version: 1.0.0
      env: {LONG: "` + strings.Repeat("x", MaxMCPServerEnvValue+1) + `"}
`, "at most 512 characters"},
		"multi-line value": {
			`    - npm: server-x
      version: 1.0.0
      env: {TWO: "a\nb"}
`, "single line"},
		"control character": {
			`    - npm: server-x
      version: 1.0.0
      env: {CTRL: "a\tb"}
`, "single line"},
		"name also in the entry's secrets": {
			`    - npm: server-x
      version: 1.0.0
      secrets: [GITHUB_TOKEN]
      env: {GITHUB_TOKEN: plain}
`, "configure it as a secret or as env, not both"},
		"name also in capabilities.secrets": {
			`    - npm: server-x
      version: 1.0.0
      env: {SHARED_TOKEN: plain}
`, "configure it as a secret or as env, not both"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			text := blockingText(issuesFor(t, mcpManifestV2(tc.yaml)))
			if !strings.Contains(text, tc.want) {
				t.Fatalf("expected a blocking issue containing %q, got:\n%s", tc.want, text)
			}
		})
	}
}

// TestMCPServerEnvDuplicateKeyRejected: the strict YAML decoder refuses a
// repeated key before validation runs, so names are unique by parse.
func TestMCPServerEnvDuplicateKeyRejected(t *testing.T) {
	doc := mcpManifestV2(`    - npm: server-x
      version: 1.0.0
      env:
        A: one
        A: two
`)
	if _, err := Parse([]byte(doc)); err == nil || !strings.Contains(err.Error(), "already defined") {
		t.Fatalf("duplicate env key survived the strict decoder: %v", err)
	}
}

// TestMCPServerEnvIsV2Only: a v1 document may not carry env (the same
// refusal shape as intake and interactive).
func TestMCPServerEnvIsV2Only(t *testing.T) {
	text := blockingText(issuesFor(t, mcpManifest(`    - npm: server-x
      version: 1.0.0
      env: {A: b}
`)))
	if !strings.Contains(text, "env is a v2 field") {
		t.Fatalf("v1 manifest accepted env:\n%s", text)
	}
}
