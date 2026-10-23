package manifest

// capabilities.mcpServers (V5): parse + validation pins. The
// load-bearing rules are the EXACT-version requirement (pins ride the
// release archive) and the closed source union (exactly one of
// npm/pypi).

import (
	"fmt"
	"slices"
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
	wantIssue(t, errs, "V5", SeverityWarning, "capabilities.mcpServers[1].egress[0]")

	m, _ := Parse([]byte(doc))
	if got := m.Capabilities.MCPServers[0].SourceID(); got != "npm:github-mcp-server-js" {
		t.Fatalf("SourceID = %q", got)
	}

	// The egress host grammar admits its edges: both ends of each
	// character range, a hyphen inside a label, a label of 63 characters
	// and a host of 253.
	edges := mcpManifest(`    - npm: server-x
      version: 1.0.0
      egress:
        - az09-AZ.example.com
        - z9.Z9.example.com
        - ` + strings.Repeat("a", 63) + "." + strings.Repeat("a", 63) + "." + strings.Repeat("a", 63) + "." + strings.Repeat("a", 61) + `
`)
	if blocking := blockingText(issuesFor(t, edges)); blocking != "" {
		t.Fatalf("egress host edges refused:\n%s", blocking)
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
`, "exactly one of npm, pypi or url"},
		"neither source": {
			`    - version: 1.0.0
`, "exactly one of npm, pypi or url"},
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
		"empty tool name": {
			`    - npm: server-x
      version: 1.0.0
      tools: [list, ""]
`, `capabilities.mcpServers[0].tools[1]: tool name must not be empty`},
		"tool name with a control character": {
			`    - npm: server-x
      version: 1.0.0
      tools: ["a\x01b"]
`, `capabilities.mcpServers[0].tools[0]: tool "a\x01b" must be a single token without whitespace`},
		"tool name with a tab": {
			`    - npm: server-x
      version: 1.0.0
      tools: ["a\tb"]
`, `capabilities.mcpServers[0].tools[0]: tool "a\tb" must be a single token without whitespace`},
		"auth on a package server": {
			`    - npm: server-x
      version: 1.0.0
      auth: oauth
`, "capabilities.mcpServers[0].auth: auth is a remote server's field; a package server signs in through an oauth block"},
		"scopes on a package server": {
			`    - npm: server-x
      version: 1.0.0
      scopes: [read]
`, "capabilities.mcpServers[0].scopes: scopes on a package server go in its oauth block"},
		"egress host of 254 characters": {
			`    - npm: server-x
      version: 1.0.0
      egress: [` + strings.Repeat("a", 63) + "." + strings.Repeat("a", 63) + "." + strings.Repeat("a", 63) + "." + strings.Repeat("a", 62) + `]
`, "not a valid DNS host name"},
		"egress host label of 64 characters": {
			`    - npm: server-x
      version: 1.0.0
      egress: [` + strings.Repeat("a", 64) + `.example.com]
`, "not a valid DNS host name"},
		"egress host with an empty label": {
			`    - npm: server-x
      version: 1.0.0
      egress: ["a..example.com"]
`, "not a valid DNS host name"},
		"egress host with a leading hyphen": {
			`    - npm: server-x
      version: 1.0.0
      egress: ["-a.example.com"]
`, "not a valid DNS host name"},
		"egress host with a trailing hyphen": {
			`    - npm: server-x
      version: 1.0.0
      egress: ["a-.example.com"]
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
	errs := issuesFor(t, doc)
	text := blockingText(errs)
	if !strings.Contains(text, "withdrawn") {
		t.Fatalf("withdrawn mcp-server kind not refused:\n%s", text)
	}
	// The kind itself is refused, at its own path: the entrypoints.mcp
	// refusal also says "withdrawn", and must not stand in for it.
	if !strings.Contains(text, "manifest V1: kind: kind mcp-server is withdrawn") {
		t.Fatalf("the kind line itself was not refused:\n%s", text)
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
	want := fmt.Sprintf("manifest V5: capabilities.mcpServers: at most %d MCP servers may be declared (got %d)", MaxMCPServers, MaxMCPServers+1)
	if !strings.Contains(text, want) {
		t.Fatalf("server count cap not enforced; want %q:\n%s", want, text)
	}

	// Exactly MaxMCPServers is allowed.
	var ok strings.Builder
	for i := 0; i < MaxMCPServers; i++ {
		ok.WriteString("    - npm: server-")
		ok.WriteRune(rune('a' + i))
		ok.WriteString("\n      version: 1.0.0\n")
	}
	if blocking := blockingText(issuesFor(t, mcpManifest(ok.String()))); blocking != "" {
		t.Fatalf("%d servers, the limit, were refused:\n%s", MaxMCPServers, blocking)
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

	// The limits admit their exact size: MaxMCPServerEnvEntries entries,
	// and a value of MaxMCPServerEnvValue characters, whether each takes
	// one byte or two.
	var full strings.Builder
	full.WriteString("    - npm: server-x\n      version: 1.0.0\n      env:\n")
	for i := 0; i < MaxMCPServerEnvEntries; i++ {
		fmt.Fprintf(&full, "        KEY_%d: v\n", i)
	}
	for name, yaml := range map[string]string{
		"entries at the cap":                   full.String(),
		"a value of the cap":                   "    - npm: server-x\n      version: 1.0.0\n      env: {LONG: \"" + strings.Repeat("x", MaxMCPServerEnvValue) + "\"}\n",
		"a value of the cap in two-byte runes": "    - npm: server-x\n      version: 1.0.0\n      env: {LONG: \"" + strings.Repeat("\xc3\xa9", MaxMCPServerEnvValue) + "\"}\n",
	} {
		if blocking := blockingText(issuesFor(t, mcpManifestV2(yaml))); blocking != "" {
			t.Fatalf("%s refused:\n%s", name, blocking)
		}
	}
}

// TestMCPServerEnvRefusals: one failing fixture per rule.
func TestMCPServerEnvRefusals(t *testing.T) {
	var tooMany strings.Builder
	tooMany.WriteString("    - npm: server-x\n      version: 1.0.0\n      env:\n")
	for i := 0; i <= MaxMCPServerEnvEntries; i++ {
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
		"value one over the cap in two-byte runes": {
			"    - npm: server-x\n      version: 1.0.0\n      env: {LONG: \"" + strings.Repeat("\xc3\xa9", MaxMCPServerEnvValue+1) + "\"}\n",
			"capabilities.mcpServers[0].env.LONG: value must be at most 512 characters (got 513)"},
		"control character below space": {
			"    - npm: server-x\n      version: 1.0.0\n      env: {CTRL: \"a\\x01b\"}\n",
			"capabilities.mcpServers[0].env.CTRL: value must be a single line with no control characters"},
		"too many keys by one": {"    - npm: server-x\n      version: 1.0.0\n      env: {" + func() string {
			var kv []string
			for i := 0; i <= MaxMCPServerEnvEntries; i++ {
				kv = append(kv, fmt.Sprintf("K%d: v", i))
			}
			return strings.Join(kv, ", ")
		}() + "}\n", "capabilities.mcpServers[0].env: at most 16 env entries may be declared per server (got 17)"},
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
		// The gateway would expand these against the server's
		// environment or evaluate them as a template; the path names
		// the entry and the key.
		"dollar name": {
			`    - npm: server-x
      version: 1.0.0
      env: {A: "$B"}
`, "capabilities.mcpServers[0].env.A: value contains a $"},
		"dollar brace name": {
			`    - npm: server-x
      version: 1.0.0
      env: {A: "${B}"}
`, "capabilities.mcpServers[0].env.A: value contains a $"},
		"dollar special parameter": {
			`    - npm: server-x
      version: 1.0.0
      env: {A: "$$"}
`, "capabilities.mcpServers[0].env.A: value contains a $"},
		"template": {
			`    - npm: server-x
      version: 1.0.0
      env: {A: "x{{y}}z"}
`, "capabilities.mcpServers[0].env.A: value contains a $ the runner's gateway would expand, or a {{ }} template; declare a literal value"},
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

// TestMCPServerEnvLiteralShapes: a `$` that nothing would expand and a
// single brace pair are literal and pass.
func TestMCPServerEnvLiteralShapes(t *testing.T) {
	doc := mcpManifestV2(`    - npm: server-x
      version: 1.0.0
      env: {PRICE: "50$", NOTE: "a {b} c"}
`)
	if blocking := Blocking(issuesFor(t, doc)); len(blocking) > 0 {
		t.Fatalf("literal values rejected: %v", blocking)
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

// TestMCPServerArgsValid: a package server's args ride the entry in order,
// and the limits admit their exact size.
func TestMCPServerArgsValid(t *testing.T) {
	doc := mcpManifestV2(`    - pypi: semgrep
      version: 1.182.0
      egress: [semgrep.dev]
      args: [mcp]
    - npm: server-x
      version: 1.0.0
      args: [--stdio, "--toolsets=repos,issues", --price=50$, "--note={b}"]
`)
	if blocking := Blocking(issuesFor(t, doc)); len(blocking) > 0 {
		t.Fatalf("valid args rejected: %v", blocking)
	}
	m, _ := Parse([]byte(doc))
	if got := m.Capabilities.MCPServers[1].Args; !slices.Equal(got, []string{"--stdio", "--toolsets=repos,issues", "--price=50$", "--note={b}"}) {
		t.Fatalf("args = %q", got)
	}

	full := make([]string, MaxMCPServerArgs)
	for i := range full {
		full[i] = fmt.Sprintf("--a%d", i)
	}
	for name, yaml := range map[string]string{
		"args at the cap":                          "    - npm: server-x\n      version: 1.0.0\n      args: [" + strings.Join(full, ", ") + "]\n",
		"an argument of the cap":                   "    - npm: server-x\n      version: 1.0.0\n      args: [\"" + strings.Repeat("x", MaxMCPServerArgLen) + "\"]\n",
		"an argument of the cap in two-byte runes": "    - npm: server-x\n      version: 1.0.0\n      args: [\"" + strings.Repeat("\xc3\xa9", MaxMCPServerArgLen) + "\"]\n",
	} {
		if blocking := blockingText(issuesFor(t, mcpManifestV2(yaml))); blocking != "" {
			t.Fatalf("%s refused:\n%s", name, blocking)
		}
	}
}

// TestMCPServerArgsRefusals: one failing fixture per rule, each naming the
// argument's position.
func TestMCPServerArgsRefusals(t *testing.T) {
	tooMany := make([]string, MaxMCPServerArgs+1)
	for i := range tooMany {
		tooMany[i] = "a"
	}
	pkg := "    - npm: server-x\n      version: 1.0.0\n      args: "
	cases := map[string]struct {
		yaml string
		want string
	}{
		"too many":            {pkg + "[" + strings.Join(tooMany, ", ") + "]\n", "capabilities.mcpServers[0].args: at most 16 args may be declared per server (got 17)"},
		"empty":               {pkg + "[mcp, \"\"]\n", "capabilities.mcpServers[0].args[1]: an argument must not be empty"},
		"too long":            {pkg + "[\"" + strings.Repeat("x", MaxMCPServerArgLen+1) + "\"]\n", "capabilities.mcpServers[0].args[0]: an argument must be at most 256 characters (got 257)"},
		"a space":             {pkg + "[\"--title=a b\"]\n", "capabilities.mcpServers[0].args[0]: an argument must be one word with no whitespace, control or format character (found U+0020)"},
		"a newline":           {pkg + "[\"a\\nb\"]\n", "(found U+000A)"},
		"a control character": {pkg + "[\"a\\x01b\"]\n", "(found U+0001)"},
		"a C1 control":        {pkg + "[\"a\\u0085b\"]\n", "(found U+0085)"},
		"a format character":  {pkg + "[\"a\\u202eb\"]\n", "(found U+202E)"},
		"a dollar name":       {pkg + "[\"--token=$GITHUB_TOKEN\"]\n", "capabilities.mcpServers[0].args[0]: argument contains a $"},
		"a dollar brace":      {pkg + "[\"${B}\"]\n", "argument contains a $"},
		"a template":          {pkg + "[\"x{{y}}z\"]\n", "argument contains a $ the runner's gateway would expand, or a {{ }} template; declare a literal argument"},
		"on a remote server":  {"    - url: https://mcp.example.com/mcp\n      auth: none\n      args: [mcp]\n", "capabilities.mcpServers[0].args: a remote server takes no args: it runs at its vendor"},
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

// TestMCPServerArgsIsV2Only: a v1 document may not carry args.
func TestMCPServerArgsIsV2Only(t *testing.T) {
	text := blockingText(issuesFor(t, mcpManifest(`    - npm: server-x
      version: 1.0.0
      args: [mcp]
`)))
	if !strings.Contains(text, "args is a v2 field") {
		t.Fatalf("v1 manifest accepted args:\n%s", text)
	}
}
