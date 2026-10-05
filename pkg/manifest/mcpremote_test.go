package manifest

// Remote MCP servers and an OAuth sign-in on a declared server (V5, v2;
// plan mcp-oauth-connections.md §4, agentry#910): parse and validation
// pins, the placeholder grammar the runner renders with, and the
// unsupported list.

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
)

const gmailRemote = `    - url: https://gmailmcp.googleapis.com/mcp/v1
      auth: oauth
      scopes: [https://www.googleapis.com/auth/gmail.readonly]
      tools: [search_threads, get_thread]
`

const calendarPackage = `    - npm: "@cocal/google-calendar-mcp"
      version: 2.7.0
      egress: [www.googleapis.com, oauth2.googleapis.com]
      oauth:
        issuer: https://accounts.google.com
        scopes: [https://www.googleapis.com/auth/calendar.readonly]
        files:
          - path: keys.json
            template: '{"installed":{"client_id":"agentry","client_secret":"agentry"}}'
          - path: tokens.json
            template: '{"normal":{"access_token":"{access_token}","expiry_date":{expiry_ms}}}'
        env:
          GOOGLE_OAUTH_CREDENTIALS: "{dir}/keys.json"
          GOOGLE_CALENDAR_MCP_TOKEN_PATH: "{dir}/tokens.json"
`

func TestRemoteAndOAuthServersValid(t *testing.T) {
	doc := mcpManifestV2(gmailRemote + `    - url: https://api.githubcopilot.com/mcp/
      auth: secret
      secrets: [GITHUB_TOKEN]
    - url: https://mcp.example.com/mcp
      auth: none
    - pypi: workspace-mcp
      version: 2.0.1
      egress: [gmail.googleapis.com]
      env: {MCP_SINGLE_USER_MODE: "1"}
      oauth:
        issuer: https://accounts.google.com
        scopes: [https://www.googleapis.com/auth/gmail.readonly]
        files:
          - path: me.json
            template: '{"token":"{access_token}","expiry":"{expiry}"}'
        env:
          WORKSPACE_MCP_CREDENTIALS_DIR: "{dir}"
    - npm: github-mcp-server-js
      version: 0.1.7
      oauth:
        issuer: https://github.com
        env:
          GITHUB_TOKEN: "{access_token}"
` + calendarPackage)
	errs := issuesFor(t, doc)
	if blocking := Blocking(errs); len(blocking) > 0 {
		t.Fatalf("valid servers rejected: %v", blocking)
	}
	m, _ := Parse([]byte(doc))
	srv := m.Capabilities.MCPServers
	if !srv[0].IsRemote() || srv[0].SourceID() != "url:https://gmailmcp.googleapis.com/mcp/v1" ||
		srv[0].RemoteHost() != "gmailmcp.googleapis.com" || !srv[0].NeedsConnection() {
		t.Fatalf("remote oauth server = %+v (%s)", srv[0], srv[0].SourceID())
	}
	if srv[1].NeedsConnection() || srv[2].NeedsConnection() {
		t.Fatal("a secret or no-auth remote server needs no connection")
	}
	if srv[3].IsRemote() || !srv[3].NeedsConnection() || srv[3].OAuth.Issuer != "https://accounts.google.com" {
		t.Fatalf("package server with oauth = %+v", srv[3])
	}
	if len(srv[5].OAuth.Files) != 2 || srv[5].OAuth.Env["GOOGLE_OAUTH_CREDENTIALS"] != "{dir}/keys.json" {
		t.Fatalf("calendar oauth = %+v", srv[5].OAuth)
	}
}

func TestRemoteServerRefusals(t *testing.T) {
	cases := map[string]struct{ yaml, want string }{
		"two sources": {`    - npm: x
      url: https://mcp.example.com/mcp
      auth: none
      version: 1.0.0
`, "exactly one of npm, pypi or url"},
		"http": {`    - url: http://mcp.example.com/mcp
      auth: none
`, "must be https://"},
		"ip literal": {`    - url: https://10.0.0.1/mcp
      auth: none
`, "not an IP address"},
		"localhost": {`    - url: https://localhost/mcp
      auth: none
`, "public host name"},
		"internal name": {`    - url: https://mcp.corp.internal/mcp
      auth: none
`, "public host name"},
		"single label": {`    - url: https://intranet/mcp
      auth: none
`, "public host name"},
		"userinfo": {`    - url: https://user:pw@mcp.example.com/mcp
      auth: none
`, "no user information"},
		"query": {`    - url: https://mcp.example.com/mcp?key=abc
      auth: none
`, "no query"},
		"fragment": {`    - url: https://mcp.example.com/mcp#x
      auth: none
`, "no fragment"},
		"port": {`    - url: https://mcp.example.com:8443/mcp
      auth: none
`, "port 443"},
		"uppercase host": {`    - url: https://MCP.example.com/mcp
      auth: none
`, "lowercase"},
		"too long": {`    - url: https://mcp.example.com/` + strings.Repeat("a", MaxRemoteURLLength) + `
      auth: none
`, "at most 512"},
		"no auth": {`    - url: https://mcp.example.com/mcp
`, "auth is required"},
		"unknown auth": {`    - url: https://mcp.example.com/mcp
      auth: basic
`, "oauth, secret or none"},
		"version on remote": {`    - url: https://mcp.example.com/mcp
      auth: none
      version: 1.0.0
`, "takes no version"},
		"egress on remote": {`    - url: https://mcp.example.com/mcp
      auth: none
      egress: [api.example.com]
`, "takes no egress"},
		"env on remote": {`    - url: https://mcp.example.com/mcp
      auth: none
      env: {A: b}
`, "takes no env"},
		"oauth block on remote": {`    - url: https://mcp.example.com/mcp
      auth: oauth
      oauth:
        issuer: https://auth.example.com
`, "takes no oauth block"},
		"secret auth without a secret": {`    - url: https://mcp.example.com/mcp
      auth: secret
`, "exactly one secret"},
		"secret auth with two": {`    - url: https://mcp.example.com/mcp
      auth: secret
      secrets: [A_KEY, B_KEY]
`, "exactly one secret"},
		"secrets without secret auth": {`    - url: https://mcp.example.com/mcp
      auth: oauth
      secrets: [A_KEY]
`, "only with auth: secret"},
		"scopes without oauth": {`    - url: https://mcp.example.com/mcp
      auth: none
      scopes: [read]
`, "only with auth: oauth"},
		"bad scope": {`    - url: https://mcp.example.com/mcp
      auth: oauth
      scopes: ["read write"]
`, "single token"},
		"duplicate scope": {`    - url: https://mcp.example.com/mcp
      auth: oauth
      scopes: [read, read]
`, "duplicate scope"},
		"duplicate url": {`    - url: https://mcp.example.com/mcp
      auth: none
    - url: https://mcp.example.com/mcp
      auth: oauth
`, "duplicate MCP server"},
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

func TestMCPOAuthRefusals(t *testing.T) {
	pkg := func(oauth string) string {
		return `    - npm: server-x
      version: 1.0.0
      env: {PLAIN: x}
      secrets: [SERVER_KEY]
      oauth:
` + oauth
	}
	cases := map[string]struct{ yaml, want string }{
		"no issuer": {pkg(`        env: {TOKEN: "{access_token}"}
`), "issuer is required"},
		"http issuer": {pkg(`        issuer: http://auth.example.com
        env: {TOKEN: "{access_token}"}
`), "must be https://"},
		"issuer with query": {pkg(`        issuer: https://auth.example.com/?tenant=x
        env: {TOKEN: "{access_token}"}
`), "no query"},
		"token reaches nothing": {pkg(`        issuer: https://auth.example.com
        env: {CONFIG_DIR: "{dir}"}
        files:
          - path: c.json
            template: '{"x":1}'
`), "{access_token} must appear"},
		"unknown placeholder in template": {pkg(`        issuer: https://auth.example.com
        files:
          - path: c.json
            template: '{"t":"{access_token}","r":"{refresh_token}"}'
`), "unknown placeholder {refresh_token}"},
		"dir placeholder in template": {pkg(`        issuer: https://auth.example.com
        files:
          - path: c.json
            template: '{"t":"{access_token}","d":"{dir}"}'
`), "unknown placeholder {dir}"},
		"expiry placeholder in env": {pkg(`        issuer: https://auth.example.com
        env: {TOKEN: "{access_token}", EXP: "{expiry}"}
`), "unknown placeholder {expiry}"},
		"dir without files": {pkg(`        issuer: https://auth.example.com
        env: {TOKEN: "{access_token}", DIR: "{dir}"}
`), "{dir} names the token folder"},
		"bad file path": {pkg(`        issuer: https://auth.example.com
        files:
          - path: ../escape.json
            template: '{"t":"{access_token}"}'
`), "plain file name"},
		"duplicate file": {pkg(`        issuer: https://auth.example.com
        files:
          - path: a.json
            template: '{"t":"{access_token}"}'
          - path: a.json
            template: '{}'
`), "duplicate file"},
		"too many files": {pkg(`        issuer: https://auth.example.com
        files:
          - {path: a, template: "{access_token}"}
          - {path: b, template: x}
          - {path: c, template: x}
          - {path: d, template: x}
          - {path: e, template: x}
`), "at most 4 files"},
		"template too long": {pkg(`        issuer: https://auth.example.com
        files:
          - path: a.json
            template: "{access_token}` + strings.Repeat("x", MaxOAuthTemplateBytes) + `"
`), "at most 2048 bytes"},
		"template control character": {pkg(`        issuer: https://auth.example.com
        files:
          - path: a.json
            template: "{access_token}\u0007"
`), "control character"},
		"env name collides with plain env": {pkg(`        issuer: https://auth.example.com
        env: {PLAIN: "{access_token}"}
`), "declared more than once"},
		"env name collides with a secret": {pkg(`        issuer: https://auth.example.com
        env: {SERVER_KEY: "{access_token}"}
`), "declared more than once"},
		"env name collides with an agent secret": {pkg(`        issuer: https://auth.example.com
        env: {SHARED_TOKEN: "{access_token}"}
`), "declared more than once"},
		"env value expands": {pkg(`        issuer: https://auth.example.com
        env: {TOKEN: "{access_token}", OTHER: "$HOME"}
`), "gateway would expand"},
		"env value multi-line": {pkg(`        issuer: https://auth.example.com
        env: {TOKEN: "{access_token}\nx"}
`), "single line"},
		"bad oauth scope": {pkg(`        issuer: https://auth.example.com
        scopes: [""]
        env: {TOKEN: "{access_token}"}
`), "scope must not be empty"},
		"unsupported package": {`    - pypi: mcp-gsuite
      version: 0.4.1
      oauth:
        issuer: https://accounts.google.com
        env: {TOKEN: "{access_token}"}
`, "pypi:workspace-mcp"},
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

// TestRemoteAndOAuthAreV2Only: a v1 manifest refuses every new field by
// name, as it refuses env.
func TestRemoteAndOAuthAreV2Only(t *testing.T) {
	for name, yaml := range map[string]string{
		"url": `    - url: https://mcp.example.com/mcp
      auth: none
`,
		"oauth": `    - npm: server-x
      version: 1.0.0
      oauth:
        issuer: https://auth.example.com
        env: {TOKEN: "{access_token}"}
`,
	} {
		t.Run(name, func(t *testing.T) {
			text := blockingText(issuesFor(t, mcpManifest(yaml)))
			if !strings.Contains(text, "is a v2 field") {
				t.Fatalf("v1 manifest accepted %s:\n%s", name, text)
			}
		})
	}
}

// TestNoRemoteFieldsEncodeAsBefore: a package server's canonical encoding
// is unchanged by the new optional fields, so no stored digest moves.
func TestNoRemoteFieldsEncodeAsBefore(t *testing.T) {
	m := mustParse(t, mcpManifestV2(`    - npm: server-x
      version: 1.0.0
`))
	got, err := CanonicalJSON(m)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"url"`, `"auth"`, `"scopes"`, `"oauth"`} {
		if strings.Contains(string(got), key) {
			t.Fatalf("canonical JSON of a package server carries %s: %s", key, got)
		}
	}
	if !strings.Contains(string(got), `"version":"1.0.0"`) {
		t.Fatalf("canonical JSON lost the pin: %s", got)
	}
}

func TestExpandOAuthPlaceholders(t *testing.T) {
	vals := map[string]string{"access_token": "ya29.TOKEN", "expiry_ms": "1700000000000"}
	got, err := ExpandOAuthPlaceholders(`{"normal":{"access_token":"{access_token}","expiry_date":{expiry_ms}}}`, OAuthTemplatePlaceholders, vals)
	if err != nil || got != `{"normal":{"access_token":"ya29.TOKEN","expiry_date":1700000000000}}` {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := ExpandOAuthPlaceholders(`{refresh_token}`, OAuthTemplatePlaceholders, vals); err == nil {
		t.Fatal("an unknown placeholder expanded")
	}
	// JSON's own braces are not placeholders.
	if got, err := ExpandOAuthPlaceholders(`{"a":{"b":{}}}`, OAuthTemplatePlaceholders, vals); err != nil || got != `{"a":{"b":{}}}` {
		t.Fatalf("plain JSON: %q, %v", got, err)
	}
	// A placeholder the caller has no value for is refused, never left in.
	if _, err := ExpandOAuthPlaceholders(`{expiry}`, OAuthTemplatePlaceholders, vals); err == nil {
		t.Fatal("a placeholder without a value expanded")
	}
}

func TestUnsupportedOAuthPackage(t *testing.T) {
	alt, ok := UnsupportedOAuthPackage("pypi:mcp-gsuite")
	if !ok || alt != "pypi:workspace-mcp" {
		t.Fatalf("mcp-gsuite: %q %v", alt, ok)
	}
	if _, ok := UnsupportedOAuthPackage("pypi:workspace-mcp"); ok {
		t.Fatal("workspace-mcp listed as unsupported")
	}
}

// TestDiffRemoteAndOAuthServers: a remote server, a sign-in, a changed
// address, auth or issuer, a new scope, and a changed token rendering are
// each wider than what was consented to; a dropped scope or server narrows
// (ARCHITECTURE.md §9, the install-contract invariant).
func TestDiffRemoteAndOAuthServers(t *testing.T) {
	remote := func(auth string, scopes ...string) MCPServer {
		return MCPServer{URL: "https://mcp.linear.app/mcp", Auth: auth, Scopes: scopes}
	}
	pkg := func(o *MCPOAuth) MCPServer {
		return MCPServer{PyPI: "workspace-mcp", Version: "2.0.1", OAuth: o}
	}
	google := func(scopes ...string) *MCPOAuth {
		return &MCPOAuth{Issuer: "https://accounts.google.com", Scopes: scopes,
			Files: []MCPOAuthFile{{Path: "me.json", Template: `{"token":"{access_token}"}`}},
			Env:   map[string]string{"WORKSPACE_MCP_CREDENTIALS_DIR": "{dir}"}}
	}
	caps := func(s ...MCPServer) Capabilities { return Capabilities{MCPServers: s} }
	tests := []struct {
		name     string
		old, new Capabilities
		widened  bool
		contains string
	}{
		{"adds a remote server", caps(), caps(remote(AuthOAuth, "read")), true,
			"adds MCP server: url:https://mcp.linear.app/mcp (auth oauth; scopes read)"},
		{"none to oauth", caps(remote(AuthNone)), caps(remote(AuthOAuth, "read")), true,
			"changes auth of MCP server url:https://mcp.linear.app/mcp: oauth (was none)"},
		{"a new scope", caps(remote(AuthOAuth, "read")), caps(remote(AuthOAuth, "read", "write")), true,
			"adds scope write to MCP server url:https://mcp.linear.app/mcp"},
		{"a dropped scope narrows", caps(remote(AuthOAuth, "read", "write")), caps(remote(AuthOAuth, "read")), false,
			"drops scope write of MCP server url:https://mcp.linear.app/mcp"},
		{"a new address", caps(remote(AuthOAuth, "read")),
			caps(MCPServer{URL: "https://mcp.linear.app/v2", Auth: AuthOAuth, Scopes: []string{"read"}}), true,
			"adds MCP server: url:https://mcp.linear.app/v2"},
		{"adds a sign-in to a package", caps(pkg(nil)), caps(pkg(google("gmail"))), true,
			"adds an OAuth sign-in to MCP server pypi:workspace-mcp@2.0.1 (issuer https://accounts.google.com; scopes gmail)"},
		{"changes the issuer", caps(pkg(google("gmail"))),
			caps(pkg(&MCPOAuth{Issuer: "https://login.example.com", Scopes: []string{"gmail"}, Files: google().Files, Env: google().Env})), true,
			"changes the issuer of MCP server pypi:workspace-mcp@2.0.1: https://login.example.com (was https://accounts.google.com)"},
		{"a new oauth scope", caps(pkg(google("gmail"))), caps(pkg(google("gmail", "drive"))), true,
			"adds scope drive to MCP server pypi:workspace-mcp@2.0.1"},
		{"a changed rendering", caps(pkg(google("gmail"))),
			caps(pkg(&MCPOAuth{Issuer: "https://accounts.google.com", Scopes: []string{"gmail"},
				Files: []MCPOAuthFile{{Path: "me.json", Template: `{"token":"{access_token}","x":1}`}}, Env: google().Env})), true,
			"changes how MCP server pypi:workspace-mcp@2.0.1 receives its token"},
		{"drops a sign-in", caps(pkg(google("gmail"))), caps(pkg(nil)), false,
			"drops the OAuth sign-in of MCP server pypi:workspace-mcp@2.0.1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := DiffCapabilities(tc.old, tc.new)
			if d.HasWidened() != tc.widened {
				t.Fatalf("widened = %v, want %v: %+v", d.HasWidened(), tc.widened, d)
			}
			all := strings.Join(append(append([]string{}, d.Widened...), d.Narrowed...), "\n")
			if !strings.Contains(all, tc.contains) {
				t.Fatalf("diff lacks %q:\n%s", tc.contains, all)
			}
		})
	}
	if d := DiffCapabilities(caps(remote(AuthOAuth, "read"), pkg(google("gmail"))), caps(remote(AuthOAuth, "read"), pkg(google("gmail")))); !d.Empty() {
		t.Fatalf("an identical contract diffs: %+v", d)
	}
}

// TestV2SchemaRemoteServerShape pins the JSON schema's remote-server and
// oauth limits to the constants pkg/manifest enforces.
func TestV2SchemaRemoteServerShape(t *testing.T) {
	raw, err := os.ReadFile("../../schemas/agent-manifest-2.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Defs struct {
			MCPServer struct {
				OneOf      []json.RawMessage `json:"oneOf"`
				Properties struct {
					URL struct {
						MaxLength int `json:"maxLength"`
					} `json:"url"`
					Auth struct {
						Enum []string `json:"enum"`
					} `json:"auth"`
					OAuth json.RawMessage `json:"oauth"`
				} `json:"properties"`
			} `json:"mcpServer"`
			Scopes struct {
				MaxItems int `json:"maxItems"`
				Items    struct {
					MaxLength int `json:"maxLength"`
				} `json:"items"`
			} `json:"oauthScopes"`
			OAuth struct {
				Required   []string `json:"required"`
				Properties struct {
					Files struct {
						MaxItems int `json:"maxItems"`
						Items    struct {
							Properties struct {
								Path struct {
									Pattern string `json:"pattern"`
								} `json:"path"`
								Template struct {
									MaxLength int `json:"maxLength"`
								} `json:"template"`
							} `json:"properties"`
						} `json:"items"`
					} `json:"files"`
					Env struct {
						MaxProperties int `json:"maxProperties"`
					} `json:"env"`
				} `json:"properties"`
			} `json:"mcpOAuth"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	d := schema.Defs
	if len(d.MCPServer.OneOf) != 3 || d.MCPServer.Properties.URL.MaxLength != MaxRemoteURLLength || d.MCPServer.Properties.OAuth == nil {
		t.Fatalf("mcpServer: %+v", d.MCPServer)
	}
	if !slices.Equal(d.MCPServer.Properties.Auth.Enum, []string{AuthOAuth, AuthSecret, AuthNone}) {
		t.Fatalf("auth enum = %v", d.MCPServer.Properties.Auth.Enum)
	}
	if d.Scopes.MaxItems != MaxMCPScopes || d.Scopes.Items.MaxLength != MaxMCPScopeLength {
		t.Fatalf("oauthScopes = %+v", d.Scopes)
	}
	f := d.OAuth.Properties.Files
	if !slices.Equal(d.OAuth.Required, []string{"issuer"}) || f.MaxItems != MaxOAuthFiles ||
		f.Items.Properties.Template.MaxLength != MaxOAuthTemplateBytes ||
		f.Items.Properties.Path.Pattern != oauthFileNameRE.String() ||
		d.OAuth.Properties.Env.MaxProperties != MaxOAuthEnvEntries {
		t.Fatalf("mcpOAuth = %+v", d.OAuth)
	}
}
