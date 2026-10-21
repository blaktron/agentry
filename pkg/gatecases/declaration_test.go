package gatecases

import (
	"slices"
	"testing"

	"github.com/blaktron/agentry/pkg/manifest"
)

// TestDeclarationReadsEveryField: what S4's rating by declaration reads
// from a manifest that declares each thing it looks at.
func TestDeclarationReadsEveryField(t *testing.T) {
	d := Declaration([]byte(`{"schemaVersion":"2","name":"x","summary":"x",
		"intake":[{"id":"site","prompt":"Which site?","type":"url","required":true}],
		"capabilities":{
		"network":{"egress":["API.github.com","none"]},
		"exec":{"commands":["git","jq"]},
		"filesystem":{"write":{"paths":["out/"]}},
		"secrets":["GITHUB_PAT"],
		"browser":{"sites":["site"],"hosts":["Fonts.GStatic.com"]},
		"mcpServers":[
			{"npm":"@x/server","version":"1.0.0","secrets":["S_KEY"]},
			{"url":"https://MCP.Linear.app/mcp","auth":"oauth"}]}}`))
	if d.EgressAny || !slices.Equal(d.Egress, []string{"api.github.com"}) {
		t.Errorf("egress = %v any=%v", d.Egress, d.EgressAny)
	}
	if !slices.Equal(d.ServerHosts, []string{"mcp.linear.app"}) || !d.MCPServers {
		t.Errorf("servers = %v declared=%v", d.ServerHosts, d.MCPServers)
	}
	if d.BrowserAny || !slices.Equal(d.BrowserHosts, []string{"fonts.gstatic.com"}) {
		t.Errorf("browser = %v any=%v", d.BrowserHosts, d.BrowserAny)
	}
	if !slices.Equal(d.Secrets, []string{"GITHUB_PAT", "S_KEY"}) {
		t.Errorf("secrets = %v", d.Secrets)
	}
	if !slices.Equal(d.Exec, []string{"git", "jq"}) || !d.FileWrite {
		t.Errorf("exec = %v fileWrite = %v", d.Exec, d.FileWrite)
	}
	if !slices.Equal(d.BaseCommands, manifest.BaseExecCommands()) {
		t.Errorf("base commands = %v", d.BaseCommands)
	}
}

// TestDeclarationOfNothing: a manifest that declares nothing, and one that
// does not read, declare nothing but the base commands; "*" egress names
// no host, and exec none is no command list.
func TestDeclarationOfNothing(t *testing.T) {
	for _, mj := range []string{`{"capabilities":{}}`, `not json`, `{"capabilities":{"exec":"none","filesystem":{"write":"none"}}}`} {
		d := Declaration([]byte(mj))
		if d.EgressAny || d.Egress != nil || d.ServerHosts != nil || d.MCPServers || d.BrowserAny ||
			d.BrowserHosts != nil || d.Secrets != nil || d.Exec != nil || d.FileWrite {
			t.Errorf("%s declares %+v", mj, d)
		}
		if len(d.BaseCommands) == 0 {
			t.Errorf("%s: no base commands", mj)
		}
	}
	if d := Declaration([]byte(`{"capabilities":{"network":{"egress":"*"}}}`)); !d.EgressAny || d.Egress != nil {
		t.Errorf("wildcard egress = %v any=%v", d.Egress, d.EgressAny)
	}
}
