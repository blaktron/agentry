package manifest

import (
	"slices"
	"testing"
)

// TestDiffCapabilitiesComparesAPackageServersOwnCapabilities: a release
// that keeps a package server at the same pin but changes what its own
// container is given (hosts, secrets, tools) is a widening or a narrowing
// of that server, named by its identity.
func TestDiffCapabilitiesComparesAPackageServersOwnCapabilities(t *testing.T) {
	srv := func(egress, secrets, tools []string) Capabilities {
		return Capabilities{MCPServers: []MCPServer{{NPM: "@acme/osv-mcp", Version: "1.2.3", Egress: egress, Secrets: secrets, Tools: tools}}}
	}
	base := srv([]string{"api.osv.dev"}, []string{"OSV_TOKEN"}, []string{"query"})
	tests := []struct {
		name              string
		old, new          Capabilities
		widened, narrowed []string
	}{
		{
			name: "an added egress host", old: base,
			new:     srv([]string{"api.osv.dev", "evil.example"}, []string{"OSV_TOKEN"}, []string{"query"}),
			widened: []string{"adds network egress to evil.example for MCP server npm:@acme/osv-mcp@1.2.3"},
		},
		{
			name: "unrestricted egress", old: base,
			new:     srv([]string{"api.osv.dev", "*"}, []string{"OSV_TOKEN"}, []string{"query"}),
			widened: []string{"adds UNRESTRICTED network egress (any host) for MCP server npm:@acme/osv-mcp@1.2.3"},
		},
		{
			name: "an added secret", old: base,
			new:     srv([]string{"api.osv.dev"}, []string{"OSV_TOKEN", "AWS_SECRET_ACCESS_KEY"}, []string{"query"}),
			widened: []string{"gives MCP server npm:@acme/osv-mcp@1.2.3 the secret AWS_SECRET_ACCESS_KEY"},
		},
		{
			name: "an added tool", old: base,
			new:     srv([]string{"api.osv.dev"}, []string{"OSV_TOKEN"}, []string{"query", "write"}),
			widened: []string{"adds tool write to MCP server npm:@acme/osv-mcp@1.2.3"},
		},
		{
			name: "restricted to every tool", old: base,
			new:     srv([]string{"api.osv.dev"}, []string{"OSV_TOKEN"}, nil),
			widened: []string{"lifts the tool allowlist of MCP server npm:@acme/osv-mcp@1.2.3 (every tool it serves)"},
		},
		{
			name: "every narrowing at once", old: base,
			new: srv(nil, nil, nil),
			// Dropping the allowlist is still a widening: every tool.
			widened:  []string{"lifts the tool allowlist of MCP server npm:@acme/osv-mcp@1.2.3 (every tool it serves)"},
			narrowed: []string{"drops network egress to api.osv.dev for MCP server npm:@acme/osv-mcp@1.2.3", "no longer gives MCP server npm:@acme/osv-mcp@1.2.3 the secret OSV_TOKEN"},
		},
		{
			name: "egress, secret and tool removed, allowlist kept",
			old:  srv([]string{"api.osv.dev", "b.example"}, []string{"OSV_TOKEN", "B"}, []string{"query", "write"}),
			new:  base,
			narrowed: []string{
				"drops network egress to b.example for MCP server npm:@acme/osv-mcp@1.2.3",
				"no longer gives MCP server npm:@acme/osv-mcp@1.2.3 the secret B",
				"drops tool write of MCP server npm:@acme/osv-mcp@1.2.3",
			},
		},
		{
			name: "every tool to a list", old: srv([]string{"api.osv.dev"}, []string{"OSV_TOKEN"}, nil), new: base,
			narrowed: []string{"restricts MCP server npm:@acme/osv-mcp@1.2.3 to tools query"},
		},
		{name: "unchanged", old: base, new: base},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := DiffCapabilities(tt.old, tt.new)
			if !slices.Equal(d.Widened, tt.widened) || !slices.Equal(d.Narrowed, tt.narrowed) {
				t.Fatalf("widened %q narrowed %q, want widened %q narrowed %q", d.Widened, d.Narrowed, tt.widened, tt.narrowed)
			}
		})
	}
}

// A server's secrets compare by name: moving one between optional and
// required is neither a widening nor a narrowing.
func TestAServerSecretsOptionalMarkingIsNotADiff(t *testing.T) {
	srv := MCPServer{NPM: "x", Version: "1", Secrets: []string{"TOKEN"}}
	old := Capabilities{MCPServers: []MCPServer{srv}, Secrets: []string{"TOKEN"}}
	next := Capabilities{MCPServers: []MCPServer{srv}, Secrets: []string{"TOKEN"}, OptionalSecrets: []string{"TOKEN"}}
	if d := DiffCapabilities(old, next); len(d.Widened)+len(d.Narrowed) != 0 {
		t.Fatalf("an optional marking changed the diff: %+v", d)
	}
}

// TestANewPackageServersLineNamesItsOwnGrants: a server new to the
// contract, or the same package at a new pin, is asked about with what its
// own container is given, so the person is told a new server may reach
// any host before they agree to it.
func TestANewPackageServersLineNamesItsOwnGrants(t *testing.T) {
	srv := func(version string, egress, secrets, tools []string) Capabilities {
		return Capabilities{MCPServers: []MCPServer{{NPM: "@acme/osv-mcp", Version: version, Egress: egress, Secrets: secrets, Tools: tools}}}
	}
	tests := []struct {
		name     string
		old, new Capabilities
		widened  []string
	}{
		{
			name:    "a new server with hosts, secrets and an allowlist",
			new:     srv("1.2.3", []string{"b.example", "a.example"}, []string{"OSV_TOKEN"}, []string{"query", "list"}),
			widened: []string{"adds MCP server: npm:@acme/osv-mcp@1.2.3 (network egress to a.example, b.example; secrets OSV_TOKEN; tools list, query)"},
		},
		{
			name:    "a new server that may reach any host and every tool",
			new:     srv("1.2.3", []string{"api.osv.dev", "*"}, nil, nil),
			widened: []string{"adds MCP server: npm:@acme/osv-mcp@1.2.3 (UNRESTRICTED network egress (any host); every tool it serves)"},
		},
		{
			name:    "a new server that declares no egress and no secret",
			new:     srv("1.2.3", nil, nil, []string{"query"}),
			widened: []string{"adds MCP server: npm:@acme/osv-mcp@1.2.3 (tools query)"},
		},
		{
			name:    "the same package at a new pin",
			old:     srv("1.2.3", []string{"api.osv.dev"}, []string{"OSV_TOKEN"}, []string{"query"}),
			new:     srv("1.2.4", []string{"api.osv.dev", "*"}, []string{"OSV_TOKEN"}, nil),
			widened: []string{"adds MCP server: npm:@acme/osv-mcp@1.2.4 (UNRESTRICTED network egress (any host); secrets OSV_TOKEN; every tool it serves)"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if d := DiffCapabilities(tt.old, tt.new); !slices.Equal(d.Widened, tt.widened) {
				t.Fatalf("widened %q, want %q", d.Widened, tt.widened)
			}
		})
	}
}
