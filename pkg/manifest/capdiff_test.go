package manifest

import (
	"strings"
	"testing"
)

// The widening rule the CLI and the desktop apply on an update (§11), now
// the registry's too (agentry#448): an account install re-asks for the
// capability acceptance only when the new release's contract widened
// against the one the person accepted.
func TestDiffCapabilitiesWidening(t *testing.T) {
	tests := []struct {
		name     string
		old, new Capabilities
		widened  bool
		contains string
	}{
		{
			name:     "new egress host",
			old:      Capabilities{Network: Network{Egress: Egress{None: true}}},
			new:      Capabilities{Network: Network{Egress: Egress{Hosts: []string{"evil.example"}}}},
			widened:  true,
			contains: "adds network egress to evil.example",
		},
		{
			name:     "wildcard egress is called out as unrestricted",
			old:      Capabilities{Network: Network{Egress: Egress{Hosts: []string{"api.example"}}}},
			new:      Capabilities{Network: Network{Egress: Egress{Hosts: []string{"api.example", "*"}}}},
			widened:  true,
			contains: "UNRESTRICTED",
		},
		{
			name:     "exec none to commands",
			old:      Capabilities{},
			new:      Capabilities{Exec: ExecCapability{Commands: []string{"git"}}},
			widened:  true,
			contains: "adds subprocess execution: git (previously none)",
		},
		{
			name:     "filesystem write escalation",
			old:      Capabilities{Filesystem: Filesystem{Write: FSAccess{Mode: FSModeNone}}},
			new:      Capabilities{Filesystem: Filesystem{Write: FSAccess{Mode: FSModeWorkspace}}},
			widened:  true,
			contains: "widens filesystem write from none to workspace",
		},
		{
			name:     "a new explicit write path",
			old:      Capabilities{Filesystem: Filesystem{Write: FSAccess{Mode: FSModePaths, Paths: []string{"out"}}}},
			new:      Capabilities{Filesystem: Filesystem{Write: FSAccess{Mode: FSModePaths, Paths: []string{"out", "/etc"}}}},
			widened:  true,
			contains: "adds filesystem write path: /etc",
		},
		{
			name:     "a new secret",
			old:      Capabilities{Secrets: []string{"API_KEY"}},
			new:      Capabilities{Secrets: []string{"API_KEY", "AWS_SECRET_ACCESS_KEY"}},
			widened:  true,
			contains: "asks for a new secret: AWS_SECRET_ACCESS_KEY",
		},
		{
			name:     "new data access",
			old:      Capabilities{},
			new:      Capabilities{DataAccess: []DataAccess{"source-code"}},
			widened:  true,
			contains: "adds data access: source-code",
		},
		{
			name:     "a new MCP server",
			old:      Capabilities{},
			new:      Capabilities{MCPServers: []MCPServer{{NPM: "@scope/x", Version: "1.2.3", Env: map[string]string{"MODE": "ro"}}}},
			widened:  true,
			contains: "adds MCP server: npm:@scope/x@1.2.3 (env MODE=ro)",
		},
		{
			name:     "the same server at a new pin",
			old:      Capabilities{MCPServers: []MCPServer{{PyPI: "srv", Version: "1.0.0"}}},
			new:      Capabilities{MCPServers: []MCPServer{{PyPI: "srv", Version: "1.0.1"}}},
			widened:  true,
			contains: "adds MCP server: pypi:srv@1.0.1",
		},
		{
			name:     "a changed env value on the same server",
			old:      Capabilities{MCPServers: []MCPServer{{NPM: "x", Version: "1", Env: map[string]string{"MODE": "ro"}}}},
			new:      Capabilities{MCPServers: []MCPServer{{NPM: "x", Version: "1", Env: map[string]string{"MODE": "rw"}}}},
			widened:  true,
			contains: "changes env of MCP server npm:x@1: MODE=rw (was ro)",
		},
		{
			name:     "dropping an egress host is a narrowing",
			old:      Capabilities{Network: Network{Egress: Egress{Hosts: []string{"a.example", "b.example"}}}},
			new:      Capabilities{Network: Network{Egress: Egress{Hosts: []string{"a.example"}}}},
			widened:  false,
			contains: "drops network egress to b.example",
		},
		{
			name:     "narrowing write access",
			old:      Capabilities{Filesystem: Filesystem{Write: FSAccess{Mode: FSModeWorkspace}}},
			new:      Capabilities{Filesystem: Filesystem{Write: FSAccess{Mode: FSModeNone}}},
			widened:  false,
			contains: "narrows filesystem write from workspace to none",
		},
		{
			name:     "a dropped MCP server is a narrowing",
			old:      Capabilities{MCPServers: []MCPServer{{NPM: "x", Version: "1"}}},
			new:      Capabilities{},
			widened:  false,
			contains: "drops MCP server: npm:x@1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := DiffCapabilities(tt.old, tt.new)
			if d.HasWidened() != tt.widened {
				t.Fatalf("widened = %v, want %v (widened=%v narrowed=%v)",
					d.HasWidened(), tt.widened, d.Widened, d.Narrowed)
			}
			all := strings.Join(append(append([]string{}, d.Widened...), d.Narrowed...), " | ")
			if !strings.Contains(all, tt.contains) {
				t.Errorf("diff %q does not contain %q", all, tt.contains)
			}
		})
	}
}

// An unchanged contract must produce nothing, or every update re-asks a
// question the person already answered.
func TestDiffCapabilitiesIdentical(t *testing.T) {
	c := Capabilities{
		Network:    Network{Egress: Egress{Hosts: []string{"api.example"}}},
		Exec:       ExecCapability{Commands: []string{"git"}},
		Filesystem: Filesystem{Read: FSAccess{Mode: FSModeWorkspace}, Write: FSAccess{Mode: FSModePaths, Paths: []string{"out"}}},
		Secrets:    []string{"API_KEY"},
		DataAccess: []DataAccess{"source-code"},
		MCPServers: []MCPServer{{NPM: "x", Version: "1", Env: map[string]string{"A": "b"}}},
	}
	if d := DiffCapabilities(c, c); !d.Empty() {
		t.Fatalf("identical contracts diffed: %+v", d)
	}
}

// The ranking: a manifest that stops declaring anything is a step DOWN from
// an explicit "none" (we know less than before), but not a step up into
// access.
func TestDiffCapabilitiesUndeclaredVsExplicitNone(t *testing.T) {
	toUndeclared := DiffCapabilities(
		Capabilities{Filesystem: Filesystem{Read: FSAccess{Mode: FSModeNone}}},
		Capabilities{})
	if !toUndeclared.HasWidened() {
		t.Error("none -> undeclared should be reported as a widening")
	}
	toWorkspace := DiffCapabilities(
		Capabilities{},
		Capabilities{Filesystem: Filesystem{Read: FSAccess{Mode: FSModeWorkspace}}})
	if !toWorkspace.HasWidened() {
		t.Error("undeclared -> workspace must be a widening")
	}
	toNone := DiffCapabilities(
		Capabilities{},
		Capabilities{Filesystem: Filesystem{Read: FSAccess{Mode: FSModeNone}}})
	if toNone.HasWidened() {
		t.Error("undeclared -> none is a promise, not a widening")
	}
}
