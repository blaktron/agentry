package manifest

import (
	"strings"
	"testing"
)

// The widening rule the CLI and the desktop apply on an update, and the
// registry applies to an account install: an install re-asks for the
// capability acceptance only when the new release's contract widened
// against the one the person accepted.
func TestDiffCapabilitiesWidening(t *testing.T) {
	tests := []struct {
		name     string
		old, new Capabilities
		widened  bool
		contains string
		// lacks, when set, must not appear in the diff: the line is the
		// plain one, not a variant that carries more.
		lacks string
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
			contains: "adds MCP server: npm:@scope/x@1.2.3 (env MODE=ro; every tool it serves)",
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
		{
			name:     "a new env key on a server that already has env",
			old:      Capabilities{MCPServers: []MCPServer{{NPM: "x", Version: "1", Env: map[string]string{"MODE": "ro"}}}},
			new:      Capabilities{MCPServers: []MCPServer{{NPM: "x", Version: "1", Env: map[string]string{"MODE": "ro", "EXTRA": "1"}}}},
			widened:  true,
			contains: "changes env of MCP server npm:x@1: EXTRA=1",
			lacks:    "MODE",
		},
		{
			name:     "a first env key on a server that had none",
			old:      Capabilities{MCPServers: []MCPServer{{NPM: "x", Version: "1"}}},
			new:      Capabilities{MCPServers: []MCPServer{{NPM: "x", Version: "1", Env: map[string]string{"EXTRA": "1"}}}},
			widened:  true,
			contains: "changes env of MCP server npm:x@1: EXTRA=1",
		},
		{
			name:     "a dropped env key is a narrowing",
			old:      Capabilities{MCPServers: []MCPServer{{NPM: "x", Version: "1", Env: map[string]string{"MODE": "ro", "EXTRA": "1"}}}},
			new:      Capabilities{MCPServers: []MCPServer{{NPM: "x", Version: "1", Env: map[string]string{"MODE": "ro"}}}},
			widened:  false,
			contains: "drops env EXTRA of MCP server npm:x@1",
		},
		{
			name:     "a second exec command does not claim the first one's wording",
			old:      Capabilities{Exec: ExecCapability{Commands: []string{"git"}}},
			new:      Capabilities{Exec: ExecCapability{Commands: []string{"git", "curl"}}},
			widened:  true,
			contains: "adds subprocess execution: curl",
			lacks:    "previously none",
		},
		{
			name:     "exec dropping one of two commands",
			old:      Capabilities{Exec: ExecCapability{Commands: []string{"git", "make"}}},
			new:      Capabilities{Exec: ExecCapability{Commands: []string{"git"}}},
			widened:  false,
			contains: "drops subprocess execution: make",
		},
		{
			name:     "exec dropping its last command",
			old:      Capabilities{Exec: ExecCapability{Commands: []string{"git"}}},
			new:      Capabilities{},
			widened:  false,
			contains: "drops subprocess execution: git",
		},
		{
			name:     "an agent-level secret dropped is a narrowing",
			old:      Capabilities{Secrets: []string{"API_KEY", "OLD_KEY"}},
			new:      Capabilities{Secrets: []string{"API_KEY"}},
			widened:  false,
			contains: "no longer asks for secret: OLD_KEY",
		},
		{
			name:     "a data access category dropped is a narrowing",
			old:      Capabilities{DataAccess: []DataAccess{"source-code", "email"}},
			new:      Capabilities{DataAccess: []DataAccess{"source-code"}},
			widened:  false,
			contains: "drops data access: email",
		},
		{
			name:     "a dropped read path is a narrowing",
			old:      Capabilities{Filesystem: Filesystem{Read: FSAccess{Mode: FSModePaths, Paths: []string{"a", "b"}}}},
			new:      Capabilities{Filesystem: Filesystem{Read: FSAccess{Mode: FSModePaths, Paths: []string{"a"}}}},
			widened:  false,
			contains: "drops filesystem read path: b",
		},
		{
			name:     "a dropped write path is a narrowing",
			old:      Capabilities{Filesystem: Filesystem{Write: FSAccess{Mode: FSModePaths, Paths: []string{"out", "/etc"}}}},
			new:      Capabilities{Filesystem: Filesystem{Write: FSAccess{Mode: FSModePaths, Paths: []string{"out"}}}},
			widened:  false,
			contains: "drops filesystem write path: /etc",
		},
		{
			name:     "a new read path",
			old:      Capabilities{Filesystem: Filesystem{Read: FSAccess{Mode: FSModePaths, Paths: []string{"a"}}}},
			new:      Capabilities{Filesystem: Filesystem{Read: FSAccess{Mode: FSModePaths, Paths: []string{"a", "b"}}}},
			widened:  true,
			contains: "adds filesystem read path: b",
		},
		{
			name:     "paths to workspace widens",
			old:      Capabilities{Filesystem: Filesystem{Write: FSAccess{Mode: FSModePaths, Paths: []string{"out"}}}},
			new:      Capabilities{Filesystem: Filesystem{Write: FSAccess{Mode: FSModeWorkspace}}},
			widened:  true,
			contains: "widens filesystem write from paths to workspace",
		},
		{
			name:     "workspace to paths narrows and names the paths",
			old:      Capabilities{Filesystem: Filesystem{Write: FSAccess{Mode: FSModeWorkspace}}},
			new:      Capabilities{Filesystem: Filesystem{Write: FSAccess{Mode: FSModePaths, Paths: []string{"out", "tmp"}}}},
			widened:  false,
			contains: "narrows filesystem write from workspace to paths out, tmp",
		},
		{
			name:     "undeclared to paths widens and names the paths",
			old:      Capabilities{},
			new:      Capabilities{Filesystem: Filesystem{Read: FSAccess{Mode: FSModePaths, Paths: []string{"src"}}}},
			widened:  true,
			contains: "widens filesystem read from undeclared to paths src",
		},
		{
			name:     "paths to undeclared narrows",
			old:      Capabilities{Filesystem: Filesystem{Read: FSAccess{Mode: FSModePaths, Paths: []string{"src"}}}},
			new:      Capabilities{},
			widened:  false,
			contains: "narrows filesystem read from paths to undeclared",
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
			if tt.lacks != "" && strings.Contains(all, tt.lacks) {
				t.Errorf("diff %q carries %q", all, tt.lacks)
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
	// A path list only counts in the paths form: the same mode with
	// different paths listed beside it is the same access.
	for _, mode := range []FSMode{FSModeWorkspace, FSModeNone} {
		with := Capabilities{Filesystem: Filesystem{Read: FSAccess{Mode: mode, Paths: []string{"a"}}}}
		other := Capabilities{Filesystem: Filesystem{Read: FSAccess{Mode: mode, Paths: []string{"b"}}}}
		if d := DiffCapabilities(with, other); !d.Empty() {
			t.Fatalf("paths beside mode %q diffed: %+v", mode, d)
		}
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
