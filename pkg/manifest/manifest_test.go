package manifest

import (
	"strings"
	"testing"
)

// normativeYAML is the §5.2 normative example (comment lines trimmed, the
// commented-out mcp block omitted).
const normativeYAML = `schemaVersion: "1"
name: incident-summarizer
namespace: acme
kind: skill
version: 1.4.2
summary: "Summarizes PagerDuty incidents into postmortem drafts"
license: Apache-2.0
authors:
  - name: Jane Doe
    email: jane@acme.example
homepage: https://acme.example/agents/incident-summarizer
tags: [incident-response, summarization]

entrypoints:
  skill: SKILL.md

runtime:
  models: ["claude-*"]
  interfaces: [claude-skill]

capabilities:
  network:
    egress: [api.pagerduty.com]
  filesystem:
    read: workspace
    write: none
  exec: none
  secrets: [PAGERDUTY_TOKEN]
  dataAccess: [tickets]

dependencies:
  agents: []

publish:
  include: [agent.yaml, README.md, SKILL.md, prompts/**, LICENSE]
  channel: stable
`

func mustParse(t *testing.T, y string) *Manifest {
	t.Helper()
	m, err := Parse([]byte(y))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return m
}

func TestParseNormativeExample(t *testing.T) {
	m := mustParse(t, normativeYAML)
	if m.Name != "incident-summarizer" || m.Namespace != "acme" || m.Kind != "skill" {
		t.Errorf("identity fields: %+v", m)
	}
	if m.Version != "1.4.2" || m.License != "Apache-2.0" {
		t.Errorf("version/license: %q %q", m.Version, m.License)
	}
	if len(m.Authors) != 1 || m.Authors[0].Email != "jane@acme.example" {
		t.Errorf("authors: %+v", m.Authors)
	}
	if m.Entrypoints.Skill != "SKILL.md" || m.Entrypoints.MCP != nil {
		t.Errorf("entrypoints: %+v", m.Entrypoints)
	}
	eg := m.Capabilities.Network.Egress
	if eg.None || len(eg.Hosts) != 1 || eg.Hosts[0] != "api.pagerduty.com" {
		t.Errorf("egress: %+v", eg)
	}
	if m.Capabilities.Filesystem.Read.Mode != FSModeWorkspace {
		t.Errorf("fs read: %+v", m.Capabilities.Filesystem.Read)
	}
	if m.Capabilities.Filesystem.Write.Mode != FSModeNone {
		t.Errorf("fs write: %+v", m.Capabilities.Filesystem.Write)
	}
	if !m.Capabilities.Exec.None {
		t.Errorf("exec: %+v", m.Capabilities.Exec)
	}
	if m.Publish.Channel != ChannelStable || m.EffectiveChannel() != ChannelStable {
		t.Errorf("channel: %q", m.Publish.Channel)
	}
}

// TestParseClosedSchema covers V1's closed-schema half: unknown keys are
// rejected at every level, including inside the union capability shapes.
func TestParseClosedSchema(t *testing.T) {
	cases := []struct {
		name string
		yaml string
	}{
		{"top-level", normativeYAML + "extraKey: true\n"},
		{"nested publish", strings.Replace(normativeYAML, "channel: stable", "channel: stable\n  compress: true", 1)},
		{"nested entrypoints", strings.Replace(normativeYAML, "skill: SKILL.md", "skill: SKILL.md\n  binary: a.out", 1)},
		{"capabilities", strings.Replace(normativeYAML, "exec: none", "exec: none\n  gpu: true", 1)},
		{"filesystem paths sibling", strings.Replace(normativeYAML, "read: workspace",
			"read:\n      paths: [data/]\n      mode: fast", 1)},
		{"exec commands sibling", strings.Replace(normativeYAML, "exec: none",
			"exec:\n    commands: [git]\n    shell: true", 1)},
		{"mcp entrypoint", strings.Replace(normativeYAML, "skill: SKILL.md",
			"mcp:\n    command: node\n    args: [x.js]\n    transport: stdio\n    port: 80", 1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse([]byte(tc.yaml)); err == nil {
				t.Fatalf("expected unknown-key error")
			}
		})
	}
}

func TestParseSchemaVersion(t *testing.T) {
	cases := []struct {
		name    string
		version string
		ok      bool
	}{
		{"major 1", `"1"`, true},
		{"unquoted 1", `1`, true},
		{"minor allowed", `"1.0"`, true},
		{"major 2", `"2"`, true},
		{"major 2 dotted", `"2.0"`, true},
		{"major 3", `"3"`, false},
		{"garbage", `"one"`, false},
		{"empty", `""`, false},
		{"trailing dot", `"1."`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			y := strings.Replace(normativeYAML, `schemaVersion: "1"`, "schemaVersion: "+tc.version, 1)
			_, err := Parse([]byte(y))
			if tc.ok && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("expected schemaVersion rejection")
			}
		})
	}
}

func TestParseUnionShapes(t *testing.T) {
	t.Run("egress none scalar", func(t *testing.T) {
		m := mustParse(t, strings.Replace(normativeYAML, "egress: [api.pagerduty.com]", "egress: none", 1))
		if !m.Capabilities.Network.Egress.None {
			t.Fatalf("egress: %+v", m.Capabilities.Network.Egress)
		}
	})
	t.Run("egress star scalar normalizes", func(t *testing.T) {
		m := mustParse(t, strings.Replace(normativeYAML, "egress: [api.pagerduty.com]", `egress: "*"`, 1))
		if got := m.Capabilities.Network.Egress.Hosts; len(got) != 1 || got[0] != "*" {
			t.Fatalf("egress: %+v", got)
		}
	})
	t.Run("egress bogus scalar", func(t *testing.T) {
		y := strings.Replace(normativeYAML, "egress: [api.pagerduty.com]", "egress: everywhere", 1)
		if _, err := Parse([]byte(y)); err == nil {
			t.Fatalf("expected error")
		}
	})
	t.Run("egress mapping", func(t *testing.T) {
		y := strings.Replace(normativeYAML, "egress: [api.pagerduty.com]", "egress: {hosts: [a.example]}", 1)
		if _, err := Parse([]byte(y)); err == nil {
			t.Fatalf("expected error")
		}
	})
	t.Run("filesystem paths form", func(t *testing.T) {
		m := mustParse(t, strings.Replace(normativeYAML, "read: workspace", "read:\n      paths: [data/cache.json]", 1))
		r := m.Capabilities.Filesystem.Read
		if r.Mode != FSModePaths || len(r.Paths) != 1 || r.Paths[0] != "data/cache.json" {
			t.Fatalf("read: %+v", r)
		}
	})
	t.Run("filesystem bogus scalar", func(t *testing.T) {
		y := strings.Replace(normativeYAML, "read: workspace", "read: everything", 1)
		if _, err := Parse([]byte(y)); err == nil {
			t.Fatalf("expected error")
		}
	})
	t.Run("exec commands form", func(t *testing.T) {
		m := mustParse(t, strings.Replace(normativeYAML, "exec: none", "exec:\n    commands: [git, jq]", 1))
		x := m.Capabilities.Exec
		if x.None || len(x.Commands) != 2 || x.Commands[0] != "git" {
			t.Fatalf("exec: %+v", x)
		}
	})
	t.Run("exec bogus scalar", func(t *testing.T) {
		y := strings.Replace(normativeYAML, "exec: none", "exec: anything", 1)
		if _, err := Parse([]byte(y)); err == nil {
			t.Fatalf("expected error")
		}
	})
}

func TestParseRejectsExtraDocumentsAndEmpty(t *testing.T) {
	if _, err := Parse([]byte(normativeYAML + "---\nsecond: doc\n")); err == nil {
		t.Errorf("expected multi-document rejection")
	}
	if _, err := Parse(nil); err == nil {
		t.Errorf("expected empty-input rejection")
	}
	if _, err := Parse([]byte("# only a comment\n")); err == nil {
		t.Errorf("expected empty-document rejection")
	}
	if _, err := Parse([]byte("{{{")); err == nil {
		t.Errorf("expected syntax-error rejection")
	}
}
