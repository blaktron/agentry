package manifest

import (
	"fmt"
	"strings"
	"testing"
)

// validSkillManifest returns the normative §5.2 example as a struct.
func validSkillManifest() *Manifest {
	return &Manifest{
		SchemaVersion: "1",
		Name:          "incident-summarizer",
		Namespace:     "acme",
		Kind:          KindSkill,
		Version:       "1.4.2",
		Summary:       "Summarizes PagerDuty incidents into postmortem drafts",
		License:       "Apache-2.0",
		Authors:       []Author{{Name: "Jane Doe", Email: "jane@acme.example"}},
		Homepage:      "https://acme.example/agents/incident-summarizer",
		Tags:          []string{"incident-response", "summarization"},
		Entrypoints:   Entrypoints{Skill: "SKILL.md"},
		Runtime:       Runtime{Models: []string{"claude-*"}, Interfaces: []string{InterfaceClaudeSkill}},
		Capabilities: Capabilities{
			Network:    Network{Egress: Egress{Hosts: []string{"api.pagerduty.com"}}},
			Filesystem: Filesystem{Read: FSAccess{Mode: FSModeWorkspace}, Write: FSAccess{Mode: FSModeNone}},
			Exec:       ExecCapability{None: true},
			Secrets:    []string{"PAGERDUTY_TOKEN"},
			DataAccess: []DataAccess{DataAccessTickets},
		},
		Publish: Publish{
			Include: []string{"agent.yaml", "README.md", "SKILL.md", "prompts/**", "LICENSE"},
			Channel: ChannelStable,
		},
	}
}

// validMCPManifest returns a minimal valid kind=mcp-server manifest.
func validMCPManifest() *Manifest {
	return &Manifest{
		SchemaVersion: "1",
		Name:          "pd-mcp",
		Namespace:     "acme",
		Kind:          KindMCPServer,
		Version:       "0.1.0",
		Summary:       "PagerDuty MCP server",
		License:       "MIT",
		Entrypoints: Entrypoints{MCP: &MCPEntrypoint{
			Command: "node", Args: []string{"src/server.js"}, Transport: TransportStdio,
		}},
		Publish: Publish{Include: []string{"agent.yaml", "README.md", "src/**", "package-lock.json", "LICENSE"}},
	}
}

// skillContext returns a Context under which validSkillManifest validates
// with zero issues.
func skillContext() Context {
	return Context{
		Namespace:  "acme",
		Name:       "incident-summarizer",
		TagVersion: "v1.4.2",
		ExistingVersions: map[Channel][]string{
			ChannelStable: {"1.4.1", "1.0.0"},
		},
		Public: true,
		Files: []FileInfo{
			{Path: "agent.yaml", Size: 400},
			{Path: "README.md", Size: 1200},
			{Path: "SKILL.md", Size: 5000},
			{Path: "prompts/system.md", Size: 900},
			{Path: "LICENSE", Size: 11000},
			{Path: ".gitignore", Size: 30}, // present but never included
		},
	}
}

// mcpContext returns a Context under which validMCPManifest validates
// with zero issues.
func mcpContext() Context {
	return Context{
		Namespace:  "acme",
		Name:       "pd-mcp",
		TagVersion: "v0.1.0",
		Public:     true,
		Files: []FileInfo{
			{Path: "agent.yaml", Size: 300},
			{Path: "README.md", Size: 800},
			{Path: "src/server.js", Size: 4000},
			{Path: "package-lock.json", Size: 20000},
			{Path: "LICENSE", Size: 1100},
		},
	}
}

func issueStrings(errs []error) string {
	var b strings.Builder
	for _, e := range errs {
		fmt.Fprintf(&b, "\n  %v", e)
	}
	return b.String()
}

// wantIssue asserts that errs contains an *Issue with the given rule,
// severity, and a Path containing pathSub.
func wantIssue(t *testing.T, errs []error, rule string, sev Severity, pathSub string) {
	t.Helper()
	for _, err := range errs {
		i, ok := AsIssue(err)
		if !ok {
			t.Fatalf("non-Issue error in results: %v", err)
		}
		if i.Rule == rule && i.Severity == sev && strings.Contains(i.Path, pathSub) {
			return
		}
	}
	t.Fatalf("no %s %v issue with path containing %q in:%s", rule, sev, pathSub, issueStrings(errs))
}

func wantClean(t *testing.T, errs []error) {
	t.Helper()
	if len(errs) != 0 {
		t.Fatalf("expected zero issues, got:%s", issueStrings(errs))
	}
}

// TestNormativeExampleValidatesClean runs the §5.2 example end to end:
// Parse, Validate, and ValidateInContext must all pass with zero issues
// (warnings included) under a suitable context.
func TestNormativeExampleValidatesClean(t *testing.T) {
	m := mustParse(t, normativeYAML)
	wantClean(t, Validate(m))
	wantClean(t, ValidateInContext(m, skillContext()))
}

func TestValidMCPManifestValidatesClean(t *testing.T) {
	wantClean(t, ValidateInContext(validMCPManifest(), mcpContext()))
}

// TestValidateStatic covers the manifest-only rules: V1 field grammar,
// V3 semver syntax, V4 pattern shape, V5 vocabulary, V6 entrypoint shape,
// V8 summary/tag quotas.
func TestValidateStatic(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Manifest)
		rule    string
		sev     Severity
		pathSub string
	}{
		{"V1 nil schemaVersion", func(m *Manifest) { m.SchemaVersion = "" }, "V1", SeverityError, "schemaVersion"},
		{"V1 wrong major", func(m *Manifest) { m.SchemaVersion = "2" }, "V1", SeverityError, "schemaVersion"},
		{"V1 empty name", func(m *Manifest) { m.Name = "" }, "V1", SeverityError, "name"},
		{"V1 bad name uppercase", func(m *Manifest) { m.Name = "Incident" }, "V1", SeverityError, "name"},
		{"V1 bad name trailing hyphen", func(m *Manifest) { m.Name = "agent-" }, "V1", SeverityError, "name"},
		{"V1 name too long", func(m *Manifest) { m.Name = strings.Repeat("a", 66) }, "V1", SeverityError, "name"},
		{"V1 bad namespace", func(m *Manifest) { m.Namespace = "-acme" }, "V1", SeverityError, "namespace"},
		{"V1 namespace too long", func(m *Manifest) { m.Namespace = strings.Repeat("a", 40) }, "V1", SeverityError, "namespace"},
		{"V1 missing kind", func(m *Manifest) { m.Kind = "" }, "V1", SeverityError, "kind"},
		{"V1 unknown kind", func(m *Manifest) { m.Kind = "binary" }, "V1", SeverityError, "kind"},
		{"V1 missing summary", func(m *Manifest) { m.Summary = "" }, "V1", SeverityError, "summary"},
		{"V1 author without name", func(m *Manifest) { m.Authors = []Author{{Email: "x@y.z"}} }, "V1", SeverityError, "authors[0]"},
		{"V1 skill kind with mcp entrypoint", func(m *Manifest) {
			m.Entrypoints.MCP = &MCPEntrypoint{Command: "node", Transport: TransportStdio}
		}, "V1", SeverityError, "entrypoints.mcp"},
		{"V1 skill kind missing skill entrypoint", func(m *Manifest) { m.Entrypoints.Skill = "" }, "V1", SeverityError, "entrypoints.skill"},
		{"V1 prompt-agent with mcp entrypoint", func(m *Manifest) {
			m.Kind = KindPromptAgent
			m.Entrypoints = Entrypoints{MCP: &MCPEntrypoint{Command: "node", Transport: TransportStdio}}
		}, "V1", SeverityError, "entrypoints.mcp"},
		{"V1 mcp-server with skill entrypoint", func(m *Manifest) {
			m.Kind = KindMCPServer
			m.Entrypoints = Entrypoints{Skill: "SKILL.md", MCP: &MCPEntrypoint{Command: "node", Transport: TransportStdio}}
		}, "V1", SeverityError, "entrypoints.skill"},
		{"V1 absolute skill entrypoint", func(m *Manifest) { m.Entrypoints.Skill = "/etc/passwd" }, "V1", SeverityError, "entrypoints.skill"},
		{"V1 unknown interface", func(m *Manifest) { m.Runtime.Interfaces = []string{"vscode"} }, "V1", SeverityError, "runtime.interfaces[0]"},
		{"V1 bad dependency ref", func(m *Manifest) {
			m.Dependencies.Agents = []AgentDependency{{Ref: "no-slash"}}
		}, "V1", SeverityError, "dependencies.agents[0].ref"},
		{"V1 bad dependency constraint", func(m *Manifest) {
			m.Dependencies.Agents = []AgentDependency{{Ref: "acme/other", Version: "not-a-range"}}
		}, "V1", SeverityError, "dependencies.agents[0].version"},
		{"V1 unknown channel", func(m *Manifest) { m.Publish.Channel = "nightly" }, "V1", SeverityError, "publish.channel"},

		{"V3 missing version", func(m *Manifest) { m.Version = "" }, "V3", SeverityError, "version"},
		{"V3 not semver", func(m *Manifest) { m.Version = "1.4" }, "V3", SeverityError, "version"},
		{"V3 leading v rejected", func(m *Manifest) { m.Version = "v1.4.2" }, "V3", SeverityError, "version"},
		{"V3 leading zero rejected", func(m *Manifest) { m.Version = "01.2.3" }, "V3", SeverityError, "version"},

		{"V4 empty include", func(m *Manifest) { m.Publish.Include = nil }, "V4", SeverityError, "publish.include"},
		{"V4 absolute pattern", func(m *Manifest) { m.Publish.Include = []string{"/etc/**"} }, "V4", SeverityError, "publish.include[0]"},
		{"V4 dotdot pattern", func(m *Manifest) { m.Publish.Include = []string{"../secrets/**"} }, "V4", SeverityError, "publish.include[0]"},
		{"V4 dot segment pattern", func(m *Manifest) { m.Publish.Include = []string{"./agent.yaml"} }, "V4", SeverityError, "publish.include[0]"},
		{"V4 bad glob syntax", func(m *Manifest) { m.Publish.Include = []string{"docs/[a-"} }, "V4", SeverityError, "publish.include[0]"},
		{"V4 trailing backslash", func(m *Manifest) { m.Publish.Include = []string{`docs\`} }, "V4", SeverityError, "publish.include[0]"},

		{"V5 bad host", func(m *Manifest) {
			m.Capabilities.Network.Egress = Egress{Hosts: []string{"https://api.example.com"}}
		}, "V5", SeverityError, "egress[0]"},
		{"V5 host label too long", func(m *Manifest) {
			m.Capabilities.Network.Egress = Egress{Hosts: []string{strings.Repeat("a", 64) + ".example.com"}}
		}, "V5", SeverityError, "egress[0]"},
		{"V5 host edge hyphen", func(m *Manifest) {
			m.Capabilities.Network.Egress = Egress{Hosts: []string{"-bad.example.com"}}
		}, "V5", SeverityError, "egress[0]"},
		{"V5 partial wildcard host", func(m *Manifest) {
			m.Capabilities.Network.Egress = Egress{Hosts: []string{"*.example.com"}}
		}, "V5", SeverityError, "egress[0]"},
		{"V5 none inside list", func(m *Manifest) {
			m.Capabilities.Network.Egress = Egress{Hosts: []string{"none"}}
		}, "V5", SeverityError, "egress[0]"},
		{"V5 star egress flagged", func(m *Manifest) {
			m.Capabilities.Network.Egress = Egress{Hosts: []string{"*"}}
		}, "V5", SeverityWarning, "egress[0]"},
		{"V5 none and hosts", func(m *Manifest) {
			m.Capabilities.Network.Egress = Egress{None: true, Hosts: []string{"a.example"}}
		}, "V5", SeverityError, "egress"},
		{"V5 fs unknown mode", func(m *Manifest) {
			m.Capabilities.Filesystem.Read = FSAccess{Mode: "everything"}
		}, "V5", SeverityError, "filesystem.read"},
		{"V5 fs empty paths", func(m *Manifest) {
			m.Capabilities.Filesystem.Read = FSAccess{Mode: FSModePaths, Paths: []string{}}
		}, "V5", SeverityError, "filesystem.read.paths"},
		{"V5 fs path escape", func(m *Manifest) {
			m.Capabilities.Filesystem.Read = FSAccess{Mode: FSModePaths, Paths: []string{"../../etc/passwd"}}
		}, "V5", SeverityError, "filesystem.read.paths[0]"},
		{"V5 exec none and commands", func(m *Manifest) {
			m.Capabilities.Exec = ExecCapability{None: true, Commands: []string{"git"}}
		}, "V5", SeverityError, "exec"},
		{"V5 exec empty commands", func(m *Manifest) {
			m.Capabilities.Exec = ExecCapability{Commands: []string{}}
		}, "V5", SeverityError, "exec.commands"},
		{"V5 exec command with space", func(m *Manifest) {
			m.Capabilities.Exec = ExecCapability{Commands: []string{"rm -rf"}}
		}, "V5", SeverityError, "exec.commands[0]"},
		{"V5 bad secret name", func(m *Manifest) {
			m.Capabilities.Secrets = []string{"my-token"}
		}, "V5", SeverityError, "secrets[0]"},
		{"V5 unknown dataAccess", func(m *Manifest) {
			m.Capabilities.DataAccess = []DataAccess{"browsing"}
		}, "V5", SeverityError, "dataAccess[0]"},

		{"V6 mcp missing entrypoint", func(m *Manifest) {
			m.Kind = KindMCPServer
			m.Entrypoints = Entrypoints{}
		}, "V6", SeverityError, "entrypoints.mcp"},
		{"V6 mcp missing command", func(m *Manifest) {
			m.Kind = KindMCPServer
			m.Entrypoints = Entrypoints{MCP: &MCPEntrypoint{Transport: TransportStdio}}
		}, "V6", SeverityError, "entrypoints.mcp.command"},
		{"V6 mcp missing transport", func(m *Manifest) {
			m.Kind = KindMCPServer
			m.Entrypoints = Entrypoints{MCP: &MCPEntrypoint{Command: "node"}}
		}, "V6", SeverityError, "entrypoints.mcp.transport"},
		{"V6 mcp unknown transport", func(m *Manifest) {
			m.Kind = KindMCPServer
			m.Entrypoints = Entrypoints{MCP: &MCPEntrypoint{Command: "node", Transport: "websocket"}}
		}, "V6", SeverityError, "entrypoints.mcp.transport"},
		{"V6 mcp empty arg", func(m *Manifest) {
			m.Kind = KindMCPServer
			m.Entrypoints = Entrypoints{MCP: &MCPEntrypoint{Command: "node", Args: []string{""}, Transport: TransportStdio}}
		}, "V6", SeverityError, "entrypoints.mcp.args[0]"},

		{"V8 summary too long", func(m *Manifest) { m.Summary = strings.Repeat("x", 141) }, "V8", SeverityError, "summary"},
		{"V8 summary control chars", func(m *Manifest) { m.Summary = "line one\nline two" }, "V8", SeverityError, "summary"},
		{"V8 too many tags", func(m *Manifest) {
			m.Tags = []string{"t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7", "t8", "t9", "t10"}
		}, "V8", SeverityError, "tags"},
		{"V8 bad tag", func(m *Manifest) { m.Tags = []string{"Über_tag"} }, "V8", SeverityError, "tags[0]"},
		{"V8 duplicate tag", func(m *Manifest) { m.Tags = []string{"dup", "dup"} }, "V8", SeverityError, "tags[1]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := validSkillManifest()
			tc.mutate(m)
			wantIssue(t, Validate(m), tc.rule, tc.sev, tc.pathSub)
		})
	}
}

// TestValidateStaticPasses exercises boundary values that must remain
// valid.
func TestValidateStaticPasses(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Manifest)
	}{
		{"normative example", func(*Manifest) {}},
		{"summary exactly 140 runes", func(m *Manifest) { m.Summary = strings.Repeat("é", 140) }},
		{"exactly 10 tags", func(m *Manifest) {
			m.Tags = []string{"t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7", "t8", "t9"}
		}},
		{"name at max length", func(m *Manifest) { m.Name = strings.Repeat("a", 65) }},
		{"namespace at max length", func(m *Manifest) { m.Namespace = strings.Repeat("a", 39) }},
		{"prerelease version", func(m *Manifest) { m.Version = "2.0.0-beta.1" }},
		{"prompt-agent without entrypoints", func(m *Manifest) {
			m.Kind = KindPromptAgent
			m.Entrypoints = Entrypoints{}
		}},
		{"prompt-agent with skill entrypoint", func(m *Manifest) { m.Kind = KindPromptAgent }},
		{"empty channel means stable", func(m *Manifest) { m.Publish.Channel = "" }},
		{"dependency with constraint", func(m *Manifest) {
			m.Dependencies.Agents = []AgentDependency{{Ref: "acme/other-agent", Version: "^1.2"}}
		}},
		{"egress none", func(m *Manifest) { m.Capabilities.Network.Egress = Egress{None: true} }},
		{"empty capabilities is pure text", func(m *Manifest) { m.Capabilities = Capabilities{} }},
		{"fs paths form", func(m *Manifest) {
			m.Capabilities.Filesystem.Read = FSAccess{Mode: FSModePaths, Paths: []string{"data/cache.json"}}
		}},
		{"exec commands form", func(m *Manifest) {
			m.Capabilities.Exec = ExecCapability{Commands: []string{"git", "jq"}}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := validSkillManifest()
			tc.mutate(m)
			wantClean(t, Validate(m))
		})
	}
}

// TestValidateInContext covers the context rules V2, V3, V4, V6, V7, V8.
func TestValidateInContext(t *testing.T) {
	cases := []struct {
		name    string
		mutateM func(*Manifest)
		mutateC func(*Context)
		rule    string
		sev     Severity
		pathSub string
	}{
		{"V2 namespace mismatch", nil, func(c *Context) { c.Namespace = "other" }, "V2", SeverityError, "namespace"},
		{"V2 name mismatch", nil, func(c *Context) { c.Name = "other-agent" }, "V2", SeverityError, "name"},

		{"V3 tag mismatch", nil, func(c *Context) { c.TagVersion = "v1.4.3" }, "V3", SeverityError, "version"},
		{"V3 duplicate on own channel", nil, func(c *Context) {
			c.ExistingVersions[ChannelStable] = append(c.ExistingVersions[ChannelStable], "1.4.2")
		}, "V3", SeverityError, "version"},
		{"V3 duplicate on other channel", nil, func(c *Context) {
			c.ExistingVersions[ChannelBeta] = []string{"1.4.2"}
		}, "V3", SeverityError, "version"},
		{"V3 not greater than existing", nil, func(c *Context) {
			c.ExistingVersions[ChannelStable] = append(c.ExistingVersions[ChannelStable], "2.0.0")
		}, "V3", SeverityError, "version"},
		{"V3 corrupt existing version", nil, func(c *Context) {
			c.ExistingVersions[ChannelStable] = []string{"not.semver"}
		}, "V3", SeverityError, "version"},

		{"V4 zero resolved files", func(m *Manifest) {
			m.Publish.Include = []string{"nonexistent/**"}
		}, nil, "V4", SeverityError, "publish.include"},
		{"V4 skill entrypoint not in repo", nil, func(c *Context) {
			c.Files = deleteFile(c.Files, "SKILL.md")
		}, "V4", SeverityError, "entrypoints"},
		{"V4 skill entrypoint not included", func(m *Manifest) {
			m.Publish.Include = []string{"agent.yaml", "README.md", "prompts/**", "LICENSE"}
		}, nil, "V4", SeverityError, "publish.include"},
		{"V4 symlink in resolved set", nil, func(c *Context) {
			c.Files = append(c.Files, FileInfo{Path: "prompts/link.md", Size: 10, Symlink: true})
		}, "V4", SeverityError, "publish.include"},
		{"V4 traversal file matched by glob", nil, func(c *Context) {
			c.Files = append(c.Files, FileInfo{Path: "prompts/../../etc/passwd", Size: 10})
		}, "V4", SeverityError, "publish.include"},
		{"V4 absolute file matched by glob", func(m *Manifest) {
			m.Publish.Include = append(m.Publish.Include, "**")
		}, func(c *Context) {
			c.Files = append(c.Files, FileInfo{Path: "/etc/passwd", Size: 10})
		}, "V4", SeverityError, "publish.include"},

		{"V7 missing license field", func(m *Manifest) { m.License = "" }, nil, "V7", SeverityError, "license"},
		{"V7 unknown SPDX id", func(m *Manifest) { m.License = "Apache 2.0" }, nil, "V7", SeverityError, "license"},
		{"V7 missing LICENSE file", nil, func(c *Context) {
			c.Files = deleteFile(c.Files, "LICENSE")
		}, "V7", SeverityError, ""},
		{"V7 missing README", nil, func(c *Context) {
			c.Files = deleteFile(c.Files, "README.md")
		}, "V7", SeverityError, ""},

		{"V8 archive too large", nil, func(c *Context) {
			for i := range c.Files {
				if c.Files[i].Path == "SKILL.md" {
					c.Files[i].Size = 11 << 20
				}
			}
			// keep per-file under a raised limit so only the total trips
			q := DefaultQuotas()
			q.MaxFileBytes = 20 << 20
			c.Quotas = &q
		}, "V8", SeverityError, "publish.include"},
		{"V8 single file too large", nil, func(c *Context) {
			c.Files = append(c.Files, FileInfo{Path: "prompts/big.md", Size: (2 << 20) + 1})
		}, "V8", SeverityError, "publish.include"},
		{"V8 image over image quota", nil, func(c *Context) {
			c.Files = append(c.Files, FileInfo{Path: "prompts/diagram.png", Size: (5 << 20) + 1})
		}, "V8", SeverityError, "publish.include"},
		{"V8 too many files", nil, func(c *Context) {
			q := DefaultQuotas()
			q.MaxFiles = 4
			c.Quotas = &q
		}, "V8", SeverityError, "publish.include"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := validSkillManifest()
			ctx := skillContext()
			if tc.mutateM != nil {
				tc.mutateM(m)
			}
			if tc.mutateC != nil {
				tc.mutateC(&ctx)
			}
			wantIssue(t, ValidateInContext(m, ctx), tc.rule, tc.sev, tc.pathSub)
		})
	}
}

func deleteFile(files []FileInfo, p string) []FileInfo {
	out := files[:0:0]
	for _, f := range files {
		if f.Path != p {
			out = append(out, f)
		}
	}
	return out
}

// TestValidateInContextPasses exercises context cases that must pass.
func TestValidateInContextPasses(t *testing.T) {
	t.Run("no tag supplied skips tag check", func(t *testing.T) {
		ctx := skillContext()
		ctx.TagVersion = ""
		wantClean(t, ValidateInContext(validSkillManifest(), ctx))
	})
	t.Run("tag without v prefix", func(t *testing.T) {
		ctx := skillContext()
		ctx.TagVersion = "1.4.2"
		wantClean(t, ValidateInContext(validSkillManifest(), ctx))
	})
	t.Run("private publish needs no license", func(t *testing.T) {
		m := validSkillManifest()
		m.License = ""
		ctx := skillContext()
		ctx.Public = false
		ctx.Files = deleteFile(deleteFile(ctx.Files, "LICENSE"), "README.md")
		m.Publish.Include = []string{"agent.yaml", "SKILL.md", "prompts/**"}
		wantClean(t, ValidateInContext(m, ctx))
	})
	t.Run("image between 2MB and 5MB passes", func(t *testing.T) {
		ctx := skillContext()
		ctx.Files = append(ctx.Files, FileInfo{Path: "prompts/diagram.png", Size: 3 << 20})
		wantClean(t, ValidateInContext(validSkillManifest(), ctx))
	})
	t.Run("no existing versions", func(t *testing.T) {
		ctx := skillContext()
		ctx.ExistingVersions = nil
		wantClean(t, ValidateInContext(validSkillManifest(), ctx))
	})
}

// TestChannelMonotonicity covers V3's per-channel ordering: each channel
// is monotonic independently, and version strings are globally unique.
func TestChannelMonotonicity(t *testing.T) {
	newBeta := func(version string) (*Manifest, Context) {
		m := validSkillManifest()
		m.Version = version
		m.Publish.Channel = ChannelBeta
		ctx := skillContext()
		ctx.TagVersion = "v" + version
		ctx.ExistingVersions = map[Channel][]string{
			ChannelStable: {"1.4.1"},
			ChannelBeta:   {"1.5.0-beta.1"},
		}
		return m, ctx
	}

	t.Run("beta advances past beta", func(t *testing.T) {
		m, ctx := newBeta("1.5.0-beta.2")
		wantClean(t, ValidateInContext(m, ctx))
	})
	t.Run("beta below stable head is allowed", func(t *testing.T) {
		// 1.4.5 < nothing on beta? It is greater than 1.5.0-beta.1? No:
		// 1.4.5 < 1.5.0-beta.1, so pick a version between channels that
		// only violates its own channel to prove independence.
		m, ctx := newBeta("1.6.0-beta.1")
		ctx.ExistingVersions[ChannelStable] = []string{"9.9.9"}
		wantClean(t, ValidateInContext(m, ctx)) // stable 9.9.9 does not gate beta
	})
	t.Run("beta must exceed beta", func(t *testing.T) {
		m, ctx := newBeta("1.5.0-alpha.1")
		wantIssue(t, ValidateInContext(m, ctx), "V3", SeverityError, "version")
	})
	t.Run("same string on other channel is immutable", func(t *testing.T) {
		m, ctx := newBeta("1.4.1")
		wantIssue(t, ValidateInContext(m, ctx), "V3", SeverityError, "version")
	})
	t.Run("build metadata does not evade immutability", func(t *testing.T) {
		m, ctx := newBeta("1.5.0-beta.1+build.7")
		wantIssue(t, ValidateInContext(m, ctx), "V3", SeverityError, "version")
	})
}

// TestLockfileRule covers V6's context half.
func TestLockfileRule(t *testing.T) {
	t.Run("missing lockfile", func(t *testing.T) {
		ctx := mcpContext()
		ctx.Files = deleteFile(ctx.Files, "package-lock.json")
		wantIssue(t, ValidateInContext(validMCPManifest(), ctx), "V6", SeverityError, "")
	})
	t.Run("uv.lock accepted", func(t *testing.T) {
		m := validMCPManifest()
		m.Publish.Include = []string{"agent.yaml", "README.md", "src/**", "uv.lock", "LICENSE"}
		ctx := mcpContext()
		ctx.Files = deleteFile(ctx.Files, "package-lock.json")
		ctx.Files = append(ctx.Files, FileInfo{Path: "uv.lock", Size: 900})
		wantClean(t, ValidateInContext(m, ctx))
	})
	t.Run("requirements.txt flagged for hashes", func(t *testing.T) {
		m := validMCPManifest()
		m.Publish.Include = []string{"agent.yaml", "README.md", "src/**", "requirements.txt", "LICENSE"}
		ctx := mcpContext()
		ctx.Files = deleteFile(ctx.Files, "package-lock.json")
		ctx.Files = append(ctx.Files, FileInfo{Path: "requirements.txt", Size: 300})
		errs := ValidateInContext(m, ctx)
		wantIssue(t, errs, "V6", SeverityWarning, "")
		if got := Blocking(errs); len(got) != 0 {
			t.Fatalf("hash note must be a warning, got blocking:%s", issueStrings(got))
		}
	})
	t.Run("lockfile excluded from archive warns", func(t *testing.T) {
		m := validMCPManifest()
		m.Publish.Include = []string{"agent.yaml", "README.md", "src/**", "LICENSE"}
		errs := ValidateInContext(m, mcpContext())
		wantIssue(t, errs, "V6", SeverityWarning, "publish.include")
	})
	t.Run("lockfile rule only applies to mcp-server", func(t *testing.T) {
		wantClean(t, ValidateInContext(validSkillManifest(), skillContext())) // no lockfile in files
	})
}

// TestWarningsAreDistinguishable proves the V5 "*" egress flag is a typed,
// non-blocking warning the caller can separate from errors.
func TestWarningsAreDistinguishable(t *testing.T) {
	m := validSkillManifest()
	m.Capabilities.Network.Egress = Egress{Hosts: []string{"*"}}
	errs := ValidateInContext(m, skillContext())
	if len(errs) != 1 {
		t.Fatalf("expected exactly the wildcard warning, got:%s", issueStrings(errs))
	}
	if !IsWarning(errs[0]) {
		t.Fatalf("expected a warning, got: %v", errs[0])
	}
	issue, ok := AsIssue(errs[0])
	if !ok || issue.Rule != "V5" || issue.Severity != SeverityWarning {
		t.Fatalf("wrong issue: %+v", issue)
	}
	if !strings.Contains(issue.Error(), "(warning)") {
		t.Errorf("Error() should mark warnings: %q", issue.Error())
	}
	if got := Blocking(errs); len(got) != 0 {
		t.Fatalf("warnings must not block: %s", issueStrings(got))
	}
}

// TestAgentYAMLInclusionWarning: an archive without agent.yaml is legal
// but flagged.
func TestAgentYAMLInclusionWarning(t *testing.T) {
	m := validSkillManifest()
	m.Publish.Include = []string{"README.md", "SKILL.md", "prompts/**", "LICENSE"}
	errs := ValidateInContext(m, skillContext())
	wantIssue(t, errs, "V4", SeverityWarning, "publish.include")
	if got := Blocking(errs); len(got) != 0 {
		t.Fatalf("expected only the warning:%s", issueStrings(got))
	}
}

func TestValidateNilManifest(t *testing.T) {
	wantIssue(t, Validate(nil), "V1", SeverityError, "")
	wantIssue(t, ValidateInContext(nil, Context{}), "V1", SeverityError, "")
}

func TestValidNameAndNamespace(t *testing.T) {
	cases := []struct {
		s         string
		name, ns  bool
		checkName string
	}{
		{"a", true, true, "single char"},
		{"incident-summarizer", true, true, "hyphenated"},
		{"a-", false, false, "trailing hyphen"},
		{"-a", false, false, "leading hyphen"},
		{"A", false, false, "uppercase"},
		{"a_b", false, false, "underscore"},
		{"", false, false, "empty"},
		{strings.Repeat("a", 39), true, true, "39 chars"},
		{strings.Repeat("a", 40), true, false, "40 chars fits name only"},
		{strings.Repeat("a", 65), true, false, "65 chars fits name only"},
		{strings.Repeat("a", 66), false, false, "66 chars fits neither"},
	}
	for _, tc := range cases {
		if got := ValidName(tc.s); got != tc.name {
			t.Errorf("ValidName(%s) = %v, want %v", tc.checkName, got, tc.name)
		}
		if got := ValidNamespace(tc.s); got != tc.ns {
			t.Errorf("ValidNamespace(%s) = %v, want %v", tc.checkName, got, tc.ns)
		}
	}
}

func TestKnownSPDXID(t *testing.T) {
	if got, ok := KnownSPDXID("apache-2.0"); !ok || got != "Apache-2.0" {
		t.Errorf("case-insensitive lookup failed: %q %v", got, ok)
	}
	if _, ok := KnownSPDXID("Proprietary-EULA"); ok {
		t.Errorf("unknown id must not be accepted")
	}
}
