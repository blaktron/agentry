// Package manifest implements the agent.yaml package manifest defined in
// PLAN §5: strict parsing (closed schema, rule V1), the validation rules
// V1–V10 (§5.3), the closed capability vocabulary (§5.4), and the canonical
// JSON form stored as agent_versions.manifest (§4.2).
//
// Two schema majors are read. Major 2 (DEV-088) classifies a BriefAgent by
// the run modes it supports — autonomous, interactive — and names one
// instruction entrypoint. Major 1 classified by kind (skill, prompt-agent,
// mcp-server) and is kept readable for the archives already published under
// it: SupportedModes and InstructionCandidates answer the v2 questions for
// either major, so callers need not branch on the version. A v1 document
// can still be validated for publish, except that kind mcp-server is
// withdrawn and refused.
//
// The API splits validation by what it needs:
//
//   - Parse decodes one YAML 1.2 document with unknown keys rejected
//     everywhere and the schemaVersion major checked.
//   - Validate applies every rule that needs only the manifest itself.
//   - ValidateInContext applies Validate plus the rules that need
//     server-supplied context (V2, V3, V4, V6, V7, V8, V9): repo identity, git
//     tag, existing versions, visibility, and the candidate file listing.
//
// Validation results are []error whose elements are *Issue values carrying
// the rule id, a manifest path, and a severity. Warnings (for example the
// policy-gated "*" egress of V5) are distinguishable via IsWarning and are
// not blocking; Blocking filters them out.
package manifest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"
)

// Mode is a run mode a release supports (DEV-088, plan §2). A release
// declares the non-empty set it supports; a run happens in exactly one.
type Mode string

// Run modes (closed set).
const (
	// ModeAutonomous runs from the source files (optionally after intake
	// questions and MCP profile authentication), writes its output and
	// receipts, and ends.
	ModeAutonomous Mode = "autonomous"
	// ModeInteractive starts from the same plan and controls, but the run is
	// a conversation with the user in the CLI TUI or the desktop.
	ModeInteractive Mode = "interactive"
)

// Valid reports whether m is a known mode.
func (m Mode) Valid() bool {
	switch m {
	case ModeAutonomous, ModeInteractive:
		return true
	}
	return false
}

// The v1 kinds (PLAN §1.4). Read for schema major 1 only; SupportedModes
// maps them. Not exported: no new code should classify by kind.
const (
	v1KindSkill       = "skill"
	v1KindPromptAgent = "prompt-agent"
	v1KindMCPServer   = "mcp-server"
)

// DefaultInstructionFile is the v2 instruction entrypoint when the manifest
// names none.
const DefaultInstructionFile = "AGENT.md"

// v1PromptAgentInstructionFiles is the closed search order the runner used
// for a v1 prompt-agent (RUNNER-PLAN §R2); kept for v1 archives only.
var v1PromptAgentInstructionFiles = []string{"AGENT.md", "PROMPT.md"}

// Channel is a release channel per §5.5.
type Channel string

// Release channels (closed set). An empty channel in the manifest means
// ChannelStable; use Manifest.EffectiveChannel.
const (
	// ChannelStable is the default resolution channel.
	ChannelStable Channel = "stable"
	// ChannelBeta is the opt-in pre-release channel.
	ChannelBeta Channel = "beta"
)

// DataAccess is a semantic data-access category from the closed capability
// vocabulary of §5.2/§5.4.
type DataAccess string

// DataAccess categories (closed set).
const (
	DataAccessEmail    DataAccess = "email"
	DataAccessCalendar DataAccess = "calendar"
	DataAccessFiles    DataAccess = "files"
	DataAccessTickets  DataAccess = "tickets"
	DataAccessCode     DataAccess = "code"
	DataAccessMessages DataAccess = "messages"
	DataAccessPayments DataAccess = "payments"
	DataAccessOther    DataAccess = "other"
)

// Transport is an MCP entrypoint transport (§5.2).
type Transport string

// MCP transports (closed set).
const (
	// TransportStdio runs the server over stdin/stdout.
	TransportStdio Transport = "stdio"
	// TransportHTTP runs the server over HTTP.
	TransportHTTP Transport = "http"
)

// Install-target interface names accepted in runtime.interfaces (§5.6).
const (
	// InterfaceClaudeSkill exports to a Claude skill directory.
	InterfaceClaudeSkill = "claude-skill"
	// InterfaceMCP exports an entry into an MCP client configuration.
	InterfaceMCP = "mcp"
	// InterfaceAgentsMD exports an AGENTS.md section.
	InterfaceAgentsMD = "agents-md"
)

// Manifest is the full agent.yaml document per PLAN §5.2. Field comments
// note the owning validation rules; zero values mean "not declared".
type Manifest struct {
	// SchemaVersion is the manifest schema major ("1" or "2"); unknown
	// majors are rejected at Parse time (V1). Major() reads it.
	SchemaVersion string `yaml:"schemaVersion" json:"schemaVersion"`
	// Name must match the target repo's agent name (V2) and the agents.name
	// DDL pattern (§4.2).
	Name string `yaml:"name" json:"name"`
	// Namespace must match the target repo's namespace handle (V2) and the
	// handles.handle DDL pattern (§4.2).
	Namespace string `yaml:"namespace" json:"namespace"`
	// Kind is the v1 classification (skill | prompt-agent | mcp-server),
	// read for schema major 1 only; a v2 manifest must not carry it (V1).
	// Use SupportedModes rather than reading this.
	Kind string `yaml:"kind,omitempty" json:"kind,omitempty"`
	// Modes is the v2 set of run modes the release supports: required,
	// non-empty, from the closed set, no duplicates (V1). Absent in v1.
	Modes []Mode `yaml:"modes,omitempty" json:"modes,omitempty"`
	// Version is strict semver without a leading "v"; it must equal the git
	// tag and exceed every existing version on its channel (V3).
	Version string `yaml:"version" json:"version"`
	// Summary is a plain-text one-liner, at most MaxSummaryChars runes (V8).
	Summary string `yaml:"summary" json:"summary"`
	// License is an SPDX identifier; required for public publish (V7).
	License string `yaml:"license,omitempty" json:"license,omitempty"`
	// Authors optionally credits the authors.
	Authors []Author `yaml:"authors,omitempty" json:"authors,omitempty"`
	// Homepage is an optional informational URL.
	Homepage string `yaml:"homepage,omitempty" json:"homepage,omitempty"`
	// Tags carries at most MaxTags lowercase [a-z0-9-]+ tags (V8).
	Tags []string `yaml:"tags,omitempty" json:"tags,omitempty"`
	// Entrypoints names the instruction file (v2) or the v1 per-kind
	// entrypoints (§5.2).
	Entrypoints Entrypoints `yaml:"entrypoints,omitempty" json:"entrypoints,omitempty"`
	// Intake lists the questions asked before a run starts, in either mode
	// (v2, V10). Answers are staged read-only for the agent by the runner.
	Intake []IntakeQuestion `yaml:"intake,omitempty" json:"intake,omitempty"`
	// Interactive carries hints for interactive sessions (v2, V10).
	// Everything else about a session is runner policy, not manifest.
	Interactive *InteractiveHints `yaml:"interactive,omitempty" json:"interactive,omitempty"`
	// Guide is what a person reads before a run: what the BriefAgent does,
	// what to gather first, what files to bring, a task placeholder, and
	// help for each declared secret (v2, V10; plan guided-runs.md §6). It is
	// shown to people only: it never reaches the agent, the run plan, the
	// capability diff or the consent.
	Guide *Guide `yaml:"guide,omitempty" json:"guide,omitempty"`
	// Runtime carries informational runtime hints and install targets.
	Runtime Runtime `yaml:"runtime,omitempty" json:"runtime,omitempty"`
	// Capabilities is the security contract (closed vocabulary, V5).
	// The zero value declares a pure-text agent.
	Capabilities Capabilities `yaml:"capabilities,omitempty" json:"capabilities,omitempty"`
	// Dependencies lists informational agent dependencies (v1: no
	// auto-install).
	Dependencies Dependencies `yaml:"dependencies,omitempty" json:"dependencies,omitempty"`
	// Publish controls the release archive allowlist and channel (V4).
	Publish Publish `yaml:"publish" json:"publish"`
}

// EffectiveChannel returns the release channel, defaulting to ChannelStable
// when the manifest omits publish.channel.
func (m *Manifest) EffectiveChannel() Channel {
	if m.Publish.Channel == "" {
		return ChannelStable
	}
	return m.Publish.Channel
}

// Major returns the schema major (1 or 2); 0 when the version is not one
// Parse would accept.
func (m *Manifest) Major() int {
	switch strings.SplitN(m.SchemaVersion, ".", 2)[0] {
	case "1":
		return 1
	case "2":
		return 2
	}
	return 0
}

// SupportedModes returns the run modes the release supports, for either
// schema major: v2 returns Modes; v1 maps skill and prompt-agent to
// autonomous and the withdrawn mcp-server kind to nothing.
func (m *Manifest) SupportedModes() []Mode {
	if m.Major() == 2 {
		return append([]Mode(nil), m.Modes...)
	}
	switch m.Kind {
	case v1KindSkill, v1KindPromptAgent:
		return []Mode{ModeAutonomous}
	}
	return nil
}

// Supports reports whether the release can run in mode.
func (m *Manifest) Supports(mode Mode) bool {
	for _, have := range m.SupportedModes() {
		if have == mode {
			return true
		}
	}
	return false
}

// InstructionCandidates returns the repo-relative files that may hold the
// harness instruction, in the order a caller should try them: exactly one
// for v2 (entrypoints.instruction, else DefaultInstructionFile) and for a
// v1 skill (entrypoints.skill); the closed AGENT.md-then-PROMPT.md order for
// a v1 prompt-agent; nothing for the withdrawn v1 mcp-server kind.
func (m *Manifest) InstructionCandidates() []string {
	if m.Major() == 2 {
		if m.Entrypoints.Instruction != "" {
			return []string{m.Entrypoints.Instruction}
		}
		return []string{DefaultInstructionFile}
	}
	switch m.Kind {
	case v1KindSkill:
		if m.Entrypoints.Skill != "" {
			return []string{m.Entrypoints.Skill}
		}
		return nil
	case v1KindPromptAgent:
		if m.Entrypoints.Skill != "" {
			return []string{m.Entrypoints.Skill}
		}
		return append([]string(nil), v1PromptAgentInstructionFiles...)
	}
	return nil
}

// Author credits one manifest author.
type Author struct {
	// Name is required for each listed author.
	Name string `yaml:"name" json:"name"`
	// Email is optional.
	Email string `yaml:"email,omitempty" json:"email,omitempty"`
}

// Entrypoints names where the instruction lives. A v2 manifest sets only
// Instruction; the other two keys are v1's per-kind entrypoints and are
// refused in v2 (V1).
type Entrypoints struct {
	// Instruction is the repo-relative instruction file (v2); empty means
	// DefaultInstructionFile. A leading YAML frontmatter block is stripped
	// by consumers, so a SKILL.md-shaped file works unchanged.
	Instruction string `yaml:"instruction,omitempty" json:"instruction,omitempty"`
	// Skill is the v1 repo-relative skill file (e.g. SKILL.md).
	Skill string `yaml:"skill,omitempty" json:"skill,omitempty"`
	// MCP is the v1 mcp-server launch spec. Parsed for archives published
	// under the withdrawn kind; never valid for publish.
	MCP *MCPEntrypoint `yaml:"mcp,omitempty" json:"mcp,omitempty"`
}

// IntakeType is the answer shape of an intake question (closed set).
type IntakeType string

// Intake answer types.
const (
	// IntakeText is a free-text answer.
	IntakeText IntakeType = "text"
	// IntakeSecret is a value that must not be echoed or recorded; the
	// runner injects it as a run-scoped secret rather than as text.
	IntakeSecret IntakeType = "secret"
	// IntakeChoice is one of Choices.
	IntakeChoice IntakeType = "choice"
	// IntakeFile is a host path the runner stages into the inputs folder.
	IntakeFile IntakeType = "file"
)

// IntakeQuestion is one question asked before a run starts (plan §3.5).
type IntakeQuestion struct {
	// ID names the answer: [a-z0-9_]+, unique within the manifest (V10).
	ID string `yaml:"id" json:"id"`
	// Prompt is what the user is asked.
	Prompt string `yaml:"prompt" json:"prompt"`
	// Type is the answer shape; text when empty.
	Type IntakeType `yaml:"type,omitempty" json:"type,omitempty"`
	// Required refuses to start the run without an answer.
	Required bool `yaml:"required,omitempty" json:"required,omitempty"`
	// Choices lists the allowed answers for IntakeChoice; forbidden otherwise.
	Choices []string `yaml:"choices,omitempty" json:"choices,omitempty"`
}

// Guide is the author's own words for the run setup (plan guided-runs.md
// §6): clients show them before a run and derive the same steps from the
// rest of the manifest when a release carries none.
type Guide struct {
	// Overview says what the BriefAgent does and returns, in markdown.
	Overview string `yaml:"overview,omitempty" json:"overview,omitempty"`
	// Prepare lists what to gather before starting, one line each.
	Prepare []string `yaml:"prepare,omitempty" json:"prepare,omitempty"`
	// Files says what files to bring to the run, in one line.
	Files string `yaml:"files,omitempty" json:"files,omitempty"`
	// Task is the placeholder for the task field.
	Task string `yaml:"task,omitempty" json:"task,omitempty"`
	// Connect is help per declared secret name: where to create the key,
	// which scopes it needs. Every key must be a declared secret (V10).
	Connect map[string]string `yaml:"connect,omitempty" json:"connect,omitempty"`
}

// InteractiveHints are the manifest's hints for interactive sessions
// (plan §3.6). Limits here can only tighten what runner policy allows.
type InteractiveHints struct {
	// Opening is the assistant's first message when no task text was given.
	Opening string `yaml:"opening,omitempty" json:"opening,omitempty"`
	// IdleTimeoutSeconds ends the session after this much silence; policy
	// caps it.
	IdleTimeoutSeconds int `yaml:"idleTimeoutSeconds,omitempty" json:"idleTimeoutSeconds,omitempty"`
}

// MCPEntrypoint launches an MCP server (kind=mcp-server, V6).
type MCPEntrypoint struct {
	// Command is the executable to run (e.g. node, python).
	Command string `yaml:"command" json:"command"`
	// Args are the command arguments; args naming repo files must be
	// included in the release archive (V4).
	Args []string `yaml:"args,omitempty" json:"args,omitempty"`
	// Transport is stdio or http.
	Transport Transport `yaml:"transport" json:"transport"`
}

// Runtime carries informational runtime hints (§5.2).
type Runtime struct {
	// Models are free-form model hint patterns (informational).
	Models []string `yaml:"models,omitempty" json:"models,omitempty"`
	// Interfaces lists the install targets §5.6 may emit; each must be one
	// of InterfaceClaudeSkill, InterfaceMCP, InterfaceAgentsMD.
	Interfaces []string `yaml:"interfaces,omitempty" json:"interfaces,omitempty"`
}

// Capabilities is the closed-vocabulary security contract of §5.2/§5.4.
// It is a declaration to consumers and policy, not runtime enforcement.
type Capabilities struct {
	// Network declares network capabilities.
	Network Network `yaml:"network,omitempty" json:"network,omitempty"`
	// Filesystem declares filesystem access.
	Filesystem Filesystem `yaml:"filesystem,omitempty" json:"filesystem,omitempty"`
	// Exec declares subprocess execution.
	Exec ExecCapability `yaml:"exec,omitempty" json:"exec,omitempty"`
	// Secrets lists environment variable NAMES the agent expects — never
	// values.
	Secrets []string `yaml:"secrets,omitempty" json:"secrets,omitempty"`
	// DataAccess lists semantic data categories the agent touches.
	DataAccess []DataAccess `yaml:"dataAccess,omitempty" json:"dataAccess,omitempty"`
	// MCPServers lists the MCP servers this agent requires at run time
	// (RUNNER-PLAN-3). The runner installs each from the operator's trusted
	// repository — npm and PyPI by default — configured for this exact
	// release only, and serves them through the per-run gateway. Versions
	// are EXACT pins (V5): they are part of the release's content, so a new
	// agent version is a new supply-chain decision by construction.
	MCPServers []MCPServer `yaml:"mcpServers,omitempty" json:"mcpServers,omitempty"`
}

// MCPServer is one declared MCP server requirement (§5.4, RUNNER-PLAN-3).
// Exactly one of NPM or PyPI names the package; Version is an exact
// release, never a range.
type MCPServer struct {
	// NPM is the npm package name (optionally @scope/name).
	NPM string `yaml:"npm,omitempty" json:"npm,omitempty"`
	// PyPI is the PyPI project name (PEP-503 normalized form).
	PyPI string `yaml:"pypi,omitempty" json:"pypi,omitempty"`
	// Version is the exact package version to install (V5: no ranges).
	Version string `yaml:"version" json:"version"`
	// Tools optionally restricts the server to these tool names; empty
	// grants the server's full set.
	Tools []string `yaml:"tools,omitempty" json:"tools,omitempty"`
	// Secrets lists environment variable NAMES this server needs — never
	// values. Additive to capabilities.secrets; collected into the same
	// per-signature MCP profile by the runner's guided setup.
	Secrets []string `yaml:"secrets,omitempty" json:"secrets,omitempty"`
	// Egress lists the exact hosts THIS SERVER may reach ("*" allowed,
	// policy-gated at run time like agent egress). Empty means none.
	Egress []string `yaml:"egress,omitempty" json:"egress,omitempty"`
	// Env is plain, non-secret configuration the server reads from its
	// environment (v2, V5, DEV-098). It lives in the manifest so it is in
	// the diff, the digest and the review, never in a policy file; a name
	// that is also a declared secret is refused, so a value is either
	// configuration in the contract or a secret from the profile.
	Env map[string]string `yaml:"env,omitempty" json:"env,omitempty"`
}

// SourceID returns the ecosystem-qualified package id ("npm:@scope/x" or
// "pypi:name") — the duplicate-detection and store key.
func (s MCPServer) SourceID() string {
	if s.NPM != "" {
		return "npm:" + s.NPM
	}
	return "pypi:" + s.PyPI
}

// Network groups network capabilities (currently egress only).
type Network struct {
	// Egress declares outbound network access.
	Egress Egress `yaml:"egress,omitempty" json:"egress,omitempty"`
}

// Egress declares outbound network access: the scalar "none", or a list of
// exact DNS hostnames where the element "*" requests unrestricted egress
// (allowed but flagged for policy evaluation, V5). The scalar "*" is
// accepted and normalized to the single-element list.
type Egress struct {
	// None is true when egress was declared as the scalar "none".
	None bool `json:"-"`
	// Hosts lists exact DNS hostnames; "*" means any host.
	Hosts []string `json:"-"`
}

// IsZero reports whether egress was not declared at all.
func (e Egress) IsZero() bool { return !e.None && e.Hosts == nil }

// UnmarshalYAML implements strict decoding of the egress union shape.
func (e *Egress) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		var s string
		if err := node.Decode(&s); err != nil {
			return fmt.Errorf("network.egress: %w", err)
		}
		switch s {
		case "none":
			*e = Egress{None: true}
			return nil
		case "*":
			*e = Egress{Hosts: []string{"*"}}
			return nil
		default:
			return fmt.Errorf("line %d: network.egress: scalar must be \"none\" or \"*\"; use a list for hosts", node.Line)
		}
	case yaml.SequenceNode:
		var hosts []string
		if err := node.Decode(&hosts); err != nil {
			return fmt.Errorf("network.egress: %w", err)
		}
		*e = Egress{Hosts: hosts}
		return nil
	default:
		return fmt.Errorf("line %d: network.egress must be \"none\" or a list of hosts", node.Line)
	}
}

// MarshalJSON encodes the union back to its canonical shape.
func (e Egress) MarshalJSON() ([]byte, error) {
	switch {
	case e.None:
		return json.Marshal("none")
	case e.Hosts != nil:
		return json.Marshal(e.Hosts)
	default:
		return []byte("null"), nil
	}
}

// UnmarshalJSON decodes the canonical JSON union shape.
func (e *Egress) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		*e = Egress{}
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		switch s {
		case "none":
			*e = Egress{None: true}
			return nil
		case "*":
			*e = Egress{Hosts: []string{"*"}}
			return nil
		default:
			return fmt.Errorf("network.egress: scalar must be %q or %q", "none", "*")
		}
	}
	var hosts []string
	if err := json.Unmarshal(b, &hosts); err != nil {
		return fmt.Errorf("network.egress: %w", err)
	}
	*e = Egress{Hosts: hosts}
	return nil
}

// Filesystem declares filesystem read and write access.
type Filesystem struct {
	// Read declares read access.
	Read FSAccess `yaml:"read,omitempty" json:"read,omitempty"`
	// Write declares write access.
	Write FSAccess `yaml:"write,omitempty" json:"write,omitempty"`
}

// FSMode is the shape of a filesystem access declaration.
type FSMode string

// Filesystem access modes (closed set). The empty mode means "not
// declared".
const (
	// FSModeNone declares no access.
	FSModeNone FSMode = "none"
	// FSModeWorkspace declares access limited to the consumer workspace.
	FSModeWorkspace FSMode = "workspace"
	// FSModePaths declares access to an explicit path list.
	FSModePaths FSMode = "paths"
)

// FSAccess declares one direction of filesystem access: the scalar "none"
// or "workspace", or a mapping {paths: [...]} of repo-relative paths.
type FSAccess struct {
	// Mode is the declared shape; empty means not declared.
	Mode FSMode `json:"-"`
	// Paths is set only for FSModePaths.
	Paths []string `json:"-"`
}

// IsZero reports whether the access was not declared at all.
func (a FSAccess) IsZero() bool { return a.Mode == "" && a.Paths == nil }

// UnmarshalYAML implements strict decoding of the filesystem union shape.
func (a *FSAccess) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		var s string
		if err := node.Decode(&s); err != nil {
			return fmt.Errorf("filesystem access: %w", err)
		}
		switch s {
		case "none":
			*a = FSAccess{Mode: FSModeNone}
			return nil
		case "workspace":
			*a = FSAccess{Mode: FSModeWorkspace}
			return nil
		default:
			return fmt.Errorf("line %d: filesystem access must be \"none\", \"workspace\", or {paths: [...]}, got %q", node.Line, s)
		}
	case yaml.MappingNode:
		paths, err := decodeSingleKeyStringList(node, "paths", "filesystem access")
		if err != nil {
			return err
		}
		*a = FSAccess{Mode: FSModePaths, Paths: paths}
		return nil
	default:
		return fmt.Errorf("line %d: filesystem access must be \"none\", \"workspace\", or {paths: [...]}", node.Line)
	}
}

// MarshalJSON encodes the union back to its canonical shape.
func (a FSAccess) MarshalJSON() ([]byte, error) {
	switch a.Mode {
	case FSModeNone, FSModeWorkspace:
		return json.Marshal(string(a.Mode))
	case FSModePaths:
		return json.Marshal(map[string][]string{"paths": a.Paths})
	default:
		return []byte("null"), nil
	}
}

// UnmarshalJSON decodes the canonical JSON union shape.
func (a *FSAccess) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		*a = FSAccess{}
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		switch s {
		case "none":
			*a = FSAccess{Mode: FSModeNone}
			return nil
		case "workspace":
			*a = FSAccess{Mode: FSModeWorkspace}
			return nil
		default:
			return fmt.Errorf("filesystem access: unknown mode %q", s)
		}
	}
	var obj struct {
		Paths []string `json:"paths"`
	}
	if err := strictJSONUnmarshal(b, &obj); err != nil {
		return fmt.Errorf("filesystem access: %w", err)
	}
	*a = FSAccess{Mode: FSModePaths, Paths: obj.Paths}
	return nil
}

// ExecCapability declares subprocess execution: the scalar "none" or a
// mapping {commands: [...]} of command names.
type ExecCapability struct {
	// None is true when exec was declared as the scalar "none".
	None bool `json:"-"`
	// Commands lists the allowed commands; set only for the commands form.
	Commands []string `json:"-"`
}

// IsZero reports whether exec was not declared at all.
func (x ExecCapability) IsZero() bool { return !x.None && x.Commands == nil }

// UnmarshalYAML implements strict decoding of the exec union shape.
func (x *ExecCapability) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		var s string
		if err := node.Decode(&s); err != nil {
			return fmt.Errorf("exec: %w", err)
		}
		if s == "none" {
			*x = ExecCapability{None: true}
			return nil
		}
		return fmt.Errorf("line %d: exec must be \"none\" or {commands: [...]}, got %q", node.Line, s)
	case yaml.MappingNode:
		commands, err := decodeSingleKeyStringList(node, "commands", "exec")
		if err != nil {
			return err
		}
		*x = ExecCapability{Commands: commands}
		return nil
	default:
		return fmt.Errorf("line %d: exec must be \"none\" or {commands: [...]}", node.Line)
	}
}

// MarshalJSON encodes the union back to its canonical shape.
func (x ExecCapability) MarshalJSON() ([]byte, error) {
	switch {
	case x.None:
		return json.Marshal("none")
	case x.Commands != nil:
		return json.Marshal(map[string][]string{"commands": x.Commands})
	default:
		return []byte("null"), nil
	}
}

// UnmarshalJSON decodes the canonical JSON union shape.
func (x *ExecCapability) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		*x = ExecCapability{}
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		if s == "none" {
			*x = ExecCapability{None: true}
			return nil
		}
		return fmt.Errorf("exec: unknown mode %q", s)
	}
	var obj struct {
		Commands []string `json:"commands"`
	}
	if err := strictJSONUnmarshal(b, &obj); err != nil {
		return fmt.Errorf("exec: %w", err)
	}
	*x = ExecCapability{Commands: obj.Commands}
	return nil
}

// Dependencies lists informational dependencies (v1: no auto-install).
type Dependencies struct {
	// Agents lists depended-on agents.
	Agents []AgentDependency `yaml:"agents,omitempty" json:"agents,omitempty"`
}

// AgentDependency references another agent by namespace/name plus an
// optional semver constraint.
type AgentDependency struct {
	// Ref is "namespace/name".
	Ref string `yaml:"ref" json:"ref"`
	// Version is a semver constraint (e.g. "^1.2"); empty means any.
	Version string `yaml:"version,omitempty" json:"version,omitempty"`
}

// Publish controls what enters the release archive and on which channel.
type Publish struct {
	// Include is the archive ALLOWLIST of glob patterns; the archive
	// contains nothing else. Segments use path.Match syntax and the whole
	// segment "**" matches any number of segments (V4).
	Include []string `yaml:"include" json:"include"`
	// Channel is stable or beta; empty means stable.
	Channel Channel `yaml:"channel,omitempty" json:"channel,omitempty"`
}

// Parse decodes exactly one agent.yaml document (YAML 1.2 via yaml.v3).
// Unknown keys anywhere are errors (closed schema, V1), trailing YAML
// documents are rejected, and only schemaVersion majors "1" and "2" are
// accepted.
// Field-level rules live in Validate and ValidateInContext.
func Parse(data []byte) (*Manifest, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("manifest: empty document")
		}
		return nil, fmt.Errorf("manifest: parsing agent.yaml: %w", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("manifest: agent.yaml must contain exactly one YAML document")
	}
	if err := checkSchemaVersion(m.SchemaVersion); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	return &m, nil
}

// checkSchemaVersion accepts majors "1" and "2" with an optional dotted
// numeric suffix (e.g. "2", "1.0").
func checkSchemaVersion(v string) error {
	if v == "" {
		return errors.New("schemaVersion is required")
	}
	parts := strings.Split(v, ".")
	if parts[0] != "1" && parts[0] != "2" {
		return fmt.Errorf("unsupported schemaVersion %q: majors \"1\" and \"2\" are supported", v)
	}
	for _, p := range parts[1:] {
		if p == "" || strings.TrimLeft(p, "0123456789") != "" {
			return fmt.Errorf("invalid schemaVersion %q", v)
		}
	}
	return nil
}

// decodeSingleKeyStringList decodes a YAML mapping that must contain
// exactly the one known key, whose value is a list of strings.
func decodeSingleKeyStringList(node *yaml.Node, key, what string) ([]string, error) {
	var out []string
	seen := false
	for i := 0; i+1 < len(node.Content); i += 2 {
		k, v := node.Content[i], node.Content[i+1]
		if k.Value != key {
			return nil, fmt.Errorf("line %d: %s: unknown key %q (only %q is allowed)", k.Line, what, k.Value, key)
		}
		if seen {
			return nil, fmt.Errorf("line %d: %s: duplicate key %q", k.Line, what, key)
		}
		seen = true
		if err := v.Decode(&out); err != nil {
			return nil, fmt.Errorf("%s.%s: %w", what, key, err)
		}
	}
	if !seen {
		return nil, fmt.Errorf("line %d: %s: mapping must contain %q", node.Line, what, key)
	}
	if out == nil {
		out = []string{}
	}
	return out, nil
}

// strictJSONUnmarshal decodes JSON with unknown fields rejected.
func strictJSONUnmarshal(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	return nil
}
