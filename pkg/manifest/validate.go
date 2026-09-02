package manifest

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Masterminds/semver/v3"
)

// Fixed spec limits from PLAN §5.2/§19 that are part of the manifest
// grammar itself (not raisable per-org entitlements).
const (
	// MaxSummaryChars caps summary length in Unicode code points (V8).
	MaxSummaryChars = 140
	// MaxTags caps the number of tags (V8).
	MaxTags = 10
)

// Severity classifies a validation Issue.
type Severity int

// Issue severities.
const (
	// SeverityError blocks publication.
	SeverityError Severity = iota
	// SeverityWarning is surfaced (and may be policy-gated, e.g. "*"
	// egress) but does not by itself block publication.
	SeverityWarning
)

// String returns "error" or "warning".
func (s Severity) String() string {
	if s == SeverityWarning {
		return "warning"
	}
	return "error"
}

// Issue is one validation finding. All errors returned by Validate and
// ValidateInContext are *Issue values.
type Issue struct {
	// Rule is the §5.3 rule id, "V1" through "V9".
	Rule string
	// Severity distinguishes blocking errors from flags such as the
	// policy-gated "*" egress.
	Severity Severity
	// Path locates the finding in the manifest (e.g.
	// "capabilities.network.egress[0]"); empty for whole-manifest issues.
	Path string
	// Message is the human-readable description.
	Message string
}

// Error implements the error interface.
func (i *Issue) Error() string {
	var b strings.Builder
	b.WriteString("manifest ")
	b.WriteString(i.Rule)
	if i.Severity == SeverityWarning {
		b.WriteString(" (warning)")
	}
	b.WriteString(": ")
	if i.Path != "" {
		b.WriteString(i.Path)
		b.WriteString(": ")
	}
	b.WriteString(i.Message)
	return b.String()
}

// AsIssue unwraps err into an *Issue when possible.
func AsIssue(err error) (*Issue, bool) {
	var i *Issue
	if errors.As(err, &i) {
		return i, true
	}
	return nil, false
}

// IsWarning reports whether err is a SeverityWarning Issue.
func IsWarning(err error) bool {
	i, ok := AsIssue(err)
	return ok && i.Severity == SeverityWarning
}

// Blocking filters errs down to the issues that block publication
// (everything that is not a warning).
func Blocking(errs []error) []error {
	var out []error
	for _, err := range errs {
		if !IsWarning(err) {
			out = append(out, err)
		}
	}
	return out
}

// Name and namespace patterns exactly as the §4.2 DDL CHECK constraints.
var (
	nameRE      = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,63}[a-z0-9])?$`)
	namespaceRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?$`)
	tagRE       = regexp.MustCompile(`^[a-z0-9-]+$`)
	envNameRE   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

// ValidName reports whether s is a valid agent name per the §4.2 DDL
// pattern (lowercase alphanumeric plus interior hyphens, at most 65 chars).
func ValidName(s string) bool { return nameRE.MatchString(s) }

// ValidNamespace reports whether s is a valid namespace handle per the
// §4.2 DDL pattern (at most 39 chars).
func ValidNamespace(s string) bool { return namespaceRE.MatchString(s) }

// Quotas are the §19 archive quotas checked by V8. The zero value is not
// meaningful; use DefaultQuotas and override fields per org entitlements.
type Quotas struct {
	// MaxArchiveBytes caps the total size of the resolved include set.
	MaxArchiveBytes int64
	// MaxFiles caps the number of files in the resolved include set.
	MaxFiles int
	// MaxFileBytes caps each non-image file.
	MaxFileBytes int64
	// MaxImageFileBytes caps each image file (recognized by extension).
	MaxImageFileBytes int64
}

// DefaultQuotas returns the §19 v1 defaults: 10 MiB archive, 2000 files,
// 2 MiB per file, 5 MiB per image.
func DefaultQuotas() Quotas {
	return Quotas{
		MaxArchiveBytes:   10 << 20,
		MaxFiles:          2000,
		MaxFileBytes:      2 << 20,
		MaxImageFileBytes: 5 << 20,
	}
}

// FileInfo describes one candidate repo file for V4/V6/V7/V8. Paths are
// slash-separated and repo-root-relative (e.g. "prompts/system.md").
type FileInfo struct {
	// Path is the repo-relative, slash-separated file path.
	Path string
	// Size is the file size in bytes.
	Size int64
	// Symlink marks symbolic links, which are rejected in the resolved
	// include set (V4/S1).
	Symlink bool
}

// Context is the server-supplied context for ValidateInContext. Namespace
// and Name identify the repo the submission targets and are always
// required; the other fields default to "not applicable" when zero.
type Context struct {
	// Namespace is the target repo's namespace handle (V2).
	Namespace string
	// Name is the target repo's agent name (V2).
	Name string
	// TagVersion is the git tag being published (with or without the
	// leading "v"); empty skips the tag-equality check (cli-upload source).
	TagVersion string
	// ExistingVersions maps channel to the version strings already
	// published for this agent (V3). The new version must be absent from
	// every channel and greater than every version on its own channel.
	ExistingVersions map[Channel][]string
	// Public marks a public publish, which requires license metadata and
	// LICENSE/README.md files (V7).
	Public bool
	// Files lists the candidate repo files at the submitted commit.
	Files []FileInfo
	// Quotas overrides the §19 defaults (org entitlements); nil uses
	// DefaultQuotas.
	Quotas *Quotas
	// ReadFile returns the content of a repo-relative file at the
	// submitted commit. It feeds V9 (skill frontmatter vs manifest); nil
	// skips that rule, so callers without content access are unaffected.
	ReadFile func(path string) ([]byte, error)
}

// issues collects validation findings.
type issues struct{ list []error }

func (s *issues) errf(rule, p, format string, args ...any) {
	s.list = append(s.list, &Issue{Rule: rule, Severity: SeverityError, Path: p, Message: fmt.Sprintf(format, args...)})
}

func (s *issues) warnf(rule, p, format string, args ...any) {
	s.list = append(s.list, &Issue{Rule: rule, Severity: SeverityWarning, Path: p, Message: fmt.Sprintf(format, args...)})
}

// Validate applies every rule that needs only the manifest itself: the
// closed field grammar of V1, the semver syntax half of V3, the pattern
// shape half of V4, the capability vocabulary of V5 (with the "*" egress
// warning), the entrypoint shape half of V6, and the summary/tag quotas of
// V8. The returned errors are *Issue values; a manifest with only
// SeverityWarning issues is valid.
func Validate(m *Manifest) []error {
	var s issues
	if m == nil {
		s.errf("V1", "", "manifest is nil")
		return s.list
	}

	if err := checkSchemaVersion(m.SchemaVersion); err != nil {
		s.errf("V1", "schemaVersion", "%v", err)
	}
	if m.Name == "" {
		s.errf("V1", "name", "name is required")
	} else if !ValidName(m.Name) {
		s.errf("V1", "name", "%q must match %s", m.Name, nameRE)
	}
	if m.Namespace == "" {
		s.errf("V1", "namespace", "namespace is required")
	} else if !ValidNamespace(m.Namespace) {
		s.errf("V1", "namespace", "%q must match %s", m.Namespace, namespaceRE)
	}
	switch m.Kind {
	case KindSkill, KindPromptAgent, KindMCPServer:
	case "":
		s.errf("V1", "kind", "kind is required")
	default:
		s.errf("V1", "kind", "unknown kind %q (skill | prompt-agent | mcp-server)", m.Kind)
	}

	if m.Version == "" {
		s.errf("V3", "version", "version is required")
	} else if _, err := semver.StrictNewVersion(m.Version); err != nil {
		s.errf("V3", "version", "%q is not strict semver: %v", m.Version, err)
	}

	validateSummary(&s, m.Summary)
	validateTags(&s, m.Tags)

	for i, a := range m.Authors {
		if a.Name == "" {
			s.errf("V1", fmt.Sprintf("authors[%d].name", i), "author name is required")
		}
	}

	validateEntrypoints(&s, m)
	validateRuntime(&s, m.Runtime)
	validateCapabilities(&s, m.Capabilities)
	validateMCPServers(&s, m)
	validateDependencies(&s, m.Dependencies)
	validatePublish(&s, m.Publish)

	return s.list
}

func validateSummary(s *issues, summary string) {
	if summary == "" {
		s.errf("V1", "summary", "summary is required")
		return
	}
	if n := utf8.RuneCountInString(summary); n > MaxSummaryChars {
		s.errf("V8", "summary", "summary is %d characters; the maximum is %d", n, MaxSummaryChars)
	}
	for _, r := range summary {
		if r < 0x20 || r == 0x7f {
			s.errf("V8", "summary", "summary must be plain single-line text (no control characters)")
			break
		}
	}
}

func validateTags(s *issues, tags []string) {
	if len(tags) > MaxTags {
		s.errf("V8", "tags", "%d tags; the maximum is %d", len(tags), MaxTags)
	}
	seen := make(map[string]bool, len(tags))
	for i, tag := range tags {
		if !tagRE.MatchString(tag) {
			s.errf("V8", fmt.Sprintf("tags[%d]", i), "tag %q must match %s", tag, tagRE)
		}
		if seen[tag] {
			s.errf("V8", fmt.Sprintf("tags[%d]", i), "duplicate tag %q", tag)
		}
		seen[tag] = true
	}
}

func validateEntrypoints(s *issues, m *Manifest) {
	ep := m.Entrypoints
	switch m.Kind {
	case KindSkill:
		if ep.Skill == "" {
			s.errf("V1", "entrypoints.skill", "kind skill requires entrypoints.skill")
		}
		if ep.MCP != nil {
			s.errf("V1", "entrypoints.mcp", "kind skill must not declare an mcp entrypoint")
		}
	case KindPromptAgent:
		if ep.MCP != nil {
			s.errf("V1", "entrypoints.mcp", "kind prompt-agent must not declare an mcp entrypoint")
		}
	case KindMCPServer:
		if ep.Skill != "" {
			s.errf("V1", "entrypoints.skill", "kind mcp-server must not declare a skill entrypoint")
		}
		if ep.MCP == nil {
			s.errf("V6", "entrypoints.mcp", "kind mcp-server requires entrypoints.mcp with command, args, and transport")
		}
	}
	if ep.Skill != "" {
		if err := checkRelFilePath(ep.Skill); err != nil {
			s.errf("V1", "entrypoints.skill", "%v", err)
		}
	}
	if ep.MCP != nil {
		if ep.MCP.Command == "" {
			s.errf("V6", "entrypoints.mcp.command", "command is required")
		}
		for i, arg := range ep.MCP.Args {
			if arg == "" {
				s.errf("V6", fmt.Sprintf("entrypoints.mcp.args[%d]", i), "argument must not be empty")
			}
		}
		switch ep.MCP.Transport {
		case TransportStdio, TransportHTTP:
		case "":
			s.errf("V6", "entrypoints.mcp.transport", "transport is required (stdio | http)")
		default:
			s.errf("V6", "entrypoints.mcp.transport", "unknown transport %q (stdio | http)", ep.MCP.Transport)
		}
	}
}

func validateRuntime(s *issues, r Runtime) {
	for i, iface := range r.Interfaces {
		switch iface {
		case InterfaceClaudeSkill, InterfaceMCP, InterfaceAgentsMD:
		default:
			s.errf("V1", fmt.Sprintf("runtime.interfaces[%d]", i),
				"unknown interface %q (claude-skill | mcp | agents-md)", iface)
		}
	}
}

func validateCapabilities(s *issues, c Capabilities) {
	eg := c.Network.Egress
	if eg.None && len(eg.Hosts) > 0 {
		s.errf("V5", "capabilities.network.egress", "egress cannot be both \"none\" and a host list")
	}
	wildcardFlagged := false
	for i, h := range eg.Hosts {
		p := fmt.Sprintf("capabilities.network.egress[%d]", i)
		if h == "*" {
			if !wildcardFlagged {
				s.warnf("V5", p, "\"*\" egress requests unrestricted network access and is policy-gated (usually requires review)")
				wildcardFlagged = true
			}
			continue
		}
		if h == "none" {
			s.errf("V5", p, "\"none\" must be the entire egress value, not a list element")
			continue
		}
		if !validDNSHost(h) {
			s.errf("V5", p, "%q is not a valid DNS host name", h)
		}
	}

	validateFSAccess(s, "capabilities.filesystem.read", c.Filesystem.Read)
	validateFSAccess(s, "capabilities.filesystem.write", c.Filesystem.Write)

	ex := c.Exec
	if ex.None && len(ex.Commands) > 0 {
		s.errf("V5", "capabilities.exec", "exec cannot be both \"none\" and a command list")
	}
	if !ex.None && ex.Commands != nil && len(ex.Commands) == 0 {
		s.errf("V5", "capabilities.exec.commands", "commands must list at least one command")
	}
	for i, cmd := range ex.Commands {
		p := fmt.Sprintf("capabilities.exec.commands[%d]", i)
		if cmd == "" {
			s.errf("V5", p, "command must not be empty")
			continue
		}
		for _, r := range cmd {
			if unicode.IsSpace(r) || unicode.IsControl(r) {
				s.errf("V5", p, "command %q must be a single token without whitespace", cmd)
				break
			}
		}
	}

	for i, name := range c.Secrets {
		if !envNameRE.MatchString(name) {
			s.errf("V5", fmt.Sprintf("capabilities.secrets[%d]", i),
				"%q is not a valid environment variable name (%s)", name, envNameRE)
		}
	}

	for i, da := range c.DataAccess {
		switch da {
		case DataAccessEmail, DataAccessCalendar, DataAccessFiles, DataAccessTickets,
			DataAccessCode, DataAccessMessages, DataAccessPayments, DataAccessOther:
		default:
			s.errf("V5", fmt.Sprintf("capabilities.dataAccess[%d]", i),
				"unknown dataAccess category %q (email | calendar | files | tickets | code | messages | payments | other)", da)
		}
	}
}

// MaxMCPServers caps capabilities.mcpServers entries (V5).
const MaxMCPServers = 8

// Package-name grammars. npm: optional @scope/ plus a lowercase name
// (npm forbids uppercase in new packages); PyPI: the PEP-503 normalized
// form — validate/publish require the normalized name so one spelling
// exists per project.
var (
	npmNameRE  = regexp.MustCompile(`^(@[a-z0-9][a-z0-9-_.]*/)?[a-z0-9][a-z0-9-_.]*$`)
	pypiNameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$`)
	// pep440ExactRE accepts an exact PEP-440 release (with optional
	// pre/post/dev segment) and nothing else: no operators, no wildcards,
	// no ranges — the pin IS the trust decision (RUNNER-PLAN-3).
	pep440ExactRE = regexp.MustCompile(`^[0-9]+(\.[0-9]+)*((a|b|rc)[0-9]+)?(\.post[0-9]+)?(\.dev[0-9]+)?$`)
)

// validateMCPServers checks capabilities.mcpServers (V5, RUNNER-PLAN-3):
// exactly one source per entry, ecosystem name grammar, EXACT version pins
// (a range is an error — the pin rides the release archive, so a new agent
// version is a new supply-chain decision by construction), single-token
// tool names, env-grammar secret names, egress host grammar, no
// duplicates, and runnable kinds only.
func validateMCPServers(s *issues, m *Manifest) {
	servers := m.Capabilities.MCPServers
	if len(servers) == 0 {
		return
	}
	if m.Kind == KindMCPServer {
		s.errf("V5", "capabilities.mcpServers",
			"an mcp-server package cannot itself require MCP servers (server composition is not in v1)")
	}
	if len(servers) > MaxMCPServers {
		s.errf("V5", "capabilities.mcpServers", "at most %d MCP servers may be declared (got %d)", MaxMCPServers, len(servers))
	}
	seen := map[string]bool{}
	for i, srv := range servers {
		p := fmt.Sprintf("capabilities.mcpServers[%d]", i)
		switch {
		case srv.NPM != "" && srv.PyPI != "":
			s.errf("V5", p, "declare exactly one of npm or pypi, not both")
			continue
		case srv.NPM == "" && srv.PyPI == "":
			s.errf("V5", p, "declare exactly one of npm or pypi")
			continue
		case srv.NPM != "" && !npmNameRE.MatchString(srv.NPM):
			s.errf("V5", p+".npm", "%q is not a valid npm package name", srv.NPM)
			continue
		case srv.PyPI != "" && !pypiNameRE.MatchString(srv.PyPI):
			s.errf("V5", p+".pypi", "%q is not a PEP-503 normalized PyPI project name (lowercase, dots/dashes/underscores)", srv.PyPI)
			continue
		}
		if id := srv.SourceID(); seen[id] {
			s.errf("V5", p, "duplicate MCP server %q", id)
		} else {
			seen[id] = true
		}

		switch {
		case srv.Version == "":
			s.errf("V5", p+".version", "version is required and must be an exact release (the pin is part of this agent version's content)")
		case srv.NPM != "":
			if _, err := semver.StrictNewVersion(srv.Version); err != nil {
				s.errf("V5", p+".version", "%q is not an exact semver release (ranges are not allowed): %v", srv.Version, err)
			}
		default:
			if !pep440ExactRE.MatchString(srv.Version) {
				s.errf("V5", p+".version", "%q is not an exact PEP-440 release (ranges and wildcards are not allowed)", srv.Version)
			}
		}

		for j, tool := range srv.Tools {
			tp := fmt.Sprintf("%s.tools[%d]", p, j)
			if tool == "" {
				s.errf("V5", tp, "tool name must not be empty")
				continue
			}
			for _, r := range tool {
				if unicode.IsSpace(r) || unicode.IsControl(r) {
					s.errf("V5", tp, "tool %q must be a single token without whitespace", tool)
					break
				}
			}
		}
		for j, name := range srv.Secrets {
			if !envNameRE.MatchString(name) {
				s.errf("V5", fmt.Sprintf("%s.secrets[%d]", p, j),
					"%q is not a valid environment variable name (%s)", name, envNameRE)
			}
		}
		wildcardFlagged := false
		for j, h := range srv.Egress {
			hp := fmt.Sprintf("%s.egress[%d]", p, j)
			if h == "*" {
				if !wildcardFlagged {
					s.warnf("V5", hp, "\"*\" egress requests unrestricted network access for this server and is policy-gated (usually requires review)")
					wildcardFlagged = true
				}
				continue
			}
			if !validDNSHost(h) {
				s.errf("V5", hp, "%q is not a valid DNS host name", h)
			}
		}
	}
}

func validateFSAccess(s *issues, p string, a FSAccess) {
	switch a.Mode {
	case "", FSModeNone, FSModeWorkspace:
		if len(a.Paths) > 0 {
			s.errf("V5", p, "paths are only valid with the paths form")
		}
	case FSModePaths:
		if len(a.Paths) == 0 {
			s.errf("V5", p+".paths", "paths must list at least one path")
		}
		for i, fp := range a.Paths {
			if err := checkRelFilePath(fp); err != nil {
				s.errf("V5", fmt.Sprintf("%s.paths[%d]", p, i), "%v", err)
			}
		}
	default:
		s.errf("V5", p, "unknown filesystem access mode %q (none | workspace | paths)", a.Mode)
	}
}

func validateDependencies(s *issues, d Dependencies) {
	for i, dep := range d.Agents {
		p := fmt.Sprintf("dependencies.agents[%d]", i)
		ns, name, ok := strings.Cut(dep.Ref, "/")
		if !ok || !ValidNamespace(ns) || !ValidName(name) {
			s.errf("V1", p+".ref", "ref %q must be \"namespace/name\"", dep.Ref)
		}
		if dep.Version != "" {
			if _, err := semver.NewConstraint(dep.Version); err != nil {
				s.errf("V1", p+".version", "%q is not a valid semver constraint: %v", dep.Version, err)
			}
		}
	}
}

func validatePublish(s *issues, p Publish) {
	if len(p.Include) == 0 {
		s.errf("V4", "publish.include", "include must list at least one pattern")
	}
	for i, pat := range p.Include {
		if err := checkIncludePattern(pat); err != nil {
			s.errf("V4", fmt.Sprintf("publish.include[%d]", i), "%v", err)
		}
	}
	switch p.Channel {
	case "", ChannelStable, ChannelBeta:
	default:
		s.errf("V1", "publish.channel", "unknown channel %q (stable | beta)", p.Channel)
	}
}

// ValidateInContext applies Validate plus the context rules V2, V3, V4,
// V6, V7, and V8. It is the full server-side submit check; the returned
// errors are *Issue values and a result containing only SeverityWarning
// issues is a pass.
func ValidateInContext(m *Manifest, ctx Context) []error {
	errsList := Validate(m)
	if m == nil {
		return errsList
	}
	s := issues{list: errsList}

	// V2: manifest identity must match the repo the submission targets.
	if m.Namespace != ctx.Namespace {
		s.errf("V2", "namespace", "manifest namespace %q does not match the target repo namespace %q", m.Namespace, ctx.Namespace)
	}
	if m.Name != ctx.Name {
		s.errf("V2", "name", "manifest name %q does not match the target repo name %q", m.Name, ctx.Name)
	}

	validateVersionInContext(&s, m, ctx)

	resolved := resolveInclude(&s, m, ctx.Files)
	validateEntrypointInclusion(&s, m, ctx.Files, resolved)
	validateLockfile(&s, m, ctx.Files, resolved)
	validatePublicPublish(&s, m, ctx)
	validateQuotas(&s, ctx, resolved)
	validateFrontmatter(&s, m, ctx)

	return s.list
}

// validateFrontmatter is V9 (agentry#47, DEV-044): a skill file's YAML
// frontmatter is what the consuming runtime shows and the claude-skill
// export keeps it verbatim, so it must not contradict the signed manifest.
// A `name` that differs from the manifest name is an error; a
// `description` that differs from the summary (after whitespace/case
// folding) is a warning — summaries are short and descriptions may say
// more, but the reviewer should see that they diverge. A block that does
// not parse is a warning too: the runtime will not read it either.
func validateFrontmatter(s *issues, m *Manifest, ctx Context) {
	if ctx.ReadFile == nil || m.Entrypoints.Skill == "" || checkRelFilePath(m.Entrypoints.Skill) != nil {
		return
	}
	content, err := ctx.ReadFile(m.Entrypoints.Skill)
	if err != nil {
		return // V4 already reports a missing entrypoint
	}
	fm, ok, perr := ParseFrontmatter(content)
	if !ok {
		return
	}
	if perr != nil {
		s.warnf("V9", "entrypoints.skill", "%s: frontmatter does not parse as YAML (%v); consuming runtimes will ignore it", m.Entrypoints.Skill, perr)
		return
	}
	if fm.Name != "" && fm.Name != m.Name {
		s.errf("V9", "entrypoints.skill", "%s: frontmatter name %q contradicts the manifest name %q", m.Entrypoints.Skill, fm.Name, m.Name)
	}
	if fm.Description != "" && NormalizeProse(fm.Description) != NormalizeProse(m.Summary) {
		s.warnf("V9", "entrypoints.skill", "%s: frontmatter description differs from the manifest summary; consumers of the installed skill see the frontmatter, the registry shows the summary", m.Entrypoints.Skill)
	}
}

// validateVersionInContext is V3's context half: tag equality, global
// version immutability, and per-channel monotonicity.
func validateVersionInContext(s *issues, m *Manifest, ctx Context) {
	ver, err := semver.StrictNewVersion(m.Version)
	if err != nil {
		return // syntax already reported by Validate
	}
	if ctx.TagVersion != "" {
		if tag := strings.TrimPrefix(ctx.TagVersion, "v"); tag != m.Version {
			s.errf("V3", "version", "version %q must equal the git tag %q", m.Version, ctx.TagVersion)
		}
	}
	channel := m.EffectiveChannel()
	for ch, versions := range ctx.ExistingVersions {
		for _, existing := range versions {
			ev, err := semver.StrictNewVersion(existing)
			if err != nil {
				s.errf("V3", "version", "existing version %q on channel %q is not valid semver (registry data): %v", existing, ch, err)
				continue
			}
			switch {
			case ver.Compare(ev) == 0:
				s.errf("V3", "version", "version %q already exists on channel %q; versions are immutable and can never be re-published", existing, ch)
			case ch == channel && ver.Compare(ev) < 0:
				s.errf("V3", "version", "version %q must be greater than existing version %q on channel %q", m.Version, existing, ch)
			}
		}
	}
}

// resolveInclude is V4's resolution half: it matches the include allowlist
// against the candidate files, rejects escapes and symlinks in the
// resolved set, and requires at least one match.
func resolveInclude(s *issues, m *Manifest, files []FileInfo) []FileInfo {
	var patterns []string
	for _, pat := range m.Publish.Include {
		if checkIncludePattern(pat) == nil { // invalid ones already reported by Validate
			patterns = append(patterns, pat)
		}
	}
	if len(patterns) == 0 {
		return nil
	}

	var resolved []FileInfo
	seen := make(map[string]bool, len(files))
	badPattern := make(map[string]bool)
	for _, f := range files {
		if seen[f.Path] {
			continue
		}
		for _, pat := range patterns {
			ok, err := matchGlob(pat, f.Path)
			if err != nil {
				if !badPattern[pat] {
					s.errf("V4", "publish.include", "%v", err)
					badPattern[pat] = true
				}
				continue
			}
			if !ok {
				continue
			}
			seen[f.Path] = true
			if err := checkRelFilePath(f.Path); err != nil {
				s.errf("V4", "publish.include", "included file %q: %v", f.Path, err)
				break
			}
			if f.Symlink {
				s.errf("V4", "publish.include", "included file %q is a symlink; symlinks are not allowed in the release archive", f.Path)
				break
			}
			resolved = append(resolved, f)
			break
		}
	}
	if len(resolved) == 0 {
		s.errf("V4", "publish.include", "include patterns resolve to zero files")
	}
	if len(resolved) > 0 && !seen["agent.yaml"] {
		s.warnf("V4", "publish.include", "agent.yaml is not included in the release archive")
	}
	return resolved
}

// validateEntrypointInclusion is V4's entrypoint half: every declared
// entrypoint file must exist and be in the resolved include set.
func validateEntrypointInclusion(s *issues, m *Manifest, files []FileInfo, resolved []FileInfo) {
	byPath := make(map[string]bool, len(files))
	for _, f := range files {
		byPath[f.Path] = true
	}
	included := make(map[string]bool, len(resolved))
	for _, f := range resolved {
		included[f.Path] = true
	}

	requireIncluded := func(p, what string) {
		switch {
		case !byPath[p]:
			s.errf("V4", "entrypoints", "%s %q not found in the repo", what, p)
		case !included[p]:
			s.errf("V4", "publish.include", "%s %q is not matched by publish.include", what, p)
		}
	}

	if m.Entrypoints.Skill != "" && checkRelFilePath(m.Entrypoints.Skill) == nil {
		requireIncluded(m.Entrypoints.Skill, "skill entrypoint")
	}
	if mcp := m.Entrypoints.MCP; mcp != nil {
		// Args (and the command) that name repo files must ship in the
		// archive; non-file args (flags, module names) are skipped.
		for _, cand := range append([]string{mcp.Command}, mcp.Args...) {
			p := strings.TrimPrefix(cand, "./")
			if p != "" && byPath[p] && !included[p] {
				s.errf("V4", "publish.include", "mcp entrypoint file %q is not matched by publish.include", p)
			}
		}
	}
}

// lockfileNames are the D-14 lockfiles accepted by V6, in preference
// order.
var lockfileNames = []string{"package-lock.json", "uv.lock", "requirements.txt"}

// validateLockfile is V6's context half: kind=mcp-server needs a lockfile
// at the repo root.
func validateLockfile(s *issues, m *Manifest, files []FileInfo, resolved []FileInfo) {
	if m.Kind != KindMCPServer {
		return
	}
	byPath := make(map[string]bool, len(files))
	for _, f := range files {
		byPath[f.Path] = true
	}
	var found []string
	for _, name := range lockfileNames {
		if byPath[name] {
			found = append(found, name)
		}
	}
	if len(found) == 0 {
		s.errf("V6", "", "kind mcp-server requires a lockfile at the repo root (package-lock.json | uv.lock | requirements.txt)")
		return
	}
	if len(found) == 1 && found[0] == "requirements.txt" {
		s.warnf("V6", "", "requirements.txt must pin all dependencies with --hash entries; the S6/S7 scanners verify coverage")
	}
	included := make(map[string]bool, len(resolved))
	for _, f := range resolved {
		included[f.Path] = true
	}
	anyIncluded := false
	for _, name := range found {
		if included[name] {
			anyIncluded = true
			break
		}
	}
	if !anyIncluded {
		s.warnf("V6", "publish.include", "lockfile %q is not included in the release archive; consumers cannot reproduce the dependency set", found[0])
	}
}

// validatePublicPublish is V7: public publish requires a plausible SPDX
// license id plus LICENSE and README.md files.
func validatePublicPublish(s *issues, m *Manifest, ctx Context) {
	if !ctx.Public {
		return
	}
	if m.License == "" {
		s.errf("V7", "license", "public publish requires an SPDX license id")
	} else if _, _, err := ParseSPDXExpression(m.License); err != nil {
		s.errf("V7", "license", "%q is not a valid SPDX license expression: %v", m.License, err)
	}
	byPath := make(map[string]bool, len(ctx.Files))
	for _, f := range ctx.Files {
		byPath[f.Path] = true
	}
	if !byPath["LICENSE"] && !byPath["LICENSE.md"] && !byPath["LICENSE.txt"] {
		s.errf("V7", "", "public publish requires a LICENSE file at the repo root")
	}
	if !byPath["README.md"] {
		s.errf("V7", "", "public publish requires README.md at the repo root")
	}
}

// validateQuotas is V8's context half: §19 archive quotas over the
// resolved include set.
func validateQuotas(s *issues, ctx Context, resolved []FileInfo) {
	q := DefaultQuotas()
	if ctx.Quotas != nil {
		q = *ctx.Quotas
	}
	if len(resolved) > q.MaxFiles {
		s.errf("V8", "publish.include", "archive would contain %d files; the maximum is %d", len(resolved), q.MaxFiles)
	}
	var total int64
	for _, f := range resolved {
		total += f.Size
		limit := q.MaxFileBytes
		if isImagePath(f.Path) {
			limit = q.MaxImageFileBytes
		}
		if f.Size > limit {
			s.errf("V8", "publish.include", "file %q is %d bytes; the per-file maximum is %d", f.Path, f.Size, limit)
		}
	}
	if total > q.MaxArchiveBytes {
		s.errf("V8", "publish.include", "archive would be %d bytes; the maximum is %d", total, q.MaxArchiveBytes)
	}
}

// imageExtensions are the extensions granted the §19 image per-file quota.
func isImagePath(p string) bool {
	switch strings.ToLower(path.Ext(p)) {
	case ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".bmp":
		return true
	}
	return false
}

// validDNSHost reports whether h is a syntactically valid DNS host name:
// dot-separated labels of at most 63 alphanumeric-or-hyphen characters
// with no leading/trailing hyphen, at most 253 characters total.
func validDNSHost(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if n := len(label); n == 0 || n > 63 {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			case c == '-':
				if i == 0 || i == len(label)-1 {
					return false
				}
			default:
				return false
			}
		}
	}
	return true
}

// checkRelFilePath validates a repo-relative file path: slash-separated,
// not absolute, and free of "", ".", and ".." segments and backslashes.
func checkRelFilePath(p string) error {
	if p == "" {
		return errors.New("path must not be empty")
	}
	if strings.HasPrefix(p, "/") {
		return fmt.Errorf("path %q must be repo-relative, not absolute", p)
	}
	if strings.Contains(p, "\\") {
		return fmt.Errorf("path %q must use forward slashes", p)
	}
	for _, seg := range strings.Split(p, "/") {
		switch seg {
		case "":
			return fmt.Errorf("path %q has an empty segment", p)
		case ".", "..":
			return fmt.Errorf("path %q must not contain %q segments", p, seg)
		}
	}
	return nil
}

// checkIncludePattern validates one publish.include glob pattern: same
// escape rules as file paths (relative, no "."/".." segments) plus
// path.Match syntax validity per segment ("**" segments excepted).
func checkIncludePattern(pat string) error {
	if pat == "" {
		return errors.New("pattern must not be empty")
	}
	if strings.HasPrefix(pat, "/") {
		return fmt.Errorf("pattern %q must be repo-relative, not absolute", pat)
	}
	for _, seg := range strings.Split(pat, "/") {
		switch seg {
		case "":
			return fmt.Errorf("pattern %q has an empty segment", pat)
		case ".", "..":
			return fmt.Errorf("pattern %q must not contain %q segments", pat, seg)
		case "**":
			continue
		}
		if err := scanPatternSegment(seg); err != nil {
			return fmt.Errorf("pattern %q: %w", pat, err)
		}
	}
	return nil
}

// scanPatternSegment checks path.Match syntax validity of one pattern
// segment, mirroring path.Match's ErrBadPattern conditions (trailing
// backslash, malformed character class) without needing a candidate name.
func scanPatternSegment(seg string) error {
	rest := seg
	for len(rest) > 0 {
		switch rest[0] {
		case '\\':
			if len(rest) == 1 {
				return path.ErrBadPattern
			}
			rest = rest[2:]
		case '[':
			rest = strings.TrimPrefix(rest[1:], "^")
			nrange := 0
			for {
				if len(rest) == 0 {
					return path.ErrBadPattern // unclosed class
				}
				if rest[0] == ']' && nrange > 0 {
					rest = rest[1:]
					break
				}
				var err error
				if rest, err = scanClassChar(rest); err != nil {
					return err
				}
				if strings.HasPrefix(rest, "-") {
					if rest, err = scanClassChar(rest[1:]); err != nil {
						return err
					}
				}
				nrange++
			}
		default:
			_, size := utf8.DecodeRuneInString(rest)
			rest = rest[size:]
		}
	}
	return nil
}

// scanClassChar consumes one (possibly escaped) character-class character,
// mirroring path.Match's getEsc.
func scanClassChar(rest string) (string, error) {
	if len(rest) == 0 || rest[0] == '-' || rest[0] == ']' {
		return rest, path.ErrBadPattern
	}
	if rest[0] == '\\' {
		rest = rest[1:]
		if len(rest) == 0 {
			return rest, path.ErrBadPattern
		}
	}
	_, size := utf8.DecodeRuneInString(rest)
	return rest[size:], nil
}
