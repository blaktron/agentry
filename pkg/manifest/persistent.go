package manifest

import (
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/Masterminds/semver/v3"
)

// A persistent release. A release whose modes include persistent is an
// agent the person keeps running on their own computer: its conversation,
// its files and its memory outlive each start and stop. Three things in
// the manifest are about that mode alone, and each is valid only beside
// it:
//
//   - capabilities.persistent declares what the agent may do beyond an
//     ordinary run (V16): keep time and tasks, keep a memory, follow
//     skills, be given stored secrets, change its own name and persona,
//     reach the person's calendars, meetings, mail and image-run servers,
//     use the coding toolchain, the web tools, Agentry's helper tools and
//     AI Review. The set is closed and every key is off unless declared,
//     so a runner grants only what the release names and an older runner
//     refuses a key it does not know. The block is part of the contract:
//     consent lists it, a new key asks again, and the scanners read
//     instruction text against it.
//   - persona names the agent and ships the text it takes on (V17), a
//     file the scanners read as they read the instruction.
//   - dependencies.agents become the agent's subagents (V18): published
//     autonomous QuickAgents it may start as runs of their own, each with
//     a semver constraint and a reason shown in consent. The registry
//     resolves each one at submit; the contract carries them, so a new
//     subagent or a changed constraint asks again.

// Persistent is capabilities.persistent (v2, V16). Every field is off
// unless declared.
type Persistent struct {
	// Clock gives the agent the time on each turn, its own tasks and the
	// heartbeat that fires them.
	Clock bool `yaml:"clock,omitempty" json:"clock,omitempty"`
	// Memory gives the agent a memory wiki on its own volume, seeded from
	// the archive's memory/ folder, with compaction and recall.
	Memory bool `yaml:"memory,omitempty" json:"memory,omitempty"`
	// Skills gives the agent the archive's skills/ folder and the skills
	// the person adds.
	Skills bool `yaml:"skills,omitempty" json:"skills,omitempty"`
	// Secrets names the stored secrets the person may keep for the agent
	// in their keychain, by environment variable name.
	Secrets []string `yaml:"secrets,omitempty" json:"secrets,omitempty"`
	// SelfConfigure lets the agent change its own name and persona.
	SelfConfigure bool `yaml:"selfConfigure,omitempty" json:"selfConfigure,omitempty"`
	// Calendars lets the agent read the calendar feeds the person adds.
	Calendars bool `yaml:"calendars,omitempty" json:"calendars,omitempty"`
	// Meetings lets the agent take meeting notes the person arms.
	Meetings bool `yaml:"meetings,omitempty" json:"meetings,omitempty"`
	// Mail names the mail providers the agent may reach once the person
	// signs in, from MailProviderNames.
	Mail []string `yaml:"mail,omitempty" json:"mail,omitempty"`
	// ImageServers names the servers the runner runs from its own pinned
	// images that the agent may use once the person signs in, from
	// ImageServerNames.
	ImageServers []string `yaml:"imageServers,omitempty" json:"imageServers,omitempty"`
	// Coder gives the agent the coding toolchain: any program in the
	// runner's coding image, open web egress for its commands, a public
	// browser, a development host, ports, and git host accounts.
	Coder bool `yaml:"coder,omitempty" json:"coder,omitempty"`
	// Web gives the agent the web tools, web_search and web_fetch.
	Web bool `yaml:"web,omitempty" json:"web,omitempty"`
	// Helper gives the agent Agentry's helper tools: search the registry,
	// show, install and run QuickAgents, read their results, list what is
	// installed, keep schedules, open settings and read the docs. Each
	// install, schedule change and first run of a new version is still
	// the person's to agree to.
	Helper bool `yaml:"helper,omitempty" json:"helper,omitempty"`
	// Review gives the agent AI Review with the person's own key.
	Review bool `yaml:"review,omitempty" json:"review,omitempty"`
}

// PersistentCapability is one key of capabilities.persistent and what it
// gives, in the words consent and the report use.
type PersistentCapability struct {
	// Key is the key as written in agent.yaml.
	Key string
	// Words say what the key gives the agent, for a person.
	Words string
}

// persistentCapabilities is every key of capabilities.persistent, in the
// order consent lists them.
var persistentCapabilities = []PersistentCapability{
	{"clock", "the time on each turn, its own tasks and the heartbeat that fires them"},
	{"memory", "a memory on its own volume that it keeps, compacts and recalls from"},
	{"skills", "the skills it ships and the ones you add"},
	{"secrets", "stored secrets you keep for it in your keychain"},
	{"selfConfigure", "changing its own name and persona"},
	{"calendars", "reading the calendar feeds you add"},
	{"meetings", "taking notes in the meetings you arm"},
	{"mail", "your mail, at the providers you sign in to"},
	{"imageServers", "servers the runner runs from its own images, once you sign in"},
	{"coder", "the coding toolchain: any program in the coding image, open web access for its commands, a public browser, a development host, ports and git host accounts"},
	{"web", "searching the web and reading pages"},
	{"helper", "finding, installing, running and scheduling QuickAgents, each install and new version with your agreement"},
	{"review", "AI Review with your own key"},
}

// PersistentCapabilities returns every key capabilities.persistent can
// declare, with its words, in consent order. The slice is the caller's
// own.
func PersistentCapabilities() []PersistentCapability {
	return append([]PersistentCapability(nil), persistentCapabilities...)
}

// MailProviderNames are the mail providers capabilities.persistent.mail
// may name, the ones a runner carries.
var MailProviderNames = []string{"google", "microsoft", "fastmail"}

// ImageServerNames are the servers capabilities.persistent.imageServers
// may name, the ones a runner runs from its own pinned images.
var ImageServerNames = []string{"google-workspace", "microsoft-365"}

// mailImageServer is the image server a mail provider is reached through,
// for the providers that have one: declaring the provider without its
// server would grant more than the contract says.
var mailImageServer = map[string]string{
	"google":    "google-workspace",
	"microsoft": "microsoft-365",
}

// MaxPersistentSecrets bounds capabilities.persistent.secrets: a runner
// keeps at most this many stored secrets for one agent.
const MaxPersistentSecrets = 32

// Keys returns the keys p declares, in consent order; nil for none.
func (p *Persistent) Keys() []string {
	if p == nil {
		return nil
	}
	var out []string
	for _, c := range persistentCapabilities {
		if p.Declares(c.Key) {
			out = append(out, c.Key)
		}
	}
	return out
}

// Declares reports whether p declares key, one of the keys of
// PersistentCapabilities; a list key is declared when it names anything.
func (p *Persistent) Declares(key string) bool {
	if p == nil {
		return false
	}
	switch key {
	case "clock":
		return p.Clock
	case "memory":
		return p.Memory
	case "skills":
		return p.Skills
	case "secrets":
		return len(p.Secrets) > 0
	case "selfConfigure":
		return p.SelfConfigure
	case "calendars":
		return p.Calendars
	case "meetings":
		return p.Meetings
	case "mail":
		return len(p.Mail) > 0
	case "imageServers":
		return len(p.ImageServers) > 0
	case "coder":
		return p.Coder
	case "web":
		return p.Web
	case "helper":
		return p.Helper
	case "review":
		return p.Review
	}
	return false
}

// IsPersistent reports whether the release supports the persistent mode.
func (m *Manifest) IsPersistent() bool { return m.Supports(ModePersistent) }

// The archive folders a persistent release's capabilities read.
const (
	// MemorySeedDir is the archive folder a memory is seeded from, with
	// capabilities.persistent.memory.
	MemorySeedDir = "memory"
	// SkillsDir is the archive folder of shipped skills, with
	// capabilities.persistent.skills: one Agent Skills folder per skill,
	// each with its SkillFile.
	SkillsDir = "skills"
	// SkillFile is the file that makes a folder under SkillsDir a skill.
	SkillFile = "SKILL.md"
)

// validatePersistent is V16: capabilities.persistent is a v2 field, valid
// only beside the persistent mode; it declares something; its secrets are
// environment variable names, at most MaxPersistentSecrets, each once and
// none also a run secret of the release; its mail and imageServers name
// what a runner carries, each once, and a mail provider reached through
// an image server comes with that server.
func validatePersistent(s *issues, m *Manifest) {
	p := m.Capabilities.Persistent
	if p == nil {
		return
	}
	if m.Major() != 2 {
		s.errf("V1", "capabilities.persistent", "persistent is a v2 field; set schemaVersion: 2")
		return
	}
	if !m.IsPersistent() {
		s.errf("V16", "capabilities.persistent", "capabilities.persistent is for a persistent agent: add persistent to modes, or remove the block")
	}
	if len(p.Keys()) == 0 {
		s.errf("V16", "capabilities.persistent", "the block declares nothing: declare a capability or remove it")
	}

	if len(p.Secrets) > MaxPersistentSecrets {
		s.errf("V16", "capabilities.persistent.secrets", "%d stored secrets; the maximum is %d", len(p.Secrets), MaxPersistentSecrets)
	}
	runSecrets := declaredSecretNames(m.Capabilities)
	seen := map[string]bool{}
	for i, name := range p.Secrets {
		at := fmt.Sprintf("capabilities.persistent.secrets[%d]", i)
		switch {
		case !envNameRE.MatchString(name):
			s.errf("V16", at, "%q is not a valid environment variable name (%s)", name, envNameRE)
		case seen[name]:
			s.errf("V16", at, "duplicate stored secret %q", name)
		case runSecrets[name]:
			s.errf("V16", at, "%q is also a secret the release asks for at each run; a stored secret needs a name of its own", name)
		}
		seen[name] = true
	}

	closedNames(s, "capabilities.persistent.mail", "mail provider", p.Mail, MailProviderNames)
	closedNames(s, "capabilities.persistent.imageServers", "image server", p.ImageServers, ImageServerNames)
	for i, provider := range p.Mail {
		if srv, ok := mailImageServer[provider]; ok && !slices.Contains(p.ImageServers, srv) {
			s.errf("V16", fmt.Sprintf("capabilities.persistent.mail[%d]", i), "mail at %s is reached through the %s server: add %s to imageServers", provider, srv, srv)
		}
	}
}

// closedNames checks that every entry of names is one of known, once.
func closedNames(s *issues, at, what string, names, known []string) {
	seen := map[string]bool{}
	for i, n := range names {
		p := fmt.Sprintf("%s[%d]", at, i)
		switch {
		case !slices.Contains(known, n):
			s.errf("V16", p, "unknown %s %q (%s)", what, n, strings.Join(known, " | "))
		case seen[n]:
			s.errf("V16", p, "duplicate %s %q", what, n)
		}
		seen[n] = true
	}
}

// validatePersistentFolders is V16's archive half: in a persistent
// release, files under memory/ are a memory seed and files under skills/
// are shipped skills, so each folder is read only when its key is
// declared. A folder without its key is reported as a warning, since the
// runner leaves it unread; each shipped skill is a folder of its own
// carrying SKILL.md.
func validatePersistentFolders(s *issues, m *Manifest, resolved []FileInfo) {
	if !m.IsPersistent() {
		return
	}
	p := m.Capabilities.Persistent
	var memory, skills bool
	skillFolders := map[string]bool{}
	for _, f := range resolved {
		top, rest, nested := strings.Cut(f.Path, "/")
		if !nested {
			continue
		}
		switch top {
		case MemorySeedDir:
			memory = true
		case SkillsDir:
			skills = true
			name, inner, ok := strings.Cut(rest, "/")
			if !ok {
				if p.Declares("skills") {
					s.errf("V16", "publish.include", "%q is not in a skill's folder: each skill is skills/<name>/ with its %s", f.Path, SkillFile)
				}
				continue
			}
			if _, seen := skillFolders[name]; !seen {
				skillFolders[name] = false
			}
			if inner == SkillFile {
				skillFolders[name] = true
			}
		}
	}
	if memory && !p.Declares("memory") {
		s.warnf("V16", "publish.include", "the archive carries %s/, which seeds a memory only with capabilities.persistent.memory; without it the runner does not read it", MemorySeedDir)
	}
	if skills && !p.Declares("skills") {
		s.warnf("V16", "publish.include", "the archive carries %s/, which gives the agent skills only with capabilities.persistent.skills; without it the runner does not read it", SkillsDir)
	}
	if !p.Declares("skills") {
		return
	}
	for _, name := range slicesSortedKeys(skillFolders) {
		if !skillFolders[name] {
			s.errf("V16", "publish.include", "the skill folder %s/%s/ has no %s", SkillsDir, name, SkillFile)
		}
	}
}

func slicesSortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// Persona is the name and the text a persistent agent takes on (v2,
// V17). The text is a file in the archive, read by the scanners as they
// read the instruction. It sits inside the instruction and the runner's
// own paragraphs and cannot widen what either allows.
type Persona struct {
	// Name is the agent's name, shown to the person: one plain line of at
	// most MaxPersonaNameBytes.
	Name string `yaml:"name" json:"name"`
	// File is the persona's text in the archive, at most
	// MaxPersonaFileBytes; empty means DefaultPersonaFile.
	File string `yaml:"file,omitempty" json:"file,omitempty"`
	// Editable lets the person replace the persona's text; nil means
	// true. A locked persona can still be renamed.
	Editable *bool `yaml:"editable,omitempty" json:"editable,omitempty"`
}

// DefaultPersonaFile is the persona's file when the manifest names none.
const DefaultPersonaFile = "PERSONA.md"

// The persona's bounds, the ones a runner keeps for a person's own name
// and personality.
const (
	MaxPersonaNameBytes = 64
	MaxPersonaFileBytes = 32 << 10
)

// PersonaFile returns the persona's file in the archive; "" when the
// release ships no persona.
func (m *Manifest) PersonaFile() string {
	if m.Persona == nil {
		return ""
	}
	if m.Persona.File == "" {
		return DefaultPersonaFile
	}
	return m.Persona.File
}

// IsEditable reports whether the person may replace the persona's text.
func (p *Persona) IsEditable() bool { return p == nil || p.Editable == nil || *p.Editable }

// validatePersona is V17: persona is a v2 field, valid only with the
// persistent mode; its name is one plain line of at most
// MaxPersonaNameBytes; its file is a repository path other than the
// instruction.
func validatePersona(s *issues, m *Manifest) {
	p := m.Persona
	if p == nil {
		return
	}
	if m.Major() != 2 {
		s.errf("V1", "persona", "persona is a v2 field; set schemaVersion: 2")
		return
	}
	if !m.IsPersistent() {
		s.errf("V17", "persona", "a persona is for a persistent agent: add persistent to modes, or remove it")
	}
	switch {
	case strings.TrimSpace(p.Name) == "":
		s.errf("V17", "persona.name", "the persona's name must not be empty")
	case len(p.Name) > MaxPersonaNameBytes:
		s.errf("V17", "persona.name", "the persona's name is %d bytes; the maximum is %d", len(p.Name), MaxPersonaNameBytes)
	default:
		if r, found := notPlain(p.Name); found {
			s.errf("V17", "persona.name", "the persona's name must be plain single-line text (no control or format characters; found U+%04X)", r)
		}
	}
	f := m.PersonaFile()
	if err := checkRelFilePath(f); err != nil {
		s.errf("V17", "persona.file", "%v", err)
		return
	}
	if slices.Contains(m.InstructionCandidates(), f) {
		s.errf("V17", "persona.file", "%q is the instruction; the persona is a file of its own", f)
	}
}

// validatePersonaInContext is V17's archive half: the persona's file is in
// the repository, matched by publish.include, at most MaxPersonaFileBytes
// and UTF-8 text.
func validatePersonaInContext(s *issues, m *Manifest, ctx Context, resolved []FileInfo) {
	f := m.PersonaFile()
	if f == "" || checkRelFilePath(f) != nil {
		return
	}
	var found, included bool
	var size int64
	for _, c := range ctx.Files {
		if c.Path == f {
			found, size = true, c.Size
		}
	}
	for _, c := range resolved {
		if c.Path == f {
			included = true
		}
	}
	switch {
	case !found:
		s.errf("V17", "persona.file", "the persona's file %q is not in the repo", f)
		return
	case !included:
		s.errf("V17", "publish.include", "the persona's file %q is not matched by publish.include", f)
		return
	case size > MaxPersonaFileBytes:
		s.errf("V17", "persona.file", "the persona's file is %d bytes; the maximum is %d", size, MaxPersonaFileBytes)
		return
	}
	if ctx.ReadFile == nil {
		return
	}
	data, err := ctx.ReadFile(f)
	if err != nil {
		s.errf("V17", "persona.file", "reading the persona's file: %v", err)
		return
	}
	if !utf8.Valid(data) || slices.Contains(data, 0) {
		s.errf("V17", "persona.file", "the persona's file must be UTF-8 text")
	}
}

// MaxSubagents bounds the subagents one persistent release may declare.
const MaxSubagents = 16

// MaxSubagentWhyChars bounds a dependency's why, the reason consent shows.
const MaxSubagentWhyChars = 200

// Subagents returns the release's subagents: its dependencies.agents when
// it supports the persistent mode, nil otherwise, where the list stays
// informational. The slice is the caller's own.
func (m *Manifest) Subagents() []AgentDependency {
	if !m.IsPersistent() || len(m.Dependencies.Agents) == 0 {
		return nil
	}
	return append([]AgentDependency(nil), m.Dependencies.Agents...)
}

// validateSubagents is V18: in a persistent release, dependencies.agents
// are its subagents, at most MaxSubagents, each once, none the release
// itself, each with a semver constraint and a why. A why is one plain
// line of at most MaxSubagentWhyChars in any release.
func validateSubagents(s *issues, m *Manifest) {
	persistent := m.IsPersistent()
	if persistent && len(m.Dependencies.Agents) > MaxSubagents {
		s.errf("V18", "dependencies.agents", "%d subagents; the maximum is %d", len(m.Dependencies.Agents), MaxSubagents)
	}
	self := m.Namespace + "/" + m.Name
	seen := map[string]bool{}
	for i, dep := range m.Dependencies.Agents {
		p := fmt.Sprintf("dependencies.agents[%d]", i)
		if dep.Why != "" {
			if n := utf8.RuneCountInString(dep.Why); n > MaxSubagentWhyChars {
				s.errf("V18", p+".why", "why is %d characters; the maximum is %d", n, MaxSubagentWhyChars)
			}
			if r, found := notPlain(dep.Why); found {
				s.errf("V18", p+".why", "why must be plain single-line text (no control or format characters; found U+%04X)", r)
			}
		}
		if !persistent {
			continue
		}
		if strings.TrimSpace(dep.Version) == "" {
			s.errf("V18", p+".version", "a subagent needs a semver constraint, such as ^1.2.0")
		}
		if strings.TrimSpace(dep.Why) == "" {
			s.errf("V18", p+".why", "a subagent needs a why: one line, shown when the person agrees, saying what the agent uses it for")
		}
		switch {
		case dep.Ref == self:
			s.errf("V18", p+".ref", "a release cannot be its own subagent")
		case seen[dep.Ref]:
			s.errf("V18", p+".ref", "duplicate subagent %q", dep.Ref)
		}
		seen[dep.Ref] = true
	}
}

// SubagentAllows reports whether version satisfies the subagent's
// constraint; false when either does not parse.
func (d AgentDependency) SubagentAllows(version string) bool {
	c, err := semver.NewConstraint(d.Version)
	if err != nil {
		return false
	}
	v, err := semver.StrictNewVersion(version)
	if err != nil {
		return false
	}
	return c.Check(v)
}
