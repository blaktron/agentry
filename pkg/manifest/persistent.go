package manifest

import (
	"fmt"
	"maps"
	"slices"
	"strings"
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
//     be offered the applications on the person's computer,
//     use the coding toolchain, the web tools, Agentry's helper tools and
//     AI Review. The set is closed and every key is off unless declared,
//     so a runner grants only what the release names and an older runner
//     refuses a key it does not know. The block is part of the contract:
//     consent lists it, a new key asks again, and the scanners read
//     instruction text against it.
//   - persona names the agent and ships the text it takes on (V17, in
//     persona.go), a file the scanners read as they read the instruction.
//   - dependencies.agents become the agent's subagents (V18, in
//     subagents.go): QuickAgents it may start as runs of their own, each
//     with a semver constraint and a reason shown in consent. The contract
//     carries them, so a new subagent or a changed constraint asks again.

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
	// Desktop lets the agent be offered the applications on the person's
	// computer, through Agentry Desktop: each application the person
	// approved there, and computer use, once the person switches it on. The
	// release's capabilities.desktop line, when it has one, narrows what is
	// offered.
	Desktop bool `yaml:"desktop,omitempty" json:"desktop,omitempty"`
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
	{"desktop", "using the applications on your computer that you switch on, through Agentry Desktop"},
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
	case "desktop":
		return p.Desktop
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
	// capabilities.skills or capabilities.persistent.skills: one Agent
	// Skills folder per skill, each with its SkillFile.
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

	if p.Coder {
		var beside []string
		for _, k := range coderAloneBeside {
			if p.Declares(k) {
				beside = append(beside, k)
			}
		}
		if len(beside) > 0 {
			s.errf("V16", "capabilities.persistent", "coder is never declared beside %s: the coding toolchain runs any program the agent asks for, on open egress, in the container that would hold the keys and feed addresses those keys put there", strings.Join(beside, " or "))
		}
	}

	closedNames(s, "capabilities.persistent.mail", "mail provider", p.Mail, MailProviderNames)
	closedNames(s, "capabilities.persistent.imageServers", "image server", p.ImageServers, ImageServerNames)
	for i, provider := range p.Mail {
		if srv, ok := mailImageServer[provider]; ok && !slices.Contains(p.ImageServers, srv) {
			s.errf("V16", fmt.Sprintf("capabilities.persistent.mail[%d]", i), "mail at %s is reached through the %s server: add %s to imageServers", provider, srv, srv)
		}
	}
}

// coderAloneBeside are the keys whose grants put the person's keys or feed
// addresses in the agent's tools container (the web tools' search and scan
// keys, the review key, the calendar feeds' addresses). They sit beside one
// another, and never beside coder, whose programs run in that container.
var coderAloneBeside = []string{"web", "review", "calendars"}

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
	for _, name := range slices.Sorted(maps.Keys(skillFolders)) {
		if !skillFolders[name] {
			s.errf("V16", "publish.include", "the skill folder %s/%s/ has no %s", SkillsDir, name, SkillFile)
		}
	}
}
