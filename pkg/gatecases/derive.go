package gatecases

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/blaktron/agentry/internal/manifestcaps"
	"github.com/blaktron/agentry/pkg/manifest"
	"github.com/blaktron/agentry/pkg/rules"
)

// The capability tokens DeclaredCapabilities names, as a publication
// policy's requireHumanReview.whenCapabilities and blockedCapabilities name
// them.
const (
	CapNetwork     = "network"
	CapFSRead      = "fs-read"
	CapFSWrite     = "fs-write"
	CapExec        = "exec"
	CapEnv         = "env"
	CapTargetHosts = "targetHosts"
	CapBrowser     = "browser"
	// CapDesktop is a release that uses the person's own computer: any
	// capabilities.desktop line.
	CapDesktop = "desktop"
	// CapComputerUse is a desktop line that does computer use.
	CapComputerUse = "computerUse"
	// CapSubagents is a persistent release that declares subagents.
	CapSubagents = "subagents"
	// CapSkills is a release that ships skills: capabilities.skills.
	CapSkills = "skills"
)

// CapPersistent is the token of one key of capabilities.persistent, such as
// persistent.coder.
func CapPersistent(key string) string { return "persistent." + key }

// DeclaredCapabilities is the set of capability tokens a manifest declares,
// sorted, from its canonical JSON: the gate's Case.DeclaredCapabilities.
//
//   - network: egress hosts other than "none", a remote MCP server's host, or
//     a package MCP server's own egress;
//   - fs-read, fs-write, exec: the line declares more than "none";
//   - env: a declared secret;
//   - targetHosts: any target host, a token of its own and never network,
//     because the runner makes the session;
//   - browser: a browser line, readable or not, a token of its own and never
//     network, because the browser reaches sites through the runner's browse
//     proxy;
//   - desktop: a line for the person's own computer, readable or not, a
//     token of its own; and computerUse when that line does computer use
//     or does not read. A line that uses any application's server, or does
//     not read, counts as network too: that server runs on the person's
//     computer with their network, and what it reaches is not known;
//   - persistent.<key>: each key capabilities.persistent declares, and every
//     key when the block does not read;
//   - subagents: a persistent release that declares subagents, or whose
//     dependencies do not read;
//   - skills: capabilities.skills, a token of its own: the skills it ships
//     guide the agent and grant it nothing. A persistent agent's are
//     persistent.skills.
//
// A manifest that is not JSON, or has no capabilities block, declares
// nothing.
func DeclaredCapabilities(manifestJSON []byte) []string {
	c, ok := manifestcaps.Read(manifestJSON)
	if !ok {
		return nil
	}
	var out []string
	if (len(c.Network.Egress.Hosts) > 0 && !manifestcaps.OnlyNone(c.Network.Egress.Hosts)) || len(c.RemoteServerHosts()) > 0 || len(c.ServerEgress()) > 0 || c.DesktopReachUnknown() {
		out = append(out, CapNetwork)
	}
	if manifestcaps.NotNone(c.Filesystem.Write) {
		out = append(out, CapFSWrite)
	}
	if manifestcaps.NotNone(c.Filesystem.Read) {
		out = append(out, CapFSRead)
	}
	if manifestcaps.NotNone(c.Exec) {
		out = append(out, CapExec)
	}
	if len(c.Secrets) > 0 {
		out = append(out, CapEnv)
	}
	if len(c.TargetHosts) > 0 {
		out = append(out, CapTargetHosts)
	}
	if _, declared, _ := c.Browser(); declared {
		out = append(out, CapBrowser)
	}
	if d, declared, ok := c.Desktop(); declared {
		out = append(out, CapDesktop)
		if !ok || d.HasComputerUse() {
			out = append(out, CapComputerUse)
		}
	}
	if p, declared, ok := c.Persistent(); declared {
		for _, k := range manifest.PersistentCapabilities() {
			if !ok || p.Declares(k.Key) {
				out = append(out, CapPersistent(k.Key))
			}
		}
	}
	if agents, ok := manifestcaps.Subagents(manifestJSON); !ok || len(agents) > 0 {
		out = append(out, CapSubagents)
	}
	if c.ShipsSkills() {
		out = append(out, CapSkills)
	}
	sort.Strings(out)
	return out
}

// UnrestrictedNetwork reports whether a manifest asks for the network
// without naming where: "*" egress, or a browser whose scope is any public
// site, or a browser line that does not read, which is taken the strict way,
// or a persistent agent's coder, browser or fetch key (or a block that
// does not read), none of which names a host.
// It is the gate's Case.WildcardEgress, which the policy's wildcardEgress
// decides.
func UnrestrictedNetwork(manifestJSON []byte) bool {
	c, _ := manifestcaps.Read(manifestJSON)
	for _, h := range c.Network.Egress.Hosts {
		if strings.ToLower(h) == "*" {
			return true
		}
	}
	if p, declared, ok := c.Persistent(); declared && (!ok || p.Coder || p.Browser || p.Fetch) {
		return true
	}
	b, declared, ok := c.Browser()
	return declared && (!ok || b.IsPublic())
}

// Declaration is what a manifest declares, as S4's rating by declaration
// (rules.RateByDeclaration) reads it, from its canonical JSON. The scanner
// rates S4 with it, and a client restating the gate's rating reads it the
// same way. An unreadable manifest declares nothing but the base commands,
// so every capability family's hit is high.
func Declaration(manifestJSON []byte) rules.Declared {
	d := rules.Declared{BaseCommands: manifest.BaseExecCommands()}
	c, ok := manifestcaps.Read(manifestJSON)
	if !ok {
		return d
	}
	for _, h := range c.Network.Egress.Hosts {
		switch h {
		case "", "none":
		case "*":
			d.EgressAny = true
		default:
			d.Egress = append(d.Egress, strings.ToLower(h))
		}
	}
	for _, h := range c.RemoteServerHosts() {
		d.ServerHosts = append(d.ServerHosts, strings.ToLower(h))
	}
	d.MCPServers = len(c.MCPServers) > 0
	// A browser's hosts are hosts the release declares. A
	// line that does not read declares none here, the side this rating
	// fails toward.
	if b, declared, ok := c.Browser(); declared && ok {
		d.BrowserAny = b.IsPublic()
		d.BrowserHosts = c.BrowserHosts()
	}
	// A persistent agent's coding toolchain reaches the open web from its
	// commands and drives a public browser. A block that does not read
	// declares none of it here, the side this rating fails toward.
	if p, declared, ok := c.Persistent(); declared && ok {
		if p.Coder {
			d.EgressAny, d.BrowserAny = true, true
		}
		if p.Browser {
			d.BrowserAny = true
		}
		if p.Fetch {
			d.EgressAny = true
		}
	}
	d.Secrets = append([]string(nil), c.Secrets...)
	for _, srv := range c.MCPServers {
		d.Secrets = append(d.Secrets, srv.Secrets...)
	}
	d.FileWrite = manifestcaps.NotNone(c.Filesystem.Write)
	if manifestcaps.NotNone(c.Exec) {
		var x struct {
			Commands []string `json:"commands"`
		}
		// An exec block that does not decode names no command: every
		// program a hit names then reads as undeclared, which holds.
		_ = json.Unmarshal(c.Exec, &x)
		d.Exec = x.Commands
		if d.Exec == nil {
			d.Exec = []string{}
		}
	}
	return d
}
