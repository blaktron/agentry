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
)

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
//     proxy.
//
// A manifest that is not JSON, or has no capabilities block, declares
// nothing.
func DeclaredCapabilities(manifestJSON []byte) []string {
	c, ok := manifestcaps.Read(manifestJSON)
	if !ok {
		return nil
	}
	var out []string
	if (len(c.Network.Egress.Hosts) > 0 && !manifestcaps.OnlyNone(c.Network.Egress.Hosts)) || len(c.RemoteServerHosts()) > 0 || len(c.ServerEgress()) > 0 {
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
	sort.Strings(out)
	return out
}

// UnrestrictedNetwork reports whether a manifest asks for the network
// without naming where: "*" egress, or a browser whose scope is any public
// site, or a browser line that does not read, which is taken the strict way.
// It is the gate's Case.WildcardEgress, which the policy's wildcardEgress
// decides.
func UnrestrictedNetwork(manifestJSON []byte) bool {
	c, _ := manifestcaps.Read(manifestJSON)
	for _, h := range c.Network.Egress.Hosts {
		if strings.ToLower(h) == "*" {
			return true
		}
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
