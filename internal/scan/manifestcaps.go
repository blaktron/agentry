package scan

import (
	"encoding/json"
	"strings"

	"github.com/blaktron/agentry/pkg/manifest"
	"github.com/blaktron/agentry/pkg/rules"
)

// manifestCaps is the capabilities block of the canonical manifest JSON, as
// every stage that reads it decodes it: once, here. Egress is pkg/manifest's
// own union type, because the canonical form carries `egress: none` as the
// JSON string "none" and a host list as an array; decoding it into a
// []string failed the whole decode, and every capability of such a
// manifest read as undeclared to S6, S9, the gate and namespace policy
// (agentry#755).
type manifestCaps struct {
	Network struct {
		Egress manifest.Egress `json:"egress"`
	} `json:"network"`
	Filesystem struct {
		Read  json.RawMessage `json:"read"`
		Write json.RawMessage `json:"write"`
	} `json:"filesystem"`
	Exec        json.RawMessage      `json:"exec"`
	Secrets     []string             `json:"secrets"`
	MCPServers  []manifest.MCPServer `json:"mcpServers"`
	TargetHosts []string             `json:"targetHosts"`
	// Browser is kept raw and read by browser(), so a value of an odd
	// shape cannot fail the whole decode and leave every other capability
	// undeclared (agentry#755).
	Browser json.RawMessage `json:"browser"`
}

// browser reads the browser line. declared is false when there is none;
// ok is false when there is one that does not decode, which the callers
// read the strict way: a browser, on any public site.
func (c manifestCaps) browser() (b *manifest.Browser, declared, ok bool) {
	if len(c.Browser) == 0 || string(c.Browser) == "null" {
		return nil, false, true
	}
	if err := json.Unmarshal(c.Browser, &b); err != nil || b == nil {
		return nil, true, false
	}
	return b, true, true
}

// unrestrictedNetwork reports whether the manifest asks for the network
// without naming where: "*" egress, or a browser whose scope is any public
// site (plan browser-testing.md D1, D12). The gate holds both the same way,
// under the policy's wildcardEgress.
func unrestrictedNetwork(manifestJSON []byte) bool {
	if egressSet(manifestJSON)["*"] {
		return true
	}
	c, _ := readManifestCaps(manifestJSON)
	b, declared, ok := c.browser()
	return declared && (!ok || b.IsPublic())
}

// remoteServerHosts are the hosts of the manifest's remote MCP servers
// (agentry#910): network the release reaches, through the runner's bridge,
// as surely as through network.egress.
func (c manifestCaps) remoteServerHosts() []string {
	var out []string
	for _, srv := range c.MCPServers {
		if h := srv.RemoteHost(); h != "" {
			out = append(out, h)
		}
	}
	return out
}

// browserHosts are the hosts the manifest's browser line declares,
// lowercased, exact or "*.": none for a line that does not read.
func (c manifestCaps) browserHosts() []string {
	b, declared, ok := c.browser()
	if !declared || !ok {
		return nil
	}
	out := make([]string, 0, len(b.Hosts))
	for _, h := range b.Hosts {
		out = append(out, strings.ToLower(h))
	}
	return out
}

// readManifestCaps decodes the capabilities block. ok is false when the
// manifest is not JSON or has no capabilities block; an unreadable
// manifest reads as nothing declared, as before.
func readManifestCaps(manifestJSON []byte) (caps manifestCaps, ok bool) {
	var m struct {
		Capabilities *manifestCaps `json:"capabilities"`
	}
	if err := json.Unmarshal(manifestJSON, &m); err != nil || m.Capabilities == nil {
		return manifestCaps{}, false
	}
	return *m.Capabilities, true
}

// declaredCaps extracts a flat capability-token set from the manifest JSON.
func declaredCaps(manifestJSON []byte) map[string]bool {
	out := map[string]bool{}
	c, ok := readManifestCaps(manifestJSON)
	if !ok {
		return out
	}
	if (len(c.Network.Egress.Hosts) > 0 && !onlyNone(c.Network.Egress.Hosts)) || len(c.remoteServerHosts()) > 0 {
		out["network"] = true
	}
	if notNone(c.Filesystem.Write) {
		out["fs-write"] = true
	}
	if notNone(c.Filesystem.Read) {
		out["fs-read"] = true
	}
	if notNone(c.Exec) {
		out["exec"] = true
	}
	if len(c.Secrets) > 0 {
		out["env"] = true
	}
	// A target host is its own token, never "network": the runner makes
	// the session, so S6 still reads a script's own ssh as undeclared, and
	// a policy can name it in requireHumanReview.whenCapabilities.
	if len(c.TargetHosts) > 0 {
		out["targetHosts"] = true
	}
	// The browser is its own token too (plan browser-testing.md §5): it
	// reaches sites through the runner's browse proxy, never the tools
	// container's fetch, so it is not "network" and S6's bar for a
	// script's own call does not move.
	if _, declared, _ := c.browser(); declared {
		out["browser"] = true
	}
	return out
}

// notNone reports whether a filesystem/exec JSON value declares more than
// "none" (string "none" → false; object/list → true).
func notNone(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s != "none" && s != ""
	}
	return true // object or array form ⇒ a real capability
}

func onlyNone(egress []string) bool {
	for _, e := range egress {
		if e != "none" && e != "" {
			return false
		}
	}
	return true
}

// declarationOf is what the manifest declares, as S4's rating by
// declaration reads it (ruleset 0.4.0, agentry#893). An unreadable manifest
// declares nothing, so every capability family's hit is high.
func declarationOf(manifestJSON []byte) rules.Declared {
	d := rules.Declared{BaseCommands: manifest.BaseExecCommands()}
	c, ok := readManifestCaps(manifestJSON)
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
	for _, h := range c.remoteServerHosts() {
		d.ServerHosts = append(d.ServerHosts, strings.ToLower(h))
	}
	d.MCPServers = len(c.MCPServers) > 0
	// A browser's hosts are hosts the release declares (agentry#1198). A
	// line that does not read declares none here, the side this rating
	// fails toward.
	if b, declared, ok := c.browser(); declared && ok {
		d.BrowserAny = b.IsPublic()
		d.BrowserHosts = c.browserHosts()
	}
	d.Secrets = append([]string(nil), c.Secrets...)
	for _, srv := range c.MCPServers {
		d.Secrets = append(d.Secrets, srv.Secrets...)
	}
	d.FileWrite = notNone(c.Filesystem.Write)
	if notNone(c.Exec) {
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
