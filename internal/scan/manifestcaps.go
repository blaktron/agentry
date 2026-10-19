package scan

import (
	"encoding/json"
	"strings"

	"github.com/blaktron/agentry/internal/manifestcaps"
	"github.com/blaktron/agentry/pkg/gatecases"
	"github.com/blaktron/agentry/pkg/manifest"
	"github.com/blaktron/agentry/pkg/rules"
)

// unrestrictedNetwork is the gate's WildcardEgress: "*" egress, or a
// browser on any public site. pkg/gatecases publishes the derivation, so a
// client restating the gate reads these two inputs exactly as this scanner
// does.
func unrestrictedNetwork(manifestJSON []byte) bool {
	return gatecases.UnrestrictedNetwork(manifestJSON)
}

// declaredCaps is the manifest's declared capability tokens as a set, from
// the derivation pkg/gatecases publishes.
func declaredCaps(manifestJSON []byte) map[string]bool {
	out := map[string]bool{}
	for _, c := range gatecases.DeclaredCapabilities(manifestJSON) {
		out[c] = true
	}
	return out
}

// declarationOf is what the manifest declares, as S4's rating by
// declaration reads it. An unreadable manifest
// declares nothing, so every capability family's hit is high.
func declarationOf(manifestJSON []byte) rules.Declared {
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
