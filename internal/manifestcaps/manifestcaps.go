// Package manifestcaps decodes the capabilities block of a canonical
// manifest's JSON the one way every reader of it in the registry does: the
// scanner's stages, the gate's inputs, and the derivations pkg/gatecases
// publishes for clients that restate the gate.
package manifestcaps

import (
	"encoding/json"
	"strings"

	"github.com/blaktron/agentry/pkg/manifest"
)

// Caps is the capabilities block of the canonical manifest JSON, decoded
// once. Egress is pkg/manifest's own union type, because the canonical form
// carries `egress: none` as the JSON string "none" and a host list as an
// array; decoding it into a []string failed the whole decode, and every
// capability of such a manifest read as undeclared to S6, S9, the gate and
// namespace policy.
type Caps struct {
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
	// Browser is kept raw and read by Browser(), so a value of an odd
	// shape cannot fail the whole decode and leave every other capability
	// undeclared.
	BrowserLine json.RawMessage `json:"browser"`
}

// Read decodes the capabilities block. ok is false when the manifest is not
// JSON or has no capabilities block; an unreadable manifest reads as nothing
// declared.
func Read(manifestJSON []byte) (caps Caps, ok bool) {
	var m struct {
		Capabilities *Caps `json:"capabilities"`
	}
	if err := json.Unmarshal(manifestJSON, &m); err != nil || m.Capabilities == nil {
		return Caps{}, false
	}
	return *m.Capabilities, true
}

// Browser reads the browser line. declared is false when there is none; ok
// is false when there is one that does not decode, which the callers read
// the strict way: a browser, on any public site.
func (c Caps) Browser() (b *manifest.Browser, declared, ok bool) {
	if len(c.BrowserLine) == 0 || string(c.BrowserLine) == "null" {
		return nil, false, true
	}
	if err := json.Unmarshal(c.BrowserLine, &b); err != nil || b == nil {
		return nil, true, false
	}
	return b, true, true
}

// RemoteServerHosts are the hosts of the manifest's remote MCP servers:
// network the release reaches, through the runner's bridge, as surely as
// through network.egress.
func (c Caps) RemoteServerHosts() []string {
	var out []string
	for _, srv := range c.MCPServers {
		if h := srv.RemoteHost(); h != "" {
			out = append(out, h)
		}
	}
	return out
}

// ServerEgress maps each host a declared package MCP server's own egress
// names (lowercased, "*" kept) to the server that names it first. It is
// network the release reaches, from the server's container rather than the
// agent's, so it counts for policy and S9 and never marks an agent script's
// own host as declared (S6 does not read it).
func (c Caps) ServerEgress() map[string]string {
	out := map[string]string{}
	for _, srv := range c.MCPServers {
		if srv.IsRemote() {
			continue
		}
		for _, h := range srv.Egress {
			h = strings.ToLower(strings.TrimSpace(h))
			if h == "" || h == "none" {
				continue
			}
			if _, seen := out[h]; !seen {
				out[h] = srv.SourceID() + "@" + srv.Version
			}
		}
	}
	return out
}

// BrowserHosts are the hosts the manifest's browser line declares,
// lowercased, exact or "*.": none for a line that does not read.
func (c Caps) BrowserHosts() []string {
	b, declared, ok := c.Browser()
	if !declared || !ok {
		return nil
	}
	out := make([]string, 0, len(b.Hosts))
	for _, h := range b.Hosts {
		out = append(out, strings.ToLower(h))
	}
	return out
}

// NotNone reports whether a filesystem or exec JSON value declares more
// than "none" (the string "none" is false; an object or a list is true).
func NotNone(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s != "none" && s != ""
	}
	return true // object or array form: a real capability
}

// OnlyNone reports whether an egress list names nothing but "none".
func OnlyNone(egress []string) bool {
	for _, e := range egress {
		if e != "none" && e != "" {
			return false
		}
	}
	return true
}
