package scan

import (
	"encoding/json"

	"github.com/blaktron/agentry/pkg/manifest"
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
	Exec       json.RawMessage      `json:"exec"`
	Secrets    []string             `json:"secrets"`
	MCPServers []manifest.MCPServer `json:"mcpServers"`
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
