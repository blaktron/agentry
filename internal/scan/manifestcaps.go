package scan

import "encoding/json"

// declaredCaps extracts a flat capability-token set from the manifest JSON.
func declaredCaps(manifestJSON []byte) map[string]bool {
	out := map[string]bool{}
	var m struct {
		Capabilities struct {
			Network struct {
				Egress []string `json:"egress"`
			} `json:"network"`
			Filesystem struct {
				Read  json.RawMessage `json:"read"`
				Write json.RawMessage `json:"write"`
			} `json:"filesystem"`
			Exec    json.RawMessage `json:"exec"`
			Secrets []string        `json:"secrets"`
		} `json:"capabilities"`
	}
	if err := json.Unmarshal(manifestJSON, &m); err != nil {
		return out
	}
	if len(m.Capabilities.Network.Egress) > 0 && !onlyNone(m.Capabilities.Network.Egress) {
		out["network"] = true
	}
	if notNone(m.Capabilities.Filesystem.Write) {
		out["fs-write"] = true
	}
	if notNone(m.Capabilities.Filesystem.Read) {
		out["fs-read"] = true
	}
	if notNone(m.Capabilities.Exec) {
		out["exec"] = true
	}
	if len(m.Capabilities.Secrets) > 0 {
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
