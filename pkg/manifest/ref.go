package manifest

import (
	"fmt"
	"strings"
)

// Ref is a parsed "ns/name[@range]" reference — the form the CLI, the
// resolve API (§9.4), and install snippets all speak.
type Ref struct {
	Namespace string
	Name      string
	Range     string // "" = latest on channel
	Channel   string // stable | beta (from @beta shorthand or explicit param)
}

// ParseRef parses "ns/name", "ns/name@^1.2", "ns/name@1.2.3", "ns/name@beta".
func ParseRef(ref string) (Ref, error) {
	path, rng, _ := strings.Cut(ref, "@")
	ns, name, ok := strings.Cut(path, "/")
	if !ok || ns == "" || name == "" {
		return Ref{}, fmt.Errorf("manifest: invalid ref %q (want ns/name[@range])", ref)
	}
	out := Ref{Namespace: ns, Name: name, Range: rng, Channel: "stable"}
	switch rng {
	case "beta", "stable":
		out.Channel = rng
		out.Range = ""
	}
	return out, nil
}
