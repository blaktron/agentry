package manifest

import (
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
)

// CapabilityDiff is the comparison between a capability contract a person
// accepted and the one a newer release declares (§11 "widened contract").
// Each line is phrased for a human — "adds network egress to evil.example"
// — because the consent gate shows it verbatim.
//
// The rule is the one the CLI's install state and the desktop's Prepare
// apply on an update; the registry applies it to an account install
// (agentry#448), so a person is asked for the capability acceptance again
// only when the new release may do more than the one they accepted.
type CapabilityDiff struct {
	// Widened lists strictly-more-permissive changes.
	Widened []string `json:"widened,omitempty"`
	// Narrowed lists strictly-less-permissive changes.
	Narrowed []string `json:"narrowed,omitempty"`
}

// HasWidened reports whether anything requires consent again.
func (d CapabilityDiff) HasWidened() bool { return len(d.Widened) > 0 }

// Empty reports an identical contract.
func (d CapabilityDiff) Empty() bool { return len(d.Widened) == 0 && len(d.Narrowed) == 0 }

// fsRank orders filesystem access declarations from least to most
// permissive. Explicit "none" ranks BELOW undeclared: a manifest that says
// nothing has told us nothing, which is worse than one that promises no
// access — but it is still better than one that asks for access.
var fsRank = map[FSMode]int{FSModeNone: 0, "": 1, FSModePaths: 2, FSModeWorkspace: 3}

// DiffCapabilities compares the previously accepted contract with the new
// one.
func DiffCapabilities(old, next Capabilities) CapabilityDiff {
	var d CapabilityDiff

	// Network egress: the canonical widening.
	added, removed := diffSets(old.Network.Egress.Hosts, next.Network.Egress.Hosts)
	for _, h := range added {
		if h == "*" {
			d.Widened = append(d.Widened, "adds UNRESTRICTED network egress (any host)")
			continue
		}
		d.Widened = append(d.Widened, "adds network egress to "+h)
	}
	for _, h := range removed {
		d.Narrowed = append(d.Narrowed, "drops network egress to "+h)
	}

	// Exec: none → commands, or a longer command list.
	added, removed = diffSets(old.Exec.Commands, next.Exec.Commands)
	for _, c := range added {
		if len(old.Exec.Commands) == 0 {
			d.Widened = append(d.Widened, "adds subprocess execution: "+c+" (previously none)")
			continue
		}
		d.Widened = append(d.Widened, "adds subprocess execution: "+c)
	}
	for _, c := range removed {
		d.Narrowed = append(d.Narrowed, "drops subprocess execution: "+c)
	}

	// Filesystem, both directions. Write escalation is the one §11 names,
	// but a read widening is a widening too and gets the same treatment.
	d.appendFSDiff("read", old.Filesystem.Read, next.Filesystem.Read)
	d.appendFSDiff("write", old.Filesystem.Write, next.Filesystem.Write)

	// Secrets: a new environment variable name is a new thing being asked
	// for.
	added, removed = diffSets(old.Secrets, next.Secrets)
	for _, s := range added {
		d.Widened = append(d.Widened, "asks for a new secret: "+s)
	}
	for _, s := range removed {
		d.Narrowed = append(d.Narrowed, "no longer asks for secret: "+s)
	}

	added, removed = diffSets(dataAccessNames(old.DataAccess), dataAccessNames(next.DataAccess))
	for _, s := range added {
		d.Widened = append(d.Widened, "adds data access: "+s)
	}
	for _, s := range removed {
		d.Narrowed = append(d.Narrowed, "drops data access: "+s)
	}

	// Declared MCP servers (RUNNER-PLAN-3): a new server — or the same
	// server at a different pin — is new tool surface and new supply
	// chain, so it widens. A dropped one narrows.
	oldSrv, newSrv := mcpServerEnvs(old.MCPServers), mcpServerEnvs(next.MCPServers)
	added, removed = diffSets(slices.Sorted(maps.Keys(oldSrv)), slices.Sorted(maps.Keys(newSrv)))
	for _, id := range added {
		line := "adds MCP server: " + id
		if env := newSrv[id]; len(env) > 0 {
			// A new server's env is part of what is being added.
			var pairs []string
			for _, k := range slices.Sorted(maps.Keys(env)) {
				pairs = append(pairs, k+"="+env[k])
			}
			line += " (env " + strings.Join(pairs, ", ") + ")"
		}
		d.Widened = append(d.Widened, line)
	}
	for _, id := range removed {
		d.Narrowed = append(d.Narrowed, "drops MCP server: "+id)
	}

	// A server's plain env: a new or changed value changes what the
	// server receives, so it widens and re-asks; a dropped key narrows.
	// Only servers present on both sides are compared — a new server is
	// already reported whole above.
	for _, id := range slices.Sorted(maps.Keys(newSrv)) {
		oldEnv, had := oldSrv[id]
		if !had {
			continue
		}
		newEnv := newSrv[id]
		for _, k := range slices.Sorted(maps.Keys(newEnv)) {
			if prev, had := oldEnv[k]; !had {
				d.Widened = append(d.Widened, fmt.Sprintf("changes env of MCP server %s: %s=%s", id, k, newEnv[k]))
			} else if prev != newEnv[k] {
				d.Widened = append(d.Widened, fmt.Sprintf("changes env of MCP server %s: %s=%s (was %s)", id, k, newEnv[k], prev))
			}
		}
		for _, k := range slices.Sorted(maps.Keys(oldEnv)) {
			if _, still := newEnv[k]; !still {
				d.Narrowed = append(d.Narrowed, fmt.Sprintf("drops env %s of MCP server %s", k, id))
			}
		}
	}

	// Shipped knowledge (plan knowledge.md §4.6): a pack is text that
	// enters the agent's context, so one more asks again.
	added, removed = diffSets(old.Knowledge, next.Knowledge)
	for _, k := range added {
		d.Widened = append(d.Widened, "ships knowledge: "+k)
	}
	for _, k := range removed {
		d.Narrowed = append(d.Narrowed, "no longer ships knowledge: "+k)
	}

	return d
}

// appendFSDiff records one filesystem direction's change.
func (d *CapabilityDiff) appendFSDiff(dir string, old, next FSAccess) {
	switch {
	case fsRank[next.Mode] > fsRank[old.Mode]:
		d.Widened = append(d.Widened, fmt.Sprintf("widens filesystem %s from %s to %s",
			dir, orUndeclared(old.Mode), describeFS(next)))
	case fsRank[next.Mode] < fsRank[old.Mode]:
		d.Narrowed = append(d.Narrowed, fmt.Sprintf("narrows filesystem %s from %s to %s",
			dir, orUndeclared(old.Mode), describeFS(next)))
	case next.Mode == FSModePaths:
		added, removed := diffSets(old.Paths, next.Paths)
		for _, p := range added {
			d.Widened = append(d.Widened, fmt.Sprintf("adds filesystem %s path: %s", dir, p))
		}
		for _, p := range removed {
			d.Narrowed = append(d.Narrowed, fmt.Sprintf("drops filesystem %s path: %s", dir, p))
		}
	}
}

func describeFS(a FSAccess) string {
	if a.Mode == FSModePaths && len(a.Paths) > 0 {
		return "paths " + strings.Join(a.Paths, ", ")
	}
	return orUndeclared(a.Mode)
}

func orUndeclared(mode FSMode) string {
	if mode == "" {
		return "undeclared"
	}
	return string(mode)
}

func dataAccessNames(in []DataAccess) []string {
	out := make([]string, 0, len(in))
	for _, d := range in {
		out = append(out, string(d))
	}
	return out
}

// mcpServerEnvs keys each declared server by "source:package@version" —
// the identity the consent gate compares — with its plain env (nil when
// it declares none).
func mcpServerEnvs(in []MCPServer) map[string]map[string]string {
	out := make(map[string]map[string]string, len(in))
	for _, srv := range in {
		out[srv.SourceID()+"@"+srv.Version] = srv.Env
	}
	return out
}

// diffSets returns the sorted elements added to and removed from a list.
func diffSets(old, next []string) (added, removed []string) {
	for _, v := range next {
		if !slices.Contains(old, v) {
			added = append(added, v)
		}
	}
	for _, v := range old {
		if !slices.Contains(next, v) {
			removed = append(removed, v)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}
