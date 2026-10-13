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

	// Target hosts (plan runtime-hosts.md §8): one more is one more machine
	// the agent may run any command on, so it asks again.
	added, removed = diffSets(old.TargetHosts, next.TargetHosts)
	for _, h := range added {
		d.Widened = append(d.Widened, "asks for a target host when it runs, and can run any command on it: "+h)
	}
	for _, h := range removed {
		d.Narrowed = append(d.Narrowed, "no longer asks for a target host: "+h)
	}

	d.appendBrowserDiff(old.Browser, next.Browser)

	added, removed = diffSets(dataAccessNames(old.DataAccess), dataAccessNames(next.DataAccess))
	for _, s := range added {
		d.Widened = append(d.Widened, "adds data access: "+s)
	}
	for _, s := range removed {
		d.Narrowed = append(d.Narrowed, "drops data access: "+s)
	}

	// Declared MCP servers (RUNNER-PLAN-3): a new server — or the same
	// server at a different pin, or a remote server at a different
	// address — is new tool surface and new supply chain, so it widens. A
	// dropped one narrows.
	oldSrv, newSrv := mcpServersByIdentity(old.MCPServers), mcpServersByIdentity(next.MCPServers)
	added, removed = diffSets(slices.Sorted(maps.Keys(oldSrv)), slices.Sorted(maps.Keys(newSrv)))
	for _, id := range added {
		d.Widened = append(d.Widened, "adds MCP server: "+id+describeNewServer(newSrv[id]))
	}
	for _, id := range removed {
		d.Narrowed = append(d.Narrowed, "drops MCP server: "+id)
	}

	// Servers present on both sides: what each receives and how it is
	// signed in to. A new server is already reported whole above.
	for _, id := range slices.Sorted(maps.Keys(newSrv)) {
		prev, had := oldSrv[id]
		if !had {
			continue
		}
		d.appendServerDiff(id, prev, newSrv[id])
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

// appendBrowserDiff records the browser line's change (plan
// browser-testing.md invariant 8): a new line, a new site, a new host, a
// new secret the browser may type, or site scope to public widens, so an
// upgrade that does any of them asks again.
func (d *CapabilityDiff) appendBrowserDiff(old, next *Browser) {
	switch {
	case old == nil && next == nil:
		return
	case old == nil:
		d.Widened = append(d.Widened, "adds a web browser ("+describeBrowser(next)+")")
		for _, sec := range next.Secrets {
			d.Widened = append(d.Widened, "lets the browser type the secret "+sec+" into the site")
		}
		return
	case next == nil:
		d.Narrowed = append(d.Narrowed, "drops the web browser")
		return
	}
	if !old.IsPublic() && next.IsPublic() {
		d.Widened = append(d.Widened, "lets the browser reach ANY public site (was: the named sites and hosts)")
	}
	if old.IsPublic() && !next.IsPublic() {
		d.Narrowed = append(d.Narrowed, "keeps the browser to the named sites and hosts (was: any public site)")
	}
	// A site or host is new reach only where the old line was held to its
	// sites: any public site already covered it.
	reach := func(line string) {
		if old.IsPublic() {
			return
		}
		d.Widened = append(d.Widened, line)
	}
	added, removed := diffSets(old.Sites, next.Sites)
	for _, id := range added {
		reach("asks for a site for the browser when it runs: " + id)
	}
	for _, id := range removed {
		d.Narrowed = append(d.Narrowed, "no longer asks for a site for the browser: "+id)
	}
	added, removed = diffSets(lowerAll(old.Hosts), lowerAll(next.Hosts))
	for _, h := range added {
		reach("lets the browser reach " + h)
	}
	for _, h := range removed {
		d.Narrowed = append(d.Narrowed, "no longer lets the browser reach "+h)
	}
	added, removed = diffSets(old.Secrets, next.Secrets)
	for _, sec := range added {
		d.Widened = append(d.Widened, "lets the browser type the secret "+sec+" into the site")
	}
	for _, sec := range removed {
		d.Narrowed = append(d.Narrowed, "no longer lets the browser type the secret "+sec)
	}
}

// describeBrowser says where a new browser line may go, for its consent
// line.
func describeBrowser(b *Browser) string {
	if b.IsPublic() {
		return "any public site"
	}
	var parts []string
	if len(b.Sites) > 0 {
		parts = append(parts, "the site you name for "+strings.Join(b.Sites, ", "))
	}
	if len(b.Hosts) > 0 {
		parts = append(parts, strings.Join(lowerAll(b.Hosts), ", "))
	}
	return strings.Join(parts, "; ")
}

func lowerAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.ToLower(s)
	}
	return out
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

// mcpServersByIdentity keys each declared server by the identity the
// consent gate compares: "source:package@version" for a package server,
// "url:<address>" for a remote one.
func mcpServersByIdentity(in []MCPServer) map[string]MCPServer {
	out := make(map[string]MCPServer, len(in))
	for _, srv := range in {
		id := srv.SourceID()
		if !srv.IsRemote() {
			id += "@" + srv.Version
		}
		out[id] = srv
	}
	return out
}

// describeNewServer is what a new server brings beside its identity: its
// env, its auth and scopes, or its OAuth sign-in.
func describeNewServer(srv MCPServer) string {
	var parts []string
	if len(srv.Env) > 0 {
		var pairs []string
		for _, k := range slices.Sorted(maps.Keys(srv.Env)) {
			pairs = append(pairs, k+"="+srv.Env[k])
		}
		parts = append(parts, "env "+strings.Join(pairs, ", "))
	}
	if srv.IsRemote() {
		a := "auth " + string(srv.Auth)
		if len(srv.Scopes) > 0 {
			a += "; scopes " + strings.Join(srv.Scopes, ", ")
		}
		parts = append(parts, a)
	}
	if srv.OAuth != nil {
		parts = append(parts, "OAuth sign-in: "+describeOAuth(srv.OAuth))
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, "; ") + ")"
}

func describeOAuth(o *MCPOAuth) string {
	s := "issuer " + o.Issuer
	if len(o.Scopes) > 0 {
		s += "; scopes " + strings.Join(o.Scopes, ", ")
	}
	return s
}

// appendServerDiff compares one server present in both contracts: its
// plain env, a remote server's auth and scopes, a package server's OAuth
// sign-in (agentry#910).
func (d *CapabilityDiff) appendServerDiff(id string, prev, next MCPServer) {
	// A server's plain env: a new or changed value changes what the
	// server receives, so it widens and re-asks; a dropped key narrows.
	for _, k := range slices.Sorted(maps.Keys(next.Env)) {
		if was, had := prev.Env[k]; !had {
			d.Widened = append(d.Widened, fmt.Sprintf("changes env of MCP server %s: %s=%s", id, k, next.Env[k]))
		} else if was != next.Env[k] {
			d.Widened = append(d.Widened, fmt.Sprintf("changes env of MCP server %s: %s=%s (was %s)", id, k, next.Env[k], was))
		}
	}
	for _, k := range slices.Sorted(maps.Keys(prev.Env)) {
		if _, still := next.Env[k]; !still {
			d.Narrowed = append(d.Narrowed, fmt.Sprintf("drops env %s of MCP server %s", k, id))
		}
	}

	// A remote server's auth: any change is a different sign-in, asked
	// again whichever way it goes.
	if prev.Auth != next.Auth {
		d.Widened = append(d.Widened, fmt.Sprintf("changes auth of MCP server %s: %s (was %s)", id, next.Auth, prev.Auth))
	}
	d.appendScopeDiff(id, prev.Scopes, next.Scopes)
	if next.IsRemote() {
		d.appendRemoteToolsAndSecret(id, prev, next)
	}

	// A package server's OAuth sign-in.
	switch {
	case prev.OAuth == nil && next.OAuth != nil:
		d.Widened = append(d.Widened, fmt.Sprintf("adds an OAuth sign-in to MCP server %s (%s)", id, describeOAuth(next.OAuth)))
	case prev.OAuth != nil && next.OAuth == nil:
		d.Narrowed = append(d.Narrowed, "drops the OAuth sign-in of MCP server "+id)
	case prev.OAuth != nil && next.OAuth != nil:
		if prev.OAuth.Issuer != next.OAuth.Issuer {
			d.Widened = append(d.Widened, fmt.Sprintf("changes the issuer of MCP server %s: %s (was %s)", id, next.OAuth.Issuer, prev.OAuth.Issuer))
		}
		d.appendScopeDiff(id, prev.OAuth.Scopes, next.OAuth.Scopes)
		if !slices.Equal(prev.OAuth.Files, next.OAuth.Files) || !maps.Equal(prev.OAuth.Env, next.OAuth.Env) {
			d.Widened = append(d.Widened, fmt.Sprintf("changes how MCP server %s receives its token (its oauth files or env)", id))
		}
	}
}

// appendRemoteToolsAndSecret compares what a remote server may be asked
// and what it is sent. Its tool allowlist bounds what the model reaches at
// a vendor that holds the person's account, so a tool added, or the list
// lifted (every tool the server serves), widens; and its one bearer secret
// is sent to the vendor, so a different name widens. The same fields of a
// package server are agentry#527's.
func (d *CapabilityDiff) appendRemoteToolsAndSecret(id string, prev, next MCPServer) {
	switch {
	case len(prev.Tools) > 0 && len(next.Tools) == 0:
		d.Widened = append(d.Widened, fmt.Sprintf("lifts the tool allowlist of MCP server %s (every tool it serves)", id))
	case len(prev.Tools) == 0 && len(next.Tools) > 0:
		d.Narrowed = append(d.Narrowed, fmt.Sprintf("restricts MCP server %s to tools %s", id, strings.Join(next.Tools, ", ")))
	default:
		added, removed := diffSets(prev.Tools, next.Tools)
		for _, tool := range added {
			d.Widened = append(d.Widened, fmt.Sprintf("adds tool %s to MCP server %s", tool, id))
		}
		for _, tool := range removed {
			d.Narrowed = append(d.Narrowed, fmt.Sprintf("drops tool %s of MCP server %s", tool, id))
		}
	}
	added, _ := diffSets(prev.Secrets, next.Secrets)
	for _, name := range added {
		d.Widened = append(d.Widened, fmt.Sprintf("sends secret %s to MCP server %s", name, id))
	}
}

// appendScopeDiff: a new scope asks for more of the person's account, so
// it widens; a dropped one narrows.
func (d *CapabilityDiff) appendScopeDiff(id string, prev, next []string) {
	added, removed := diffSets(prev, next)
	for _, sc := range added {
		d.Widened = append(d.Widened, fmt.Sprintf("adds scope %s to MCP server %s", sc, id))
	}
	for _, sc := range removed {
		d.Narrowed = append(d.Narrowed, fmt.Sprintf("drops scope %s of MCP server %s", sc, id))
	}
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
