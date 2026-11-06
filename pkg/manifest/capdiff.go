package manifest

import (
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"

	"github.com/blaktron/agentry/pkg/appserver"
)

// CapabilityDiff is the comparison between a capability contract a
// person accepted and the one a newer release declares. Each line is
// phrased for a human — "adds network egress to evil.example" — because
// the consent gate shows it verbatim.
//
// The rule is the one the CLI's install state and the desktop's Prepare
// apply on an update; the registry applies it to an account install, so
// a person is asked for the capability acceptance again only when the
// new release may do more than the one they accepted.
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

	// Filesystem, both directions. Write escalation is the usual case,
	// but a read widening is a widening too and gets the same
	// treatment.
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

	// Target hosts: one more is one more machine the agent may run any
	// command on, so it asks again.
	added, removed = diffSets(old.TargetHosts, next.TargetHosts)
	for _, h := range added {
		d.Widened = append(d.Widened, "asks for a target host when it runs, and can run any command on it: "+h)
	}
	for _, h := range removed {
		d.Narrowed = append(d.Narrowed, "no longer asks for a target host: "+h)
	}

	d.appendBrowserDiff(old.Browser, next.Browser)
	d.appendDesktopDiff(old.Desktop, next.Desktop)

	added, removed = diffSets(dataAccessNames(old.DataAccess), dataAccessNames(next.DataAccess))
	for _, s := range added {
		d.Widened = append(d.Widened, "adds data access: "+s)
	}
	for _, s := range removed {
		d.Narrowed = append(d.Narrowed, "drops data access: "+s)
	}

	// Declared MCP servers: a new server — or the same server at a
	// different pin, or a remote server at a different address — is new
	// tool surface and new supply chain, so it widens. A dropped one
	// narrows.
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

	// Shipped knowledge: a pack is text that enters the agent's
	// context, so one more asks again.
	added, removed = diffSets(old.Knowledge, next.Knowledge)
	for _, k := range added {
		d.Widened = append(d.Widened, "ships knowledge: "+k)
	}
	for _, k := range removed {
		d.Narrowed = append(d.Narrowed, "no longer ships knowledge: "+k)
	}

	d.appendPersistentDiff(old.Persistent, next.Persistent)
	d.appendSubagentDiff(old.Subagents, next.Subagents)

	return d
}

// appendPersistentDiff compares capabilities.persistent: a key newly
// declared widens, and so does one more name in a list key (a stored
// secret, a mail provider, an image server); the reverse narrows.
func (d *CapabilityDiff) appendPersistentDiff(old, next *Persistent) {
	for _, c := range persistentCapabilities {
		was, is := old.Declares(c.Key), next.Declares(c.Key)
		switch {
		case is && !was:
			d.Widened = append(d.Widened, "adds a persistent capability: "+c.Key+" ("+c.Words+")")
		case was && !is:
			d.Narrowed = append(d.Narrowed, "drops a persistent capability: "+c.Key)
		}
	}
	lists := []struct {
		what      string
		old, next []string
	}{
		{"stored secret", persistentList(old, "secrets"), persistentList(next, "secrets")},
		{"mail provider", persistentList(old, "mail"), persistentList(next, "mail")},
		{"image server", persistentList(old, "imageServers"), persistentList(next, "imageServers")},
	}
	for _, l := range lists {
		if len(l.old) == 0 || len(l.next) == 0 {
			continue // the key itself was added or dropped, said above
		}
		added, removed := diffSets(l.old, l.next)
		for _, n := range added {
			d.Widened = append(d.Widened, "adds a "+l.what+": "+n)
		}
		for _, n := range removed {
			d.Narrowed = append(d.Narrowed, "drops a "+l.what+": "+n)
		}
	}
}

func persistentList(p *Persistent, key string) []string {
	if p == nil {
		return nil
	}
	switch key {
	case "secrets":
		return p.Secrets
	case "mail":
		return p.Mail
	case "imageServers":
		return p.ImageServers
	}
	return nil
}

// appendSubagentDiff compares the subagents: one more is another
// QuickAgent the agent may start, so it widens, and so does a changed
// constraint, which may admit versions the person never agreed to (a
// tightened one is counted too, since a constraint's range cannot be
// compared in general). A dropped subagent narrows.
func (d *CapabilityDiff) appendSubagentDiff(old, next []AgentDependency) {
	oldBy := make(map[string]string, len(old))
	for _, a := range old {
		oldBy[a.Ref] = a.Version
	}
	nextBy := make(map[string]string, len(next))
	for _, a := range next {
		nextBy[a.Ref] = a.Version
	}
	added, removed := diffSets(slices.Sorted(maps.Keys(oldBy)), slices.Sorted(maps.Keys(nextBy)))
	for _, ref := range added {
		d.Widened = append(d.Widened, "adds a subagent: "+ref+" "+nextBy[ref])
	}
	for _, ref := range removed {
		d.Narrowed = append(d.Narrowed, "drops a subagent: "+ref)
	}
	for _, ref := range slices.Sorted(maps.Keys(nextBy)) {
		if was, ok := oldBy[ref]; ok && was != nextBy[ref] {
			d.Widened = append(d.Widened, "changes the versions it may run of subagent "+ref+": "+was+" → "+nextBy[ref])
		}
	}
}

// appendBrowserDiff records the browser line's change: a new line, a
// new site, a new host, a new secret the browser may type, or site
// scope to public widens, so an upgrade that does any of them asks
// again.
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
// env, a package server's own grants (the hosts its container may reach,
// the secrets it receives, the tools the model may call on it), its auth
// and scopes, or its OAuth sign-in. A package server's grants are the
// ones appendPackageServerOwnCaps compares at the same pin, so the line
// that asks about a new server names what a later widening would.
func describeNewServer(srv MCPServer) string {
	var parts []string
	if len(srv.Env) > 0 {
		var pairs []string
		for _, k := range slices.Sorted(maps.Keys(srv.Env)) {
			pairs = append(pairs, k+"="+srv.Env[k])
		}
		parts = append(parts, "env "+strings.Join(pairs, ", "))
	}
	if len(srv.Args) > 0 {
		parts = append(parts, "args "+strings.Join(srv.Args, " "))
	}
	if srv.IsRemote() {
		a := "auth " + string(srv.Auth)
		if len(srv.Scopes) > 0 {
			a += "; scopes " + strings.Join(srv.Scopes, ", ")
		}
		parts = append(parts, a)
	} else {
		parts = append(parts, describePackageServerOwnCaps(srv)...)
	}
	if srv.OAuth != nil {
		parts = append(parts, "OAuth sign-in: "+describeOAuth(srv.OAuth))
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, "; ") + ")"
}

// describePackageServerOwnCaps names a package server's own grants for its
// consent line: "*" is called out as unrestricted, and a server with no
// tool allowlist is given every tool it serves. Egress and secrets are
// left out when it declares none.
func describePackageServerOwnCaps(srv MCPServer) []string {
	var parts []string
	switch {
	case slices.Contains(srv.Egress, "*"):
		parts = append(parts, "UNRESTRICTED network egress (any host)")
	case len(srv.Egress) > 0:
		parts = append(parts, "network egress to "+strings.Join(slices.Sorted(slices.Values(srv.Egress)), ", "))
	}
	if len(srv.Secrets) > 0 {
		parts = append(parts, "secrets "+strings.Join(slices.Sorted(slices.Values(srv.Secrets)), ", "))
	}
	if len(srv.Tools) > 0 {
		parts = append(parts, "tools "+strings.Join(slices.Sorted(slices.Values(srv.Tools)), ", "))
	} else {
		parts = append(parts, "every tool it serves")
	}
	return parts
}

// describeArgs is a server's args as its consent line names them: the
// words in order, or "none".
func describeArgs(args []string) string {
	if len(args) == 0 {
		return "none"
	}
	return strings.Join(args, " ")
}

func describeOAuth(o *MCPOAuth) string {
	s := "issuer " + o.Issuer
	if len(o.Scopes) > 0 {
		s += "; scopes " + strings.Join(o.Scopes, ", ")
	}
	return s
}

// appendServerDiff compares one server present in both contracts: its
// plain env, a remote server's auth and scopes, a package server's
// OAuth sign-in.
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

	// A package server's args: any change starts a different command, so
	// it is asked again whichever way it goes, an argument dropped
	// included (it may have been the one that kept the server read-only).
	if !slices.Equal(prev.Args, next.Args) {
		d.Widened = append(d.Widened, fmt.Sprintf("changes args of MCP server %s: %s (was %s)", id, describeArgs(next.Args), describeArgs(prev.Args)))
	}

	// A remote server's auth: any change is a different sign-in, asked
	// again whichever way it goes.
	if prev.Auth != next.Auth {
		d.Widened = append(d.Widened, fmt.Sprintf("changes auth of MCP server %s: %s (was %s)", id, next.Auth, prev.Auth))
	}
	d.appendScopeDiff(id, prev.Scopes, next.Scopes)
	if next.IsRemote() {
		d.appendRemoteToolsAndSecret(id, prev, next)
	} else {
		d.appendPackageServerOwnCaps(id, prev, next)
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
// and what it is sent. Its tool allowlist bounds what the model reaches
// at a vendor that holds the person's account, so a tool added, or the
// list lifted (every tool the server serves), widens; and its one
// bearer secret is sent to the vendor, so a different name widens. A
// package server's are compared by appendPackageServerOwnCaps.
func (d *CapabilityDiff) appendRemoteToolsAndSecret(id string, prev, next MCPServer) {
	d.appendToolsDiff(id, prev.Tools, next.Tools)
	added, _ := diffSets(prev.Secrets, next.Secrets)
	for _, name := range added {
		d.Widened = append(d.Widened, fmt.Sprintf("sends secret %s to MCP server %s", name, id))
	}
}

// appendPackageServerOwnCaps compares what a package server's own
// container is given at the same pin: the hosts it may reach, the secrets
// it receives (by name: a secret's optional marking is not a capability)
// and the tools the model may call on it. The runner builds the server's
// grants from exactly these fields, so a release that keeps the pin and
// widens any of them asks again.
func (d *CapabilityDiff) appendPackageServerOwnCaps(id string, prev, next MCPServer) {
	added, removed := diffSets(prev.Egress, next.Egress)
	for _, h := range added {
		if h == "*" {
			d.Widened = append(d.Widened, "adds UNRESTRICTED network egress (any host) for MCP server "+id)
			continue
		}
		d.Widened = append(d.Widened, fmt.Sprintf("adds network egress to %s for MCP server %s", h, id))
	}
	for _, h := range removed {
		d.Narrowed = append(d.Narrowed, fmt.Sprintf("drops network egress to %s for MCP server %s", h, id))
	}
	added, removed = diffSets(prev.Secrets, next.Secrets)
	for _, name := range added {
		d.Widened = append(d.Widened, fmt.Sprintf("gives MCP server %s the secret %s", id, name))
	}
	for _, name := range removed {
		d.Narrowed = append(d.Narrowed, fmt.Sprintf("no longer gives MCP server %s the secret %s", id, name))
	}
	d.appendToolsDiff(id, prev.Tools, next.Tools)
}

// appendToolsDiff compares a server's tool allowlist: a tool added, or the
// list lifted (every tool the server serves), widens.
func (d *CapabilityDiff) appendToolsDiff(id string, prev, next []string) {
	switch {
	case len(prev) > 0 && len(next) == 0:
		d.Widened = append(d.Widened, fmt.Sprintf("lifts the tool allowlist of MCP server %s (every tool it serves)", id))
	case len(prev) == 0 && len(next) > 0:
		d.Narrowed = append(d.Narrowed, fmt.Sprintf("restricts MCP server %s to tools %s", id, strings.Join(next, ", ")))
	default:
		added, removed := diffSets(prev, next)
		for _, tool := range added {
			d.Widened = append(d.Widened, fmt.Sprintf("adds tool %s to MCP server %s", tool, id))
		}
		for _, tool := range removed {
			d.Narrowed = append(d.Narrowed, fmt.Sprintf("drops tool %s of MCP server %s", tool, id))
		}
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

// appendDesktopDiff records the change to the use of the person's own
// computer: a new line, a new application server, a tool narrowing lifted
// or a tool added to it, and computer use declared or moved from the
// applications' windows to the whole screen widen, so an upgrade that does
// any of them asks again. A removed server, a narrower tool list and a
// smaller scope narrow.
func (d *CapabilityDiff) appendDesktopDiff(old, next *Desktop) {
	switch {
	case old == nil && next == nil:
		return
	case next == nil:
		d.Narrowed = append(d.Narrowed, "no longer uses your computer")
		return
	}
	if old == nil {
		old = &Desktop{}
	}
	oldIDs, nextIDs := desktopIDs(old), desktopIDs(next)
	added, removed := diffSets(oldIDs, nextIDs)
	for _, id := range added {
		srv, _ := next.Server(id)
		d.Widened = append(d.Widened, "uses "+DescribeDesktopServer(srv))
	}
	for _, id := range removed {
		d.Narrowed = append(d.Narrowed, "no longer uses "+desktopApplication(id)+" on your computer")
	}
	for _, id := range nextIDs {
		prev, had := old.Server(id)
		if !had {
			continue
		}
		cur, _ := next.Server(id)
		d.appendDesktopToolsDiff(id, prev.Tools, cur.Tools)
	}
	switch {
	case old.ComputerUse == next.ComputerUse:
	case next.ComputerUse == "":
		d.Narrowed = append(d.Narrowed, "drops computer use on your computer")
	case old.ComputerUse == "":
		d.Widened = append(d.Widened, DescribeComputerUse(next))
	case next.ComputerUse == ComputerUseScreen:
		d.Widened = append(d.Widened, "lets computer use reach your whole screen (was: the applications' windows)")
	default:
		d.Narrowed = append(d.Narrowed, "keeps computer use to the applications' windows (was: your whole screen)")
	}
}

// appendDesktopToolsDiff compares one application server's tool
// narrowing: no narrowing is every tool the catalogue gives.
func (d *CapabilityDiff) appendDesktopToolsDiff(id string, prev, next []string) {
	app := desktopApplication(id)
	switch {
	case len(prev) > 0 && len(next) == 0:
		d.Widened = append(d.Widened, "lifts the tool narrowing of "+app+" on your computer (every tool the catalogue gives)")
	case len(prev) == 0 && len(next) > 0:
		d.Narrowed = append(d.Narrowed, "narrows "+app+" on your computer to tools "+strings.Join(next, ", "))
	default:
		added, removed := diffSets(prev, next)
		e, known := appserver.Builtin().Lookup(id)
		for _, tool := range added {
			line := "adds tool " + tool + " of " + app + " on your computer"
			if t, ok := e.Tool(tool); known && ok && t.Class == appserver.ClassExec {
				line += " (runs code inside " + app + ")"
			}
			d.Widened = append(d.Widened, line)
		}
		for _, tool := range removed {
			d.Narrowed = append(d.Narrowed, "drops tool "+tool+" of "+app+" on your computer")
		}
	}
}

func desktopIDs(d *Desktop) []string {
	out := make([]string, 0, len(d.Servers))
	for _, s := range d.Servers {
		out = append(out, s.ID)
	}
	return out
}
