package scan

import (
	"encoding/json"
	"slices"
	"sort"
	"strings"

	"github.com/blaktron/agentry/pkg/manifest"
)

// A persistent release's subagents are other releases it may start as runs
// of their own. The pipeline resolves each one against the registry before
// the stages run (Pipeline.resolveSubagents), and S7, the stage that reads
// what a release depends on, reports each one that does not resolve: a
// subagent that is not in the registry, is quarantined, blocked or retired,
// is private outside the release's organization, has no published version
// its constraint admits, or whose matching version does not run on its own
// (autonomous) or is itself persistent. Such a version is held for a person.
// The report lists every subagent with the version it resolved to and that
// version's reach, so a reader of the parent sees the whole of what it can
// start.

// scannerSubagentUnresolved is S7's finding for a subagent that does not
// resolve: high, so the version goes to a person, and weighed at medium by a
// rescan (rescanSeverity), so a subagent that is quarantined later does not
// move the parent's own verdict.
const scannerSubagentUnresolved = "S7/subagent-unresolved"

// subagentRecordKey is where S7's record of the subagents sits in its stage
// row's detail.
const subagentRecordKey = "subagents"

// Subagent is one subagent as the scan resolved it.
type Subagent struct {
	// Ref is the subagent's namespace/name.
	Ref string `json:"ref"`
	// Constraint is the semver constraint the release declares.
	Constraint string `json:"constraint"`
	// Why is the release's reason for it.
	Why string `json:"why,omitempty"`
	// Version is the newest published version the constraint admits that
	// may be a subagent; empty when none does.
	Version string `json:"version,omitempty"`
	// Problem says why the subagent does not resolve; empty when it does.
	Problem string `json:"problem,omitempty"`
	// Reach is what the resolved version may do; nil when none resolved.
	Reach *SubagentReach `json:"reach,omitempty"`
}

// SubagentReach is what a subagent's resolved version declares, in the
// terms its own consent lists: where it may connect, the servers it uses,
// the programs it may run and the secrets it asks for.
type SubagentReach struct {
	// Egress are the hosts it may reach ("*" for any), its own and its
	// servers', sorted; none for a release that reaches none.
	Egress []string `json:"egress,omitempty"`
	// Servers are its declared MCP servers by source id, sorted.
	Servers []string `json:"servers,omitempty"`
	// Exec are the commands it may run, sorted.
	Exec []string `json:"exec,omitempty"`
	// Secrets are the secrets it asks for, its own and its servers', sorted.
	Secrets []string `json:"secrets,omitempty"`
	// Browser is its browser's scope, "site" or "public"; empty for none.
	Browser string `json:"browser,omitempty"`
	// TargetHosts is how many target hosts it asks for.
	TargetHosts int `json:"targetHosts,omitempty"`
}

// reachOf is what m declares, as a SubagentReach.
func reachOf(m *manifest.Manifest) *SubagentReach {
	c := m.Capabilities
	r := &SubagentReach{TargetHosts: len(c.TargetHosts)}
	egress := map[string]bool{}
	for _, h := range c.Network.Egress.Hosts {
		if h != "" && h != "none" {
			egress[strings.ToLower(h)] = true
		}
	}
	secrets := map[string]bool{}
	for _, s := range c.Secrets {
		secrets[s] = true
	}
	for _, srv := range c.MCPServers {
		r.Servers = append(r.Servers, srv.SourceID())
		for _, h := range srv.Egress {
			egress[strings.ToLower(h)] = true
		}
		if h := srv.RemoteHost(); h != "" {
			egress[strings.ToLower(h)] = true
		}
		for _, s := range srv.Secrets {
			secrets[s] = true
		}
	}
	r.Egress = sortedSet(egress)
	r.Secrets = sortedSet(secrets)
	sort.Strings(r.Servers)
	r.Exec = slices.Sorted(slices.Values(c.Exec.Commands))
	if b := c.Browser; b != nil {
		r.Browser = string(manifest.BrowserScopeSite)
		if b.IsPublic() {
			r.Browser = string(manifest.BrowserScopePublic)
		}
	}
	return r
}

// subagentProblem says why the release m, at the version the scan picked,
// cannot be a subagent; empty when it can.
func subagentProblem(m *manifest.Manifest) string {
	switch {
	case m.IsPersistent():
		return "it is itself a persistent agent, and a subagent runs once and ends"
	case !m.Supports(manifest.ModeAutonomous):
		return "it does not run on its own (its modes do not include autonomous)"
	}
	return ""
}

// subagentFindings is S7's report of the subagents that do not resolve, one
// finding each, in the order the release declares them.
func subagentFindings(subs []Subagent) []Finding {
	var out []Finding
	for _, s := range subs {
		if s.Problem == "" {
			continue
		}
		out = append(out, Finding{
			Scanner: scannerSubagentUnresolved, Severity: SevHigh, Confidence: ConfHigh,
			Title:    "Subagent " + s.Ref + " " + s.Constraint + " does not resolve: " + s.Problem,
			FilePath: "agent.yaml",
			Detail:   map[string]any{"ref": s.Ref, "constraint": s.Constraint, "problem": s.Problem},
			Taxonomy: []string{"LLM03", "ASI04"},
		})
	}
	return out
}

// DecodeSubagentRecord reads S7's record of the subagents out of its stage
// row's detail into into (a slice of Subagent, or the API's shape of it); a
// detail without one leaves into as it is.
func DecodeSubagentRecord(detail []byte, into any) error {
	var d map[string]json.RawMessage
	if err := json.Unmarshal(detail, &d); err != nil {
		return err
	}
	raw, ok := d[subagentRecordKey]
	if !ok {
		return nil
	}
	return json.Unmarshal(raw, into)
}
