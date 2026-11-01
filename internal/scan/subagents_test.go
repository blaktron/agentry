package scan

import (
	"context"
	"slices"
	"strings"
	"testing"

	storegen "github.com/blaktron/agentry/internal/store/gen"
	"github.com/blaktron/agentry/pkg/manifest"
)

// A subagent's reach is what its own consent would list: its hosts and its
// servers' (a remote server's host included), its servers, commands and
// secrets, its browser's scope and its target hosts.
func TestASubagentsReachIsWhatItsVersionDeclares(t *testing.T) {
	m, err := manifest.Parse([]byte(`schemaVersion: "2"
name: sum
namespace: acme
version: 1.0.0
summary: s
modes: [autonomous]
intake:
  - id: site
    prompt: Which site?
    type: url
  - id: box
    prompt: Which machine?
    type: host
capabilities:
  network:
    egress: [API.example.com]
  exec:
    commands: [pdftotext, curl]
  secrets: [SUM_KEY]
  targetHosts: [box]
  browser:
    sites: [site]
  mcpServers:
    - npm: "@acme/notes-mcp"
      version: 1.0.0
      egress: [notes.example.com]
      secrets: [NOTES_TOKEN]
    - url: https://mcp.example.org/mcp
      auth: none
publish:
  include: [agent.yaml]
`))
	if err != nil {
		t.Fatal(err)
	}
	r := reachOf(m)
	if !slices.Equal(r.Egress, []string{"api.example.com", "mcp.example.org", "notes.example.com"}) ||
		!slices.Equal(r.Servers, []string{"npm:@acme/notes-mcp", "url:https://mcp.example.org/mcp"}) ||
		!slices.Equal(r.Exec, []string{"curl", "pdftotext"}) || !slices.Equal(r.Secrets, []string{"NOTES_TOKEN", "SUM_KEY"}) ||
		r.Browser != "site" || r.TargetHosts != 1 {
		t.Fatalf("reach = %+v", r)
	}
	if subagentProblem(m) != "" {
		t.Fatalf("an autonomous release cannot be a subagent: %q", subagentProblem(m))
	}
	m.Modes = []manifest.Mode{manifest.ModeInteractive}
	if !strings.Contains(subagentProblem(m), "does not run on its own") {
		t.Fatalf("an interactive-only release: %q", subagentProblem(m))
	}
	m.Modes = []manifest.Mode{manifest.ModeAutonomous, manifest.ModePersistent}
	if !strings.Contains(subagentProblem(m), "itself a persistent agent") {
		t.Fatalf("a persistent release: %q", subagentProblem(m))
	}
}

// Each subagent that does not resolve is one high finding naming it, which
// a rescan weighs at medium: a subagent's later quarantine does not pull the
// parent.
func TestAnUnresolvedSubagentHoldsTheVersionAndNeverPullsIt(t *testing.T) {
	got := subagentFindings([]Subagent{
		{Ref: "acme/sum", Constraint: "^1.0.0", Version: "1.2.0", Reach: &SubagentReach{}},
		{Ref: "acme/ghost", Constraint: "^1.0.0", Problem: "it is not in the registry"},
	})
	if len(got) != 1 || got[0].Scanner != scannerSubagentUnresolved || got[0].Severity != SevHigh ||
		got[0].Detail["ref"] != "acme/ghost" || !strings.Contains(got[0].Title, "acme/ghost ^1.0.0 does not resolve: it is not in the registry") {
		t.Fatalf("findings = %+v", got)
	}
	if rescanSeverity(got[0]) != SevMedium {
		t.Fatalf("a rescan weighs it %s", rescanSeverity(got[0]))
	}
}

// Dependencies that do not decode are one subagent that does not resolve,
// read before the registry is asked anything.
func TestSubagentsThatDoNotReadDoNotResolve(t *testing.T) {
	got, err := resolveSubagents(context.Background(), nil, storegen.GetAgentByIDRow{},
		[]byte(`{"modes":["persistent"],"dependencies":{"agents":"everything"}}`))
	if err != nil || len(got) != 1 || got[0].Problem == "" {
		t.Fatalf("resolveSubagents = %+v, %v", got, err)
	}
	if got, err := resolveSubagents(context.Background(), nil, storegen.GetAgentByIDRow{},
		[]byte(`{"modes":["autonomous"],"dependencies":{"agents":[{"ref":"acme/sum"}]}}`)); err != nil || len(got) != 0 {
		t.Fatalf("an autonomous release's dependencies resolve to %+v, %v", got, err)
	}
}
