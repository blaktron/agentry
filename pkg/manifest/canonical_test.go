package manifest

import (
	"encoding/json"
	"testing"
)

// canonicalGolden is the expected canonical encoding of the §5.2
// normative example. Key order is lexicographic at every level and the
// empty dependencies block is pruned. This string is load-bearing: it
// pins the byte-stable form stored in agent_versions.manifest.
const canonicalGolden = `{"authors":[{"email":"jane@acme.example","name":"Jane Doe"}],"capabilities":{"dataAccess":["tickets"],"exec":"none","filesystem":{"read":"workspace","write":"none"},"network":{"egress":["api.pagerduty.com"]},"secrets":["PAGERDUTY_TOKEN"]},"entrypoints":{"skill":"SKILL.md"},"homepage":"https://acme.example/agents/incident-summarizer","kind":"skill","license":"Apache-2.0","name":"incident-summarizer","namespace":"acme","publish":{"channel":"stable","include":["agent.yaml","README.md","SKILL.md","prompts/**","LICENSE"]},"runtime":{"interfaces":["claude-skill"],"models":["claude-*"]},"schemaVersion":"1","summary":"Summarizes PagerDuty incidents into postmortem drafts","tags":["incident-response","summarization"],"version":"1.4.2"}`

func TestCanonicalJSONGolden(t *testing.T) {
	m := mustParse(t, normativeYAML)
	got, err := CanonicalJSON(m)
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	if string(got) != canonicalGolden {
		t.Fatalf("canonical form drifted:\n got: %s\nwant: %s", got, canonicalGolden)
	}
}

// TestCanonicalJSONDeterministic: reordering YAML keys must not change
// the canonical bytes.
func TestCanonicalJSONDeterministic(t *testing.T) {
	reordered := `publish:
  channel: stable
  include: [agent.yaml, README.md, SKILL.md, prompts/**, LICENSE]
version: 1.4.2
tags: [incident-response, summarization]
namespace: acme
name: incident-summarizer
license: Apache-2.0
kind: skill
summary: "Summarizes PagerDuty incidents into postmortem drafts"
schemaVersion: "1"
homepage: https://acme.example/agents/incident-summarizer
runtime:
  interfaces: [claude-skill]
  models: ["claude-*"]
entrypoints:
  skill: SKILL.md
dependencies:
  agents: []
capabilities:
  dataAccess: [tickets]
  secrets: [PAGERDUTY_TOKEN]
  exec: none
  filesystem:
    write: none
    read: workspace
  network:
    egress: [api.pagerduty.com]
authors:
  - name: Jane Doe
    email: jane@acme.example
`
	a, err := CanonicalJSON(mustParse(t, normativeYAML))
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	b, err := CanonicalJSON(mustParse(t, reordered))
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	if string(a) != string(b) {
		t.Fatalf("canonical output depends on YAML key order:\n a: %s\n b: %s", a, b)
	}
}

// TestCanonicalJSONPrunesUndeclared: optional fields that were not
// declared never appear.
func TestCanonicalJSONPrunesUndeclared(t *testing.T) {
	m := &Manifest{
		SchemaVersion: "1",
		Name:          "tiny",
		Namespace:     "acme",
		Kind:          KindPromptAgent,
		Version:       "0.1.0",
		Summary:       "Tiny prompt agent",
		Publish:       Publish{Include: []string{"agent.yaml", "prompts/**"}},
	}
	got, err := CanonicalJSON(m)
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	want := `{"kind":"prompt-agent","name":"tiny","namespace":"acme","publish":{"include":["agent.yaml","prompts/**"]},"schemaVersion":"1","summary":"Tiny prompt agent","version":"0.1.0"}`
	if string(got) != want {
		t.Fatalf("pruning wrong:\n got: %s\nwant: %s", got, want)
	}
}

// TestCanonicalJSONRoundTrip: the canonical form decodes back into an
// equivalent Manifest, including the union capability shapes.
func TestCanonicalJSONRoundTrip(t *testing.T) {
	m := mustParse(t, normativeYAML)
	raw, err := CanonicalJSON(m)
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	var back Manifest
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("round-trip decode: %v", err)
	}
	if back.Capabilities.Filesystem.Read.Mode != FSModeWorkspace ||
		back.Capabilities.Filesystem.Write.Mode != FSModeNone {
		t.Errorf("filesystem round-trip: %+v", back.Capabilities.Filesystem)
	}
	if !back.Capabilities.Exec.None {
		t.Errorf("exec round-trip: %+v", back.Capabilities.Exec)
	}
	if h := back.Capabilities.Network.Egress.Hosts; len(h) != 1 || h[0] != "api.pagerduty.com" {
		t.Errorf("egress round-trip: %+v", back.Capabilities.Network.Egress)
	}
	again, err := CanonicalJSON(&back)
	if err != nil {
		t.Fatalf("CanonicalJSON(round-tripped): %v", err)
	}
	if string(again) != string(raw) {
		t.Fatalf("canonical form not stable across round-trip:\n a: %s\n b: %s", raw, again)
	}
}

func TestCanonicalJSONNil(t *testing.T) {
	if _, err := CanonicalJSON(nil); err == nil {
		t.Fatalf("expected error for nil manifest")
	}
}
