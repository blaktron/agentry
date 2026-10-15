package scan

import (
	"strings"
	"testing"

	"github.com/blaktron/agentry/internal/registry"
)

// TestAPackageServersEgressIsNetwork: a declared package MCP server's own
// egress is network the release reaches, for namespace policy and S9, and
// its hosts never become the agent's own declared egress.
func TestAPackageServersEgressIsNetwork(t *testing.T) {
	server := func(egress string) string {
		return "  network:\n    egress: none\n  mcpServers:\n    - npm: \"@acme/osv-mcp\"\n      version: \"1.2.3\"\n      egress: [" + egress + "]\n"
	}
	cur := canonicalManifest(t, server("api.osv.dev"))
	if !declaredCaps(cur)["network"] {
		t.Fatalf("a package server's egress does not declare network: %v", declaredCaps(cur))
	}
	pol, err := ParsePolicy([]byte(`{"blockedCapabilities":["network"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if issues := CheckSubmissionPolicy(pol, registry.PolicySubmission{ManifestJSON: cur}); len(issues) != 1 {
		t.Fatalf("blockedCapabilities network missed a package server's egress: %v", issues)
	}
	if egressSet(cur)["api.osv.dev"] {
		t.Fatal("a server's egress became the agent's own declared egress")
	}
	if d := declarationOf(cur); len(d.Egress) != 0 {
		t.Fatalf("S6's declaration counts a server's egress as the agent's: %+v", d.Egress)
	}

	newEgress := func(prev, next []byte) map[string]Severity {
		out := map[string]Severity{}
		for _, f := range s9ManifestDiff(&Input{PrevManifestJSON: prev, ManifestJSON: next}) {
			if f.Scanner == "S9/new-egress" {
				out[f.Detail["host"].(string)] = f.Severity
				if !strings.Contains(f.Title, "@acme/osv-mcp@1.2.3") && f.Detail["mcpServer"] != nil {
					t.Errorf("finding does not name the server: %+v", f)
				}
			}
		}
		return out
	}
	none := canonicalManifest(t, "  network:\n    egress: none\n")
	if got := newEgress(none, cur); len(got) != 1 || got["api.osv.dev"] != SevLow {
		t.Fatalf("a new server egress host: %v, want api.osv.dev low", got)
	}
	if got := newEgress(cur, canonicalManifest(t, server("api.osv.dev, evil.example"))); len(got) != 1 || got["evil.example"] != SevLow {
		t.Fatalf("a host added to the same server: %v, want evil.example low", got)
	}
	if got := newEgress(cur, canonicalManifest(t, server(`api.osv.dev, "*"`))); got["*"] != SevMedium {
		t.Fatalf(`"*" on a server: %v, want medium`, got)
	}
	if got := newEgress(cur, cur); len(got) != 0 {
		t.Fatalf("an unchanged server egress is new: %v", got)
	}
	// A host the previous release reached through network.egress is not new.
	agentEgress := canonicalManifest(t, "  network:\n    egress: [api.osv.dev]\n")
	if got := newEgress(agentEgress, cur); len(got) != 0 {
		t.Fatalf("a host the agent already reached: %v", got)
	}
}
