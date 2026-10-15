package scan

import (
	"strings"
	"testing"

	"github.com/blaktron/agentry/internal/registry"
)

// A remote MCP server's host is network the release reaches: it declares
// the network capability to the gate and to namespace
// policy, and an update that adds one is S9's low new-egress finding, as a
// new network.egress host is.
func TestARemoteServerIsNetwork(t *testing.T) {
	remote := func(url string) string {
		return "  network:\n    egress: none\n  mcpServers:\n    - url: " + url + "\n      auth: none\n"
	}
	cur := canonicalManifest(t, remote("https://mcp.linear.app/mcp"))
	if !declaredCaps(cur)["network"] {
		t.Fatalf("a remote server does not declare network: %v", declaredCaps(cur))
	}
	pol, err := ParsePolicy([]byte(`{"blockedCapabilities":["network"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if issues := CheckSubmissionPolicy(pol, registry.PolicySubmission{ManifestJSON: cur}); len(issues) != 1 {
		t.Fatalf("blockedCapabilities network missed a remote server: %v", issues)
	}

	in := &Input{PrevManifestJSON: canonicalManifest(t, "  network:\n    egress: none\n"), ManifestJSON: cur}
	var hosts, widened []string
	for _, f := range s9ManifestDiff(in) {
		switch f.Scanner {
		case "S9/new-egress":
			if f.Severity != SevLow || !strings.Contains(f.Title, "remote MCP server") {
				t.Errorf("finding: %+v", f)
			}
			hosts = append(hosts, f.Detail["host"].(string))
		case "S9/capability-widened":
			widened = append(widened, f.Detail["capability"].(string))
		}
	}
	if len(hosts) != 1 || hosts[0] != "mcp.linear.app" || len(widened) != 1 || widened[0] != "network" {
		t.Fatalf("new-egress = %v, capability-widened = %v", hosts, widened)
	}

	// The same host in the previous release is nothing new.
	in.PrevManifestJSON = canonicalManifest(t, remote("https://mcp.linear.app/v2"))
	for _, f := range s9ManifestDiff(in) {
		if f.Scanner == "S9/new-egress" {
			t.Fatalf("an unchanged host is new: %+v", f)
		}
	}
}

// S2 reads an oauth template's values in any format, not only quoted
// strings: an INI value carries a pasted secret as well as JSON does.
func TestS2ManifestOAuthReadsUnquotedValues(t *testing.T) {
	in := &Input{ManifestJSON: []byte(`{"capabilities":{"mcpServers":[{"npm":"x","version":"1.0.0","oauth":{` +
		`"issuer":"https://auth.example.com","files":[{"path":"c.ini","template":"token = {access_token}\nclient_secret = ` + fakeHexToken() + `\n"}]}}]}}`)}
	res := S2Secrets{}.Run(stageContext{}, in)
	if got := findScanner(res.Findings, "S2/oauth-token-value"); len(got) != 1 || got[0].Detail["key"] != "oauth.files[0]" {
		t.Fatalf("findings: %+v", res.Findings)
	}
}
