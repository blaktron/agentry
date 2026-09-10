package scan

import (
	"strings"
	"testing"

	"github.com/blaktron/agentry/internal/registry"
)

func TestBlockedMcpServersPolicy(t *testing.T) {
	manifest := []byte(`{"name":"x","capabilities":{"mcpServers":[
		{"npm":"@modelcontextprotocol/server-github","version":"2026.1.2"},
		{"pypi":"mcp-server-fetch","version":"0.6.2"}]}}`)
	pol, err := ParsePolicy([]byte(`{"blockedMcpServers":["pypi:mcp-server-fetch","npm:@evil/*"]}`))
	if err != nil {
		t.Fatal(err)
	}
	issues := CheckSubmissionPolicy(pol, registry.PolicySubmission{ManifestJSON: manifest})
	if len(issues) != 1 || !strings.Contains(issues[0].Error(), `blocks MCP server "pypi:mcp-server-fetch"`) {
		t.Fatalf("issues: %v", issues)
	}
	// Globs and unions toward strict.
	merged := Merge(Policy{BlockedMcpServers: []string{"npm:@modelcontextprotocol/*"}}, pol)
	issues = CheckSubmissionPolicy(merged, registry.PolicySubmission{ManifestJSON: manifest})
	if len(issues) != 2 {
		t.Fatalf("union must block both: %v", issues)
	}
	// Bad entries are rejected at parse time.
	for _, bad := range []string{`{"blockedMcpServers":["server-github"]}`, `{"blockedMcpServers":["npm:[bad"]}`} {
		if _, err := ParsePolicy([]byte(bad)); err == nil {
			t.Fatalf("expected parse error for %s", bad)
		}
	}
	// Nothing declared, nothing blocked.
	if issues := CheckSubmissionPolicy(pol, registry.PolicySubmission{ManifestJSON: []byte(`{"name":"y"}`)}); len(issues) != 0 {
		t.Fatalf("no servers declared: %v", issues)
	}
}
