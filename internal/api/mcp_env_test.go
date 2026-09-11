package api_test

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/scan"
)

// TestVersionCapabilitiesCarryMCPServerEnv (agentry#286): a declared
// server's plain env map is stored with the version's capability block and
// served unchanged, keys sorted by the canonical form, so every consumer of
// the API reads the configuration the server will receive.
func TestVersionCapabilitiesCarryMCPServerEnv(t *testing.T) {
	osv := &fakeOSV{vulns: map[string][]scan.OSVVulnerability{}}
	env := newTestEnvCfg(t, func(c *config.Config) {}, func(s *api.Server) { s.SetMCPScanning(osv) })
	author := env.register("env-auth")
	env.verifyEmail(author)
	sess := env.login(author)
	env.doJSON(sess, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": author, "name": "issue-digest", "modes": []string{"autonomous"}, "visibility": "public"}, nil, http.StatusCreated)
	_, pat := env.mintPAT(sess, "pub", "agent:publish", "agent:read", "repo:read")
	manifest := "schemaVersion: \"2\"\nname: issue-digest\nnamespace: " + author + "\nmodes: [autonomous]\nversion: 1.0.0\n" +
		"summary: declares a configured MCP server\nlicense: Apache-2.0\ncapabilities:\n  mcpServers:\n" +
		"    - npm: github-mcp-server-js\n      version: \"0.1.7\"\n      tools: [list_issues]\n      secrets: [GITHUB_TOKEN]\n" +
		"      env:\n        LOGS_DIR: /tmp/logs\n        GITHUB_PERMISSION: read-only\n      egress: [api.github.com]\n" +
		"publish:\n  include: [\"agent.yaml\", \"AGENT.md\", \"README.md\", \"LICENSE\"]\n"
	files := map[string]string{
		"agent.yaml": manifest,
		"AGENT.md":   "List the open issues and write a digest.\n",
		"README.md":  "# issue-digest\n",
		"LICENSE":    "Apache-2.0\n",
	}
	if status, body := env.uploadVersionCLI(author, "issue-digest", pat, files); status != http.StatusAccepted {
		t.Fatalf("submit: %d %s", status, body)
	}

	// The capability block is written with the version row, before the
	// pipeline decides anything; poll for the row rather than for a state.
	var v struct {
		Status       string `json:"status"`
		Capabilities struct {
			MCPServers []struct {
				NPM   string            `json:"npm"`
				Tools []string          `json:"tools"`
				Env   map[string]string `json:"env"`
			} `json:"mcpServers"`
		} `json:"capabilities"`
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		res := env.do(anonymous, http.MethodGet, "/api/v1/agents/"+author+"/issue-digest/versions/1.0.0", nil)
		ok := res.StatusCode == http.StatusOK
		if ok {
			_ = json.NewDecoder(res.Body).Decode(&v)
		}
		_ = res.Body.Close()
		if ok || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(v.Capabilities.MCPServers) != 1 {
		t.Fatalf("version capabilities: %+v", v)
	}
	srv := v.Capabilities.MCPServers[0]
	if srv.NPM != "github-mcp-server-js" || len(srv.Tools) != 1 || len(srv.Env) != 2 ||
		srv.Env["GITHUB_PERMISSION"] != "read-only" || srv.Env["LOGS_DIR"] != "/tmp/logs" {
		t.Fatalf("served server entry: %+v", srv)
	}
}
