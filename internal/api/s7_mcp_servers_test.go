package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/blaktron/agentry/internal/api"
	"github.com/blaktron/agentry/internal/config"
	"github.com/blaktron/agentry/internal/scan"
)

// fakeOSV answers for one package version and counts the lookups.
type fakeOSV struct {
	calls int
	vulns map[string][]scan.OSVVulnerability
}

func (f *fakeOSV) Query(_ context.Context, pkgs []scan.OSVPackage) (map[string][]scan.OSVVulnerability, error) {
	f.calls++
	out := map[string][]scan.OSVVulnerability{}
	for _, p := range pkgs {
		if v, ok := f.vulns[p.Key()]; ok {
			out[p.Key()] = v
		}
	}
	return out, nil
}

func mcpManifest(ns, name, version, pkg, pkgVersion string) string {
	return "schemaVersion: \"2\"\nname: " + name + "\nnamespace: " + ns + "\nmodes: [autonomous]\nversion: " + version +
		"\nsummary: declares an MCP server\nlicense: Apache-2.0\ncapabilities:\n  mcpServers:\n    - npm: " + pkg +
		"\n      version: \"" + pkgVersion + "\"\npublish:\n  include: [\"agent.yaml\", \"AGENT.md\", \"README.md\", \"LICENSE\"]\n"
}

// S7 (agentry#177): a declared MCP server version with a known advisory is a
// finding at the advisory's severity, the lookup happens once per server
// version, the registry remembers it, and the version ↔ server join is
// recorded for the daily sweep.
func TestS7DeclaredMCPServerVulnerability(t *testing.T) {
	osv := &fakeOSV{vulns: map[string][]scan.OSVVulnerability{
		"npm/minimist@1.2.5": {{ID: "GHSA-xvch-5gv4-984h", Aliases: []string{"CVE-2021-44906"}, Summary: "Prototype Pollution in minimist", Severity: "high", FixedIn: []string{"1.2.6"}}},
		"npm/left-pad@1.3.0": {{ID: "GHSA-crit-0000-0001", Summary: "made up, critical", Severity: "critical"}},
	}}
	env := newTestEnvCfg(t, func(c *config.Config) {}, func(s *api.Server) { s.SetMCPScanning(osv) })
	author := env.register("s7-auth")
	env.verifyEmail(author)
	sess := env.login(author)
	_, _ = env.st.Pool().Exec(context.Background(),
		`UPDATE users SET created_at = now() - interval '30 days' WHERE id = (SELECT id FROM handles WHERE handle = $1)`, author)
	env.doJSON(sess, http.MethodPost, "/api/v1/agents",
		map[string]any{"namespace": author, "name": "uses-minimist", "modes": []string{"autonomous"}, "visibility": "public"}, nil, http.StatusCreated)
	_, pat := env.mintPAT(sess, "pub", "agent:publish", "agent:read", "repo:read")
	files := func(version, pkg, pkgVersion string) map[string]string {
		return map[string]string{
			"agent.yaml": mcpManifest(author, "uses-minimist", version, pkg, pkgVersion),
			"AGENT.md":   "Summarise the ticket the user pastes.\n",
			"README.md":  "# uses-minimist\n",
			"LICENSE":    "Apache-2.0\n",
		}
	}
	if status, body := env.uploadVersionCLI(author, "uses-minimist", pat, files("1.0.0", "minimist", "1.2.5")); status != http.StatusAccepted {
		t.Fatalf("submit: %d %s", status, body)
	}
	waitStatusLong(env, author, "uses-minimist", "1.0.0", "needs_review")

	var rep struct {
		Findings []struct {
			Scanner  string         `json:"scanner"`
			Severity string         `json:"severity"`
			Title    string         `json:"title"`
			Detail   map[string]any `json:"detail"`
		} `json:"findings"`
	}
	env.doJSON(anonymous, http.MethodGet, "/api/v1/agents/"+author+"/uses-minimist/versions/1.0.0/report", nil, &rep, http.StatusOK)
	var s7 []string
	for _, f := range rep.Findings {
		if strings.HasPrefix(f.Scanner, "S7/") {
			s7 = append(s7, f.Scanner+":"+f.Severity)
			if f.Scanner == "S7/mcp-vuln-ghsa-xvch-5gv4-984h" {
				if f.Severity != "high" || !strings.Contains(f.Title, "CVE-2021-44906") || f.Detail["package"] != "minimist" {
					t.Fatalf("S7 finding: %+v", f)
				}
			}
		}
	}
	if len(s7) != 1 || !strings.HasPrefix(s7[0], "S7/mcp-vuln-ghsa-xvch-5gv4-984h:") {
		t.Fatalf("S7 findings: %v (all: %d)", s7, len(rep.Findings))
	}
	if osv.calls != 1 {
		t.Fatalf("osv calls = %d, want 1", osv.calls)
	}

	// The registry remembers the answer and the join names the version.
	var status, maxSev string
	if err := env.st.Pool().QueryRow(context.Background(),
		`SELECT status, max_severity FROM mcp_server_scans WHERE ecosystem='npm' AND package='minimist' AND version='1.2.5'`).Scan(&status, &maxSev); err != nil {
		t.Fatalf("registry row: %v", err)
	}
	if status != "vulnerable" || maxSev != "high" {
		t.Fatalf("registry row: %s/%s", status, maxSev)
	}
	var joined int
	_ = env.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM agent_version_mcp_servers m JOIN agent_versions v ON v.id = m.version_id WHERE v.version='1.0.0' AND m.package='minimist' AND m.version='1.2.5'`).Scan(&joined)
	if joined != 1 {
		t.Fatalf("version ↔ server rows: %d", joined)
	}

	// A second version declaring the same server is answered from the
	// registry: no second lookup, same finding.
	if status, body := env.uploadVersionCLI(author, "uses-minimist", pat, files("1.0.1", "minimist", "1.2.5")); status != http.StatusAccepted {
		t.Fatalf("submit 1.0.1: %d %s", status, body)
	}
	waitStatusLong(env, author, "uses-minimist", "1.0.1", "needs_review")
	if osv.calls != 1 {
		t.Fatalf("osv calls after cached submission = %d, want 1", osv.calls)
	}

	// A critical advisory rejects outright, like any critical finding.
	if status, body := env.uploadVersionCLI(author, "uses-minimist", pat, files("1.1.0", "left-pad", "1.3.0")); status != http.StatusAccepted {
		t.Fatalf("submit 1.1.0: %d %s", status, body)
	}
	waitStatusLong(env, author, "uses-minimist", "1.1.0", "rejected")
	if osv.calls != 2 {
		t.Fatalf("osv calls after a new server = %d, want 2", osv.calls)
	}
}

// waitStatusLong is waitStatus with a budget for a loaded CI runner: the S7
// path adds a registry round trip per declared server, and the shared
// helper's ~1 s is what a quiet machine needs, not a busy one.
func waitStatusLong(env *testEnv, ns, name, version, want string) {
	env.t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		res := env.do(anonymous, http.MethodGet, "/api/v1/agents/"+ns+"/"+name+"/versions/"+version, nil)
		var v struct {
			Status string `json:"status"`
		}
		_ = json.NewDecoder(res.Body).Decode(&v)
		_ = res.Body.Close()
		if v.Status == want {
			return
		}
		if v.Status == "rejected" || v.Status == "published" || v.Status == "needs_review" {
			env.t.Fatalf("version %s/%s@%s reached %s, want %s", ns, name, version, v.Status, want)
		}
		time.Sleep(50 * time.Millisecond)
	}
	env.t.Fatalf("version %s/%s@%s did not reach %s in time", ns, name, version, want)
}
