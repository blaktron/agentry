package scan

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
)

type fakeOSV struct {
	calls int
	vulns map[string][]OSVVulnerability
	err   error
}

func (f *fakeOSV) Query(_ context.Context, pkgs []OSVPackage) (map[string][]OSVVulnerability, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	out := map[string][]OSVVulnerability{}
	for _, p := range pkgs {
		if v, ok := f.vulns[p.Key()]; ok {
			out[p.Key()] = v
		}
	}
	return out, nil
}

const s7Manifest = `{"schemaVersion":"2","name":"x","namespace":"y","modes":["autonomous"],"version":"1.0.0","summary":"s",
"capabilities":{"mcpServers":[
  {"npm":"@modelcontextprotocol/server-github","version":"2026.1.2"},
  {"pypi":"mcp-server-fetch","version":"0.6.2"}
]},"publish":{"include":["AGENT.md"]}}`

func s7ctx(osv OSVClient, cache MCPScanCache) stageContext {
	return stageContext{ctx: context.Background(), log: slog.Default(), osv: osv, mcpCache: cache}
}

func findScanner(fs []Finding, prefix string) []Finding {
	var out []Finding
	for _, f := range fs {
		if strings.HasPrefix(f.Scanner, prefix) {
			out = append(out, f)
		}
	}
	return out
}

func TestS7NoServersNoFindings(t *testing.T) {
	osv := &fakeOSV{}
	res := S7MCPServers{}.Run(s7ctx(osv, &MemoryMCPScanCache{}), &Input{ManifestJSON: []byte(`{"schemaVersion":"2","capabilities":{}}`)})
	if len(res.Findings) != 0 || osv.calls != 0 || !res.NoCache {
		t.Fatalf("findings=%d calls=%d nocache=%v", len(res.Findings), osv.calls, res.NoCache)
	}
}

func TestS7OfflineIsNotChecked(t *testing.T) {
	res := S7MCPServers{}.Run(s7ctx(OfflineOSV{}, &MemoryMCPScanCache{}), &Input{ManifestJSON: []byte(s7Manifest)})
	if got := findScanner(res.Findings, "S7/osv-not-checked"); len(got) != 1 || got[0].Severity != SevInfo {
		t.Fatalf("findings: %+v", res.Findings)
	}
}

// First sight asks the database and records the answer; a second submission
// within the TTL is answered from the registry, and the finding carries the
// advisory's own severity (D2).
func TestS7LooksUpOnceThenReadsTheRegistry(t *testing.T) {
	osv := &fakeOSV{vulns: map[string][]OSVVulnerability{
		"npm/@modelcontextprotocol/server-github@2026.1.2": {
			{ID: "GHSA-aaaa-bbbb-cccc", Aliases: []string{"CVE-2026-0001"}, Summary: "SSRF in fetch", Severity: "high", FixedIn: []string{"2026.1.3"}},
			{ID: "GHSA-dddd-eeee-ffff", Summary: "Path traversal", Severity: "critical"},
		},
	}}
	cache := &MemoryMCPScanCache{}
	res := S7MCPServers{}.Run(s7ctx(osv, cache), &Input{ManifestJSON: []byte(s7Manifest)})
	if osv.calls != 1 {
		t.Fatalf("osv calls = %d, want 1", osv.calls)
	}
	vulns := findScanner(res.Findings, "S7/mcp-vuln-")
	if len(vulns) != 2 {
		t.Fatalf("findings: %+v", res.Findings)
	}
	if vulns[0].Scanner != "S7/mcp-vuln-ghsa-aaaa-bbbb-cccc" || vulns[0].Severity != SevHigh || !strings.Contains(vulns[0].Title, "CVE-2026-0001") {
		t.Fatalf("first finding: %+v", vulns[0])
	}
	if vulns[0].Detail["fixedIn"].([]string)[0] != "2026.1.3" || vulns[0].Detail["package"] != "@modelcontextprotocol/server-github" {
		t.Fatalf("detail: %+v", vulns[0].Detail)
	}
	if vulns[1].Severity != SevCritical {
		t.Fatalf("second finding severity: %s", vulns[1].Severity)
	}
	gh, _ := cache.Get(context.Background(), "npm", "@modelcontextprotocol/server-github", "2026.1.2")
	if gh == nil || gh.Status != "vulnerable" || gh.MaxSeverity != "critical" || len(gh.Advisories) != 2 {
		t.Fatalf("registry row: %+v", gh)
	}
	py, _ := cache.Get(context.Background(), "pypi", "mcp-server-fetch", "0.6.2")
	if py == nil || py.Status != "safe" || len(py.Advisories) != 0 {
		t.Fatalf("registry row (safe): %+v", py)
	}

	// Second submission: no lookup, same findings.
	res2 := S7MCPServers{}.Run(s7ctx(osv, cache), &Input{ManifestJSON: []byte(s7Manifest)})
	if osv.calls != 1 {
		t.Fatalf("osv calls after re-run = %d, want 1", osv.calls)
	}
	if len(findScanner(res2.Findings, "S7/mcp-vuln-")) != 2 {
		t.Fatalf("re-run findings: %+v", res2.Findings)
	}

	// Past the TTL the database is asked again.
	later := S7MCPServers{now: func() time.Time { return time.Now().Add(mcpScanTTL + time.Minute) }}
	_ = later.Run(s7ctx(osv, cache), &Input{ManifestJSON: []byte(s7Manifest)})
	if osv.calls != 2 {
		t.Fatalf("osv calls after TTL = %d, want 2", osv.calls)
	}
}

// A lookup failure is a medium finding (routes to review) for servers the
// registry has never seen, and silently uses the last known row otherwise.
func TestS7LookupErrorFailsTowardReview(t *testing.T) {
	osv := &fakeOSV{err: errors.New("dial tcp: i/o timeout")}
	cache := &MemoryMCPScanCache{}
	res := S7MCPServers{}.Run(s7ctx(osv, cache), &Input{ManifestJSON: []byte(s7Manifest)})
	errs := findScanner(res.Findings, "S7/osv-error")
	if len(errs) != 1 || errs[0].Severity != SevMedium {
		t.Fatalf("findings: %+v", res.Findings)
	}
	if got := errs[0].Detail["servers"].([]string); len(got) != 2 {
		t.Fatalf("unchecked servers: %v", got)
	}
	rec, _ := cache.Get(context.Background(), "pypi", "mcp-server-fetch", "0.6.2")
	if rec == nil || rec.Status != "error" || rec.LastError == "" {
		t.Fatalf("error row: %+v", rec)
	}

	// With a stale-but-real row the failure is absorbed: its advisories
	// are reported and no osv-error finding is raised for that server.
	stale := &MemoryMCPScanCache{}
	_ = stale.Put(context.Background(), MCPScanRecord{Ecosystem: "npm", Package: "@modelcontextprotocol/server-github", Version: "2026.1.2",
		Status: "vulnerable", MaxSeverity: "high", LastChecked: time.Now().Add(-48 * time.Hour),
		Advisories: []OSVVulnerability{{ID: "GHSA-old", Severity: "high", Summary: "old"}}})
	_ = stale.Put(context.Background(), MCPScanRecord{Ecosystem: "pypi", Package: "mcp-server-fetch", Version: "0.6.2",
		Status: "safe", LastChecked: time.Now().Add(-48 * time.Hour)})
	res = S7MCPServers{}.Run(s7ctx(osv, stale), &Input{ManifestJSON: []byte(s7Manifest)})
	if len(findScanner(res.Findings, "S7/osv-error")) != 0 || len(findScanner(res.Findings, "S7/mcp-vuln-ghsa-old")) != 1 {
		t.Fatalf("stale-row findings: %+v", res.Findings)
	}
}

func TestDeclaredMCPServersSorted(t *testing.T) {
	got := DeclaredMCPServers([]byte(s7Manifest))
	if len(got) != 2 || got[0].Ecosystem != "npm" || got[1].Ecosystem != "pypi" || got[1].Package != "mcp-server-fetch" {
		t.Fatalf("declared: %+v", got)
	}
	if DeclaredMCPServers(nil) != nil || DeclaredMCPServers([]byte("{")) != nil {
		t.Fatal("garbage manifests must yield nothing")
	}
}
