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
// gate's rating of the advisory (here, both are their own: a High with no
// score, and a Critical).
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

// A lookup failure is one medium S7/osv-no-data finding (which publishes,
// the tweaks plan's D3) for servers the registry has never answered for,
// and silently uses the last known answer otherwise.
func TestS7LookupErrorIsNoData(t *testing.T) {
	osv := &fakeOSV{err: errors.New("dial tcp: i/o timeout")}
	cache := &MemoryMCPScanCache{}
	res := S7MCPServers{}.Run(s7ctx(osv, cache), &Input{ManifestJSON: []byte(s7Manifest)})
	errs := findScanner(res.Findings, scannerOSVNoData)
	if len(errs) != 1 || errs[0].Severity != SevMedium || errs[0].Detail["error"] != "dial tcp: i/o timeout" {
		t.Fatalf("findings: %+v", res.Findings)
	}
	if got := errs[0].Detail["servers"].([]string); len(got) != 2 {
		t.Fatalf("unchecked servers: %v", got)
	}
	if got := errs[0].Detail["reasons"].(map[string]string); got["pypi:mcp-server-fetch@0.6.2"] != noDataLookupFailed {
		t.Fatalf("reasons: %v", got)
	}
	if couldNotScan(errs) != nil {
		t.Fatal("no advisory data must not force review (D3)")
	}
	rec, _ := cache.Get(context.Background(), "pypi", "mcp-server-fetch", "0.6.2")
	if rec == nil || rec.Status != "error" || rec.LastError == "" {
		t.Fatalf("error row: %+v", rec)
	}

	// A second submission during the same outage finds those error rows.
	// An error row is no evidence, so the servers still have no data and
	// the finding is made again (agentry#480: there used to be none).
	res = S7MCPServers{}.Run(s7ctx(osv, cache), &Input{ManifestJSON: []byte(s7Manifest)})
	errs = findScanner(res.Findings, scannerOSVNoData)
	if len(errs) != 1 || errs[0].Severity != SevMedium || errs[0].Confidence != ConfHigh {
		t.Fatalf("second submission during the outage: %+v", res.Findings)
	}
	if got := errs[0].Detail["servers"].([]string); len(got) != 2 {
		t.Fatalf("unchecked servers on the second submission: %v", got)
	}

	// With a stale-but-real row the failure is absorbed: its advisories
	// are reported and no osv-no-data finding is raised for that server.
	stale := &MemoryMCPScanCache{}
	_ = stale.Put(context.Background(), MCPScanRecord{Ecosystem: "npm", Package: "@modelcontextprotocol/server-github", Version: "2026.1.2",
		Status: "vulnerable", MaxSeverity: "high", LastChecked: time.Now().Add(-48 * time.Hour),
		Advisories: []OSVVulnerability{{ID: "GHSA-old", Severity: "high", Summary: "old", Scored: true}}})
	_ = stale.Put(context.Background(), MCPScanRecord{Ecosystem: "pypi", Package: "mcp-server-fetch", Version: "0.6.2",
		Status: "safe", LastChecked: time.Now().Add(-48 * time.Hour)})
	res = S7MCPServers{}.Run(s7ctx(osv, stale), &Input{ManifestJSON: []byte(s7Manifest)})
	if len(findScanner(res.Findings, scannerOSVNoData)) != 0 || len(findScanner(res.Findings, "S7/mcp-vuln-ghsa-old")) != 1 {
		t.Fatalf("stale-row findings: %+v", res.Findings)
	}

	// Mixed: one server with a real answer, one with only an error row. Only
	// the second is unchecked.
	mixed := &MemoryMCPScanCache{}
	_ = mixed.Put(context.Background(), MCPScanRecord{Ecosystem: "npm", Package: "@modelcontextprotocol/server-github", Version: "2026.1.2",
		Status: "safe", LastChecked: time.Now().Add(-48 * time.Hour)})
	_ = mixed.Put(context.Background(), MCPScanRecord{Ecosystem: "pypi", Package: "mcp-server-fetch", Version: "0.6.2",
		Status: "error", LastChecked: time.Now().Add(-time.Hour), LastError: "earlier outage"})
	res = S7MCPServers{}.Run(s7ctx(osv, mixed), &Input{ManifestJSON: []byte(s7Manifest)})
	errs = findScanner(res.Findings, scannerOSVNoData)
	if len(errs) != 1 {
		t.Fatalf("mixed findings: %+v", res.Findings)
	}
	if got := errs[0].Detail["servers"].([]string); len(got) != 1 || got[0] != "pypi:mcp-server-fetch@0.6.2" {
		t.Fatalf("mixed unchecked servers: %v", got)
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

// The finding carries the gate's rating (agentry#774, the tweaks plan's D1
// and D2); the registry row keeps the advisory's own severity, which the
// scan route, the alerts and their routing read.
func TestS7RatesAdvisoriesForTheGate(t *testing.T) {
	score := func(f float64) *float64 { return &f }
	osv := &fakeOSV{vulns: map[string][]OSVVulnerability{
		"npm/@modelcontextprotocol/server-github@2026.1.2": {
			{ID: "GHSA-crit", Severity: "critical", CVSSScore: score(8.6)},
			{ID: "GHSA-high-85", Severity: "high", CVSSScore: score(8.5)},
			{ID: "GHSA-high-84", Severity: "high", CVSSScore: score(8.4)},
			{ID: "GHSA-high-none", Severity: "high"},
			{ID: "GHSA-low", Severity: "low", CVSSScore: score(3.1)},
		},
	}}
	cache := &MemoryMCPScanCache{}
	res := S7MCPServers{}.Run(s7ctx(osv, cache), &Input{ManifestJSON: []byte(s7Manifest)})
	want := map[string]Severity{
		"S7/mcp-vuln-ghsa-crit": SevCritical, "S7/mcp-vuln-ghsa-high-85": SevHigh,
		"S7/mcp-vuln-ghsa-high-84": SevMedium, "S7/mcp-vuln-ghsa-high-none": SevHigh, "S7/mcp-vuln-ghsa-low": SevLow,
	}
	got := findScanner(res.Findings, "S7/mcp-vuln-")
	if len(got) != len(want) {
		t.Fatalf("findings: %+v", res.Findings)
	}
	for _, f := range got {
		if f.Severity != want[f.Scanner] {
			t.Errorf("%s: severity %s, want %s", f.Scanner, f.Severity, want[f.Scanner])
		}
	}
	for _, f := range got {
		if f.Scanner == "S7/mcp-vuln-ghsa-high-84" && (f.Detail["advisorySeverity"] != "high" || f.Detail["cvssScore"] != 8.4) {
			t.Fatalf("detail: %+v", f.Detail)
		}
	}
	rec, _ := cache.Get(context.Background(), "npm", "@modelcontextprotocol/server-github", "2026.1.2")
	if rec == nil || rec.MaxSeverity != "critical" {
		t.Fatalf("row: %+v", rec)
	}
	for _, a := range rec.Advisories {
		if a.ID == "GHSA-high-84" && a.Severity != "high" {
			t.Fatalf("the stored severity must stay the advisory's own: %+v", a)
		}
	}
	// The gate on the result: the worst gating finding is the Critical, so
	// the version is rejected (D1).
	if d := Evaluate(GateInput{Findings: res.Findings, Policy: DefaultBaseline()}); d.Outcome != OutcomeRejected {
		t.Fatalf("outcome: %+v", d)
	}
}

// A fresh registry row written before advisories were scored is asked about
// again, so the redo of a new ruleset does not judge a High below 8.5 as
// high for want of a score. When the lookup fails, the row still answers.
func TestS7AsksAgainAboutAnUnscoredRow(t *testing.T) {
	score := func(f float64) *float64 { return &f }
	cache := &MemoryMCPScanCache{}
	_ = cache.Put(context.Background(), MCPScanRecord{Ecosystem: "npm", Package: "@modelcontextprotocol/server-github", Version: "2026.1.2",
		Status: "vulnerable", MaxSeverity: "high", LastChecked: time.Now().Add(-time.Hour),
		Advisories: []OSVVulnerability{{ID: "GHSA-pre", Severity: "high", Summary: "read before scoring"}}})
	_ = cache.Put(context.Background(), MCPScanRecord{Ecosystem: "pypi", Package: "mcp-server-fetch", Version: "0.6.2",
		Status: "safe", LastChecked: time.Now().Add(-time.Hour)})

	down := &fakeOSV{err: errors.New("timeout")}
	res := S7MCPServers{}.Run(s7ctx(down, cache), &Input{ManifestJSON: []byte(s7Manifest)})
	if down.calls != 1 {
		t.Fatalf("an unscored row must be looked up again; calls = %d", down.calls)
	}
	if f := findScanner(res.Findings, "S7/mcp-vuln-ghsa-pre"); len(f) != 1 || f[0].Severity != SevHigh || len(findScanner(res.Findings, scannerOSVNoData)) != 0 {
		t.Fatalf("with the lookup down, the old answer stands: %+v", res.Findings)
	}

	up := &fakeOSV{vulns: map[string][]OSVVulnerability{
		"npm/@modelcontextprotocol/server-github@2026.1.2": {{ID: "GHSA-pre", Severity: "high", CVSSScore: score(7.5)}},
	}}
	res = S7MCPServers{}.Run(s7ctx(up, cache), &Input{ManifestJSON: []byte(s7Manifest)})
	if f := findScanner(res.Findings, "S7/mcp-vuln-ghsa-pre"); up.calls != 1 || len(f) != 1 || f[0].Severity != SevMedium {
		t.Fatalf("calls=%d findings: %+v", up.calls, res.Findings)
	}
	// Scored now: the next submission is answered from the registry.
	_ = S7MCPServers{}.Run(s7ctx(up, cache), &Input{ManifestJSON: []byte(s7Manifest)})
	if up.calls != 1 {
		t.Fatalf("a scored fresh row must answer; calls = %d", up.calls)
	}
}

// A declared server S7 cannot look up is no data, not nothing (D3).
func TestS7NoDataForAServerItCannotLookUp(t *testing.T) {
	m := `{"schemaVersion":"2","capabilities":{"mcpServers":[
  {"npm":"left-pad","version":""},
  {"version":"1.0.0"},
  {"pypi":"mcp-server-fetch","version":"0.6.2"}
]}}`
	osv := &fakeOSV{}
	res := S7MCPServers{}.Run(s7ctx(osv, &MemoryMCPScanCache{}), &Input{ManifestJSON: []byte(m)})
	nd := findScanner(res.Findings, scannerOSVNoData)
	if len(nd) != 1 || nd[0].Severity != SevMedium || osv.calls != 1 {
		t.Fatalf("calls=%d findings: %+v", osv.calls, res.Findings)
	}
	if _, failed := nd[0].Detail["error"]; failed {
		t.Fatalf("no lookup failed: %+v", nd[0].Detail)
	}
	reasons := nd[0].Detail["reasons"].(map[string]string)
	if reasons["npm:left-pad"] != noDataNoVersion || reasons["capabilities.mcpServers[1]"] != noDataEcosystem || len(reasons) != 2 {
		t.Fatalf("reasons: %v", reasons)
	}
	if d := Evaluate(GateInput{Findings: res.Findings, Policy: DefaultBaseline()}); d.Outcome != OutcomePublish {
		t.Fatalf("no data publishes at the baseline (D3): %+v", d)
	}
}

// A remote server has no package to look up: S7 reports it for what it is,
// low, naming its address, its auth and its scopes, and publishes with it
// (plan mcp-oauth-connections.md D11, agentry#910). It is never "no data",
// and it is reported whether or not a vulnerability database is configured.
func TestS7ReportsARemoteServerWithoutLookingItUp(t *testing.T) {
	m := `{"schemaVersion":"2","capabilities":{"mcpServers":[
  {"url":"https://gmailmcp.googleapis.com/mcp/v1","auth":"oauth","scopes":["https://www.googleapis.com/auth/gmail.readonly"]},
  {"pypi":"mcp-server-fetch","version":"0.6.2"}
]}}`
	osv := &fakeOSV{}
	res := S7MCPServers{}.Run(s7ctx(osv, &MemoryMCPScanCache{}), &Input{ManifestJSON: []byte(m)})
	rs := findScanner(res.Findings, scannerRemoteServer)
	if len(rs) != 1 || rs[0].Severity != SevLow || osv.calls != 1 {
		t.Fatalf("calls=%d findings: %+v", osv.calls, res.Findings)
	}
	if got := rs[0].Detail; got["url"] != "https://gmailmcp.googleapis.com/mcp/v1" || got["auth"] != "oauth" ||
		len(got["scopes"].([]string)) != 1 {
		t.Fatalf("detail: %+v", got)
	}
	if !strings.Contains(rs[0].Title, "https://gmailmcp.googleapis.com/mcp/v1") || !strings.Contains(rs[0].Title, "gmail.readonly") ||
		strings.Contains(strings.ToLower(rs[0].Title), "safe") {
		t.Fatalf("title: %q", rs[0].Title)
	}
	if nd := findScanner(res.Findings, scannerOSVNoData); len(nd) != 0 {
		t.Fatalf("a remote server is not no-data: %+v", nd)
	}
	if got := DeclaredMCPServers([]byte(m)); len(got) != 1 || got[0].Package != "mcp-server-fetch" {
		t.Fatalf("the registry join records packages only: %+v", got)
	}
	if d := Evaluate(GateInput{Findings: res.Findings, Policy: DefaultBaseline()}); d.Outcome != OutcomePublish {
		t.Fatalf("a remote server publishes with its finding (D11): %+v", d)
	}
	off := S7MCPServers{}.Run(s7ctx(OfflineOSV{}, &MemoryMCPScanCache{}), &Input{ManifestJSON: []byte(m)})
	if len(findScanner(off.Findings, scannerRemoteServer)) != 1 {
		t.Fatalf("offline, the remote server went unreported: %+v", off.Findings)
	}
}
