package scan

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// fakeRegistries answers Published from a set of known refs; err makes every
// call fail as an unreachable registry would.
type fakeRegistries struct {
	published map[string]bool // "npm:pkg@ver" → published
	err       error
	calls     int
}

func (f *fakeRegistries) Published(_ context.Context, eco, name, ver string) (bool, error) {
	f.calls++
	if f.err != nil {
		return false, f.err
	}
	return f.published[eco+":"+name+"@"+ver], nil
}

func s7ctxR(osv OSVClient, cache MCPScanCache, reg PackageRegistries) stageContext {
	return stageContext{ctx: context.Background(), log: slog.Default(), osv: osv, mcpCache: cache, registries: reg}
}

// agentry#1036: a version its registry does not publish is refused (a
// critical finding, which the gate rejects), OSV is not asked about it, and
// its registry row says not-found, never safe. The other server goes on as
// before.
func TestS7RefusesAVersionItsRegistryDoesNotPublish(t *testing.T) {
	reg := &fakeRegistries{published: map[string]bool{"pypi:mcp-server-fetch@0.6.2": true}}
	osv := &fakeOSV{}
	cache := &MemoryMCPScanCache{}
	res := S7MCPServers{}.Run(s7ctxR(osv, cache, reg), &Input{ManifestJSON: []byte(s7Manifest)})

	gone := findScanner(res.Findings, scannerVersionNotPublished)
	if len(gone) != 1 || gone[0].Severity != SevCritical || gone[0].Confidence != ConfHigh ||
		gone[0].Detail["package"] != "@modelcontextprotocol/server-github" || gone[0].Detail["version"] != "2026.1.2" {
		t.Fatalf("findings: %+v", res.Findings)
	}
	row, _ := cache.Get(context.Background(), "npm", "@modelcontextprotocol/server-github", "2026.1.2")
	if row == nil || row.Status != "not-found" {
		t.Fatalf("registry row: %+v", row)
	}
	if py, _ := cache.Get(context.Background(), "pypi", "mcp-server-fetch", "0.6.2"); py == nil || py.Status != "safe" {
		t.Fatalf("the published server was not looked up: %+v", py)
	}
	if osv.calls != 1 {
		t.Fatalf("osv calls = %d, want 1 (the published server only)", osv.calls)
	}
	d := Evaluate(GateInput{Findings: res.Findings})
	if d.Outcome != OutcomeRejected {
		t.Fatalf("gate: %+v", d)
	}

	// A second submission within the TTL reads the not-found row and does
	// not ask the registry about that version again.
	before := reg.calls
	res2 := S7MCPServers{}.Run(s7ctxR(osv, cache, reg), &Input{ManifestJSON: []byte(s7Manifest)})
	if len(findScanner(res2.Findings, scannerVersionNotPublished)) != 1 || reg.calls != before+1 {
		t.Fatalf("re-run: findings %+v, registry calls %d (was %d)", res2.Findings, reg.calls, before)
	}
}

// A registry that does not answer is "not checked", medium, which publishes
// as S7/osv-no-data does; the servers still go to OSV, and nothing is
// recorded as not-found.
func TestS7NotCheckedWhenTheRegistryDoesNotAnswer(t *testing.T) {
	reg := &fakeRegistries{err: errors.New("registry: 503")}
	osv := &fakeOSV{}
	cache := &MemoryMCPScanCache{}
	res := S7MCPServers{}.Run(s7ctxR(osv, cache, reg), &Input{ManifestJSON: []byte(s7Manifest)})
	nc := findScanner(res.Findings, scannerVersionNotChecked)
	if len(nc) != 1 || nc[0].Severity != SevMedium || len(nc[0].Detail["servers"].([]string)) != 2 {
		t.Fatalf("findings: %+v", res.Findings)
	}
	if len(findScanner(res.Findings, scannerVersionNotPublished)) != 0 || osv.calls != 1 {
		t.Fatalf("refused or skipped OSV on no answer: %+v, osv calls %d", res.Findings, osv.calls)
	}
	if d := Evaluate(GateInput{Findings: res.Findings}); d.Outcome != OutcomePublish {
		t.Fatalf("gate: %+v", d)
	}
}

// Every version published: no finding of the check's own, and OSV as before.
func TestS7PublishedVersionsAddNothing(t *testing.T) {
	reg := &fakeRegistries{published: map[string]bool{
		"npm:@modelcontextprotocol/server-github@2026.1.2": true, "pypi:mcp-server-fetch@0.6.2": true}}
	osv := &fakeOSV{}
	res := S7MCPServers{}.Run(s7ctxR(osv, &MemoryMCPScanCache{}, reg), &Input{ManifestJSON: []byte(s7Manifest)})
	if len(findScanner(res.Findings, "S7/version-")) != 0 || osv.calls != 1 || reg.calls != 2 {
		t.Fatalf("findings %+v, osv calls %d, registry calls %d", res.Findings, osv.calls, reg.calls)
	}
}

// Told not to ask (AGENTRY_SCAN_NPM_REGISTRY=none): an info finding that
// does not gate, and OSV as before.
func TestS7OfflineRegistriesAreNotChecked(t *testing.T) {
	osv := &fakeOSV{}
	res := S7MCPServers{}.Run(s7ctxR(osv, &MemoryMCPScanCache{}, OfflineRegistries{}), &Input{ManifestJSON: []byte(s7Manifest)})
	nc := findScanner(res.Findings, scannerVersionNotChecked)
	if len(nc) != 1 || nc[0].Severity != SevInfo || osv.calls != 1 {
		t.Fatalf("findings %+v, osv calls %d", res.Findings, osv.calls)
	}
}

// Once the registry answers 404 the not-found row stands for a day; past
// the TTL the registry is asked again, and a version published since then
// goes on to OSV.
func TestS7AsksTheRegistryAgainPastTheTTL(t *testing.T) {
	reg := &fakeRegistries{published: map[string]bool{"pypi:mcp-server-fetch@0.6.2": true}}
	cache := &MemoryMCPScanCache{}
	_ = S7MCPServers{}.Run(s7ctxR(&fakeOSV{}, cache, reg), &Input{ManifestJSON: []byte(s7Manifest)})
	reg.published["npm:@modelcontextprotocol/server-github@2026.1.2"] = true
	later := S7MCPServers{now: func() time.Time { return time.Now().Add(mcpScanTTL + time.Minute) }}
	res := later.Run(s7ctxR(&fakeOSV{}, cache, reg), &Input{ManifestJSON: []byte(s7Manifest)})
	if len(findScanner(res.Findings, scannerVersionNotPublished)) != 0 {
		t.Fatalf("still refused past the TTL: %+v", res.Findings)
	}
	if row, _ := cache.Get(context.Background(), "npm", "@modelcontextprotocol/server-github", "2026.1.2"); row == nil || row.Status == "not-found" {
		t.Fatalf("registry row: %+v", row)
	}
}

// The HTTP client asks npm for one path segment per scoped name and PyPI's
// JSON API per version, and reads 200 as published, 404 as not, anything
// else as no answer.
func TestHTTPRegistriesPaths(t *testing.T) {
	seen := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen[r.URL.EscapedPath()] = true
		switch r.URL.EscapedPath() {
		case "/@cyanheads%2Fosv-advisory-mcp-server/0.1.13", "/pypi/mcp-server-fetch/0.6.2/json":
			w.WriteHeader(http.StatusOK)
		case "/@cyanheads%2Fosv-advisory-mcp-server/0.1.23":
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusBadGateway)
		}
	}))
	defer srv.Close()
	r := &HTTPRegistries{NPM: srv.URL, PyPI: srv.URL}
	ctx := context.Background()
	for _, tc := range []struct {
		eco, name, ver string
		ok, err        bool
	}{
		{"npm", "@cyanheads/osv-advisory-mcp-server", "0.1.13", true, false},
		{"npm", "@cyanheads/osv-advisory-mcp-server", "0.1.23", false, false},
		{"pypi", "mcp-server-fetch", "0.6.2", true, false},
		{"pypi", "mcp-server-fetch", "9.9.9", false, true},
		{"cargo", "x", "1", false, true},
	} {
		ok, err := r.Published(ctx, tc.eco, tc.name, tc.ver)
		if ok != tc.ok || (err != nil) != tc.err {
			t.Errorf("%s %s@%s: got %v, %v", tc.eco, tc.name, tc.ver, ok, err)
		}
	}
	if !seen["/@cyanheads%2Fosv-advisory-mcp-server/0.1.13"] {
		t.Fatalf("npm path not asked as one segment: %v", seen)
	}
}
