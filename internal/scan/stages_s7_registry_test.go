package scan

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
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

// A version its registry does not publish is refused (a
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

	// A second submission asks the registry again, both servers: the
	// not-found row never answers for it.
	before := reg.calls
	res2 := S7MCPServers{}.Run(s7ctxR(osv, cache, reg), &Input{ManifestJSON: []byte(s7Manifest)})
	if len(findScanner(res2.Findings, scannerVersionNotPublished)) != 1 || reg.calls != before+2 {
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
	if nc[0].Detail["error"] != "registry: 503" {
		t.Fatalf("detail = %+v", nc[0].Detail)
	}

	// One server whose registry does not answer is enough for the finding.
	one := `{"schemaVersion":"2","capabilities":{"mcpServers":[{"pypi":"mcp-server-fetch","version":"0.6.2"}]}}`
	res = S7MCPServers{}.Run(s7ctxR(&fakeOSV{}, &MemoryMCPScanCache{}, reg), &Input{ManifestJSON: []byte(one)})
	if nc := findScanner(res.Findings, scannerVersionNotChecked); len(nc) != 1 || len(nc[0].Detail["servers"].([]string)) != 1 {
		t.Fatalf("one server, registry down: %+v", res.Findings)
	}
}

// Every version published: no finding of the check's own, and OSV is asked.
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
// does not gate, and OSV is asked.
func TestS7OfflineRegistriesAreNotChecked(t *testing.T) {
	osv := &fakeOSV{}
	res := S7MCPServers{}.Run(s7ctxR(osv, &MemoryMCPScanCache{}, OfflineRegistries{}), &Input{ManifestJSON: []byte(s7Manifest)})
	nc := findScanner(res.Findings, scannerVersionNotChecked)
	if len(nc) != 1 || nc[0].Severity != SevInfo || osv.calls != 1 {
		t.Fatalf("findings %+v, osv calls %d", res.Findings, osv.calls)
	}

	// One server is enough for the note, and it says how many.
	one := `{"schemaVersion":"2","capabilities":{"mcpServers":[{"pypi":"mcp-server-fetch","version":"0.6.2"}]}}`
	res = S7MCPServers{}.Run(s7ctxR(&fakeOSV{}, &MemoryMCPScanCache{}, OfflineRegistries{}), &Input{ManifestJSON: []byte(one)})
	if nc := findScanner(res.Findings, scannerVersionNotChecked); len(nc) != 1 || !strings.HasPrefix(nc[0].Title, "1 declared MCP server version(s)") {
		t.Fatalf("one server, registries off: %+v", res.Findings)
	}
}

// A not-found row never refuses a version its registry has published since:
// otherwise a pin submitted just before its release landed, or a future
// version someone submitted early to poison it, would stay refused while the
// sweep kept the row fresh.
func TestS7NotFoundRowNeverRefusesAVersionPublishedSince(t *testing.T) {
	reg := &fakeRegistries{published: map[string]bool{"pypi:mcp-server-fetch@0.6.2": true}}
	cache := &MemoryMCPScanCache{}
	_ = S7MCPServers{}.Run(s7ctxR(&fakeOSV{}, cache, reg), &Input{ManifestJSON: []byte(s7Manifest)})
	if row, _ := cache.Get(context.Background(), "npm", "@modelcontextprotocol/server-github", "2026.1.2"); row == nil || row.Status != "not-found" {
		t.Fatalf("first submission's row: %+v", row)
	}
	reg.published["npm:@modelcontextprotocol/server-github@2026.1.2"] = true
	res := S7MCPServers{}.Run(s7ctxR(&fakeOSV{}, cache, reg), &Input{ManifestJSON: []byte(s7Manifest)})
	if len(findScanner(res.Findings, scannerVersionNotPublished)) != 0 {
		t.Fatalf("refused from the not-found row: %+v", res.Findings)
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
	accept := map[string]bool{}
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		seen[r.URL.EscapedPath()] = true
		accept[r.Header.Get("Accept")] = true
		switch r.URL.EscapedPath() {
		case "/@cyanheads%2Fosv-advisory-mcp-server/0.1.13", "/pypi/mcp-server-fetch/0.6.2/json":
			w.WriteHeader(http.StatusOK)
		case "/@cyanheads%2Fosv-advisory-mcp-server/0.1.23":
			w.WriteHeader(http.StatusNotFound)
		case "/lodash/4.17.21", "/pypi/requests%2Fx/2.0.0/json", "/lodash/1%2F2", "/pypi/requests/1%2F2/json":
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusBadGateway)
		}
	}))
	defer srv.Close()
	r := &HTTPRegistries{NPM: srv.URL, PyPI: srv.URL}
	ctx := context.Background()
	// A name or version that cannot be one path segment, and an ecosystem
	// that is not covered, are refused before anything is asked.
	for _, tc := range []struct{ eco, name, ver string }{
		{"npm", "", "1.0.0"}, {"npm", ".", "1.0.0"}, {"npm", "..", "1.0.0"}, {"npm", "lodash", ""}, {"npm", "lodash", "."}, {"npm", "lodash", ".."},
		{"pypi", "", "1.0.0"}, {"pypi", "requests", ".."}, {"cargo", "x", "1"}, {"", "x", "1"},
	} {
		before := requests.Load()
		if ok, err := (&HTTPRegistries{NPM: srv.URL, PyPI: srv.URL}).Published(context.Background(), tc.eco, tc.name, tc.ver); ok || err == nil {
			t.Errorf("%s %q@%q: %v, %v; want an error", tc.eco, tc.name, tc.ver, ok, err)
		}
		if requests.Load() != before {
			t.Errorf("%s %q@%q: the registry was asked", tc.eco, tc.name, tc.ver)
		}
	}
	for _, tc := range []struct {
		eco, name, ver string
		ok, err        bool
	}{
		{"npm", "@cyanheads/osv-advisory-mcp-server", "0.1.13", true, false},
		{"npm", "@cyanheads/osv-advisory-mcp-server", "0.1.23", false, false},
		{"pypi", "mcp-server-fetch", "0.6.2", true, false},
		{"pypi", "mcp-server-fetch", "9.9.9", false, true},
		{"cargo", "x", "1", false, true},
		{"npm", "lodash", "..", false, true},
		{"npm", "..", "1.0.0", false, true},
		{"npm", "", "1.0.0", false, true},
		{"npm", "lodash", "", false, true},
		{"npm", ".", "1.0.0", false, true},
		{"npm", "lodash", ".", false, true},
		{"pypi", "mcp-server-fetch", "", false, true},
		{"pypi", ".", "1.0.0", false, true},
		// only 200 is published: another success is no answer
		{"npm", "lodash", "4.17.21", false, true},
		// names and versions are one path segment each, escaped
		{"npm", "lodash", "1/2", false, true},
		{"pypi", "requests", "1/2", false, true},
		{"pypi", "requests/x", "2.0.0", false, true},
	} {
		ok, err := r.Published(ctx, tc.eco, tc.name, tc.ver)
		if ok != tc.ok || (err != nil) != tc.err {
			t.Errorf("%s %s@%s: got %v, %v", tc.eco, tc.name, tc.ver, ok, err)
		}
	}
	if !seen["/@cyanheads%2Fosv-advisory-mcp-server/0.1.13"] {
		t.Fatalf("npm path not asked as one segment: %v", seen)
	}
	for _, path := range []string{"/lodash/1%2F2", "/pypi/requests/1%2F2/json", "/pypi/requests%2Fx/2.0.0/json"} {
		if !seen[path] {
			t.Errorf("%s was not asked as one escaped segment: %v", path, seen)
		}
	}
	if len(accept) != 1 || !accept["application/json"] {
		t.Errorf("Accept headers sent: %v", accept)
	}

	// An origin written with a trailing slash asks the same paths, and the
	// client given is the one used; without one, a request times out after 20s.
	slash := &HTTPRegistries{NPM: srv.URL + "/", PyPI: srv.URL + "/"}
	for _, tc := range []struct {
		eco, name, ver string
	}{{"npm", "@cyanheads/osv-advisory-mcp-server", "0.1.13"}, {"pypi", "mcp-server-fetch", "0.6.2"}} {
		if ok, err := slash.Published(ctx, tc.eco, tc.name, tc.ver); !ok || err != nil {
			t.Errorf("trailing slash, %s %s@%s: %v, %v", tc.eco, tc.name, tc.ver, ok, err)
		}
	}
	if got := (&HTTPRegistries{}).httpClient().Timeout; got != 20*time.Second {
		t.Errorf("default client timeout = %v, want 20s", got)
	}
	own := &http.Client{Timeout: time.Second}
	if (&HTTPRegistries{Client: own}).httpClient() != own {
		t.Error("the configured client was not used")
	}
}
