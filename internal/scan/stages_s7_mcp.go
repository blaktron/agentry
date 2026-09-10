package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/blaktron/agentry/pkg/manifest"
)

// S7 — declared MCP servers: known vulnerabilities (§8.3; reinstated for
// manifest v2 by agentry#177, plan agentry-notes/plans/mcp-vuln-scanning.md,
// DEV-090). Every `capabilities.mcpServers` entry is an exact npm or PyPI
// package version. S7 asks the vulnerability database about each one — live
// the first time a package version is seen, from the mcp_server_scans
// registry when it was checked within mcpScanTTL — and reports every
// advisory as a finding at the advisory's own severity, so a high or
// critical CVE gates like any other high or critical finding.
//
// The stage depends on the database, not the archive, so its result is
// never served from the archive-keyed stage cache (NoCache).

// mcpScanTTL is how long a registry row answers for a server version before
// S7 asks the database again; the daily sweep refreshes rows sooner.
const mcpScanTTL = 24 * time.Hour

// MCPScanRecord is one row of the scanned-server registry.
type MCPScanRecord struct {
	Ecosystem string
	Package   string
	Version   string
	// Status is "safe" (no known advisories at LastChecked), "vulnerable"
	// or "error" (the last lookup failed; Advisories are the last known).
	Status      string
	MaxSeverity string
	Advisories  []OSVVulnerability
	FirstSeen   time.Time
	LastChecked time.Time
	LastError   string
}

// MCPScanCache is the registry of scanned server versions S7 reads and
// writes; the pipeline implements it over the store, tests in memory.
type MCPScanCache interface {
	Get(ctx context.Context, ecosystem, pkg, version string) (*MCPScanRecord, error)
	Put(ctx context.Context, rec MCPScanRecord) error
}

// MemoryMCPScanCache is an in-memory MCPScanCache for tests and for a
// process with no store.
type MemoryMCPScanCache struct {
	mu   sync.Mutex
	rows map[string]MCPScanRecord
}

// Get implements MCPScanCache.
func (m *MemoryMCPScanCache) Get(_ context.Context, eco, pkg, ver string) (*MCPScanRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.rows[eco+"/"+pkg+"@"+ver]
	if !ok {
		return nil, nil
	}
	return &r, nil
}

// Put implements MCPScanCache.
func (m *MemoryMCPScanCache) Put(_ context.Context, rec MCPScanRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.rows == nil {
		m.rows = map[string]MCPScanRecord{}
	}
	if rec.LastChecked.IsZero() {
		rec.LastChecked = time.Now()
	}
	if rec.FirstSeen.IsZero() {
		rec.FirstSeen = rec.LastChecked
	}
	m.rows[rec.Ecosystem+"/"+rec.Package+"@"+rec.Version] = rec
	return nil
}

// S7MCPServers is the stage.
type S7MCPServers struct {
	// now is injectable for the TTL tests.
	now func() time.Time
}

// ID implements Stage.
func (S7MCPServers) ID() string { return "S7" }

// declaredServer is one manifest entry in the shape S7 needs.
type declaredServer struct {
	Ecosystem string
	Package   string
	Version   string
}

// DeclaredMCPServers lists a manifest's declared servers (ecosystem "npm" or
// "pypi"). The pipeline uses it to record the version ↔ server join.
func DeclaredMCPServers(manifestJSON []byte) []declaredServer {
	var m manifest.Manifest
	if len(manifestJSON) == 0 || json.Unmarshal(manifestJSON, &m) != nil {
		return nil
	}
	var out []declaredServer
	for _, s := range m.Capabilities.MCPServers {
		switch {
		case s.NPM != "" && s.Version != "":
			out = append(out, declaredServer{Ecosystem: "npm", Package: s.NPM, Version: s.Version})
		case s.PyPI != "" && s.Version != "":
			out = append(out, declaredServer{Ecosystem: "pypi", Package: s.PyPI, Version: s.Version})
		}
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].Ecosystem != out[b].Ecosystem {
			return out[a].Ecosystem < out[b].Ecosystem
		}
		if out[a].Package != out[b].Package {
			return out[a].Package < out[b].Package
		}
		return out[a].Version < out[b].Version
	})
	return out
}

// Run implements Stage.
func (s S7MCPServers) Run(sc stageContext, in *Input) StageResult {
	res := StageResult{Scanner: "S7", NoCache: true}
	servers := DeclaredMCPServers(in.ManifestJSON)
	if len(servers) == 0 {
		return res
	}
	now := time.Now
	if s.now != nil {
		now = s.now
	}
	if !osvEnabled(sc.osv) {
		res.Findings = append(res.Findings, Finding{
			Scanner: "S7/osv-not-checked", Severity: SevInfo, Confidence: ConfLow,
			Title: fmt.Sprintf("%d declared MCP server(s); no vulnerability database consulted", len(servers)),
			Detail: map[string]any{
				"servers": len(servers),
				"reason":  "no OSV API configured (AGENTRY_SCAN_OSV_URL=none), so the pipeline did not check these servers for known vulnerabilities",
			},
			Taxonomy: []string{"LLM03", "ASI04"},
		})
		return res
	}
	ctx := sc.Context()
	// Fresh registry rows answer directly; the rest are looked up in one batch.
	records := make([]*MCPScanRecord, len(servers))
	var lookup []OSVPackage
	lookupIdx := map[string]int{}
	for i, d := range servers {
		var rec *MCPScanRecord
		if sc.mcpCache != nil {
			r, err := sc.mcpCache.Get(ctx, d.Ecosystem, d.Package, d.Version)
			if err != nil {
				sc.log.Warn("scan: S7 registry read", "server", d.Ecosystem+":"+d.Package+"@"+d.Version, "err", err)
			}
			rec = r
		}
		if rec != nil && rec.Status != "error" && now().Sub(rec.LastChecked) < mcpScanTTL {
			records[i] = rec
			continue
		}
		records[i] = rec // stale or errored: kept as the fallback
		p := OSVPackage{Ecosystem: osvEcosystem(d.Ecosystem), Name: d.Package, Version: d.Version}
		lookupIdx[p.Key()] = i
		lookup = append(lookup, p)
	}
	if len(lookup) > 0 {
		vulns, err := sc.osv.Query(ctx, lookup)
		if err != nil {
			// Registry rows, stale or not, are better evidence than nothing;
			// a server with no row at all is reported as unchecked.
			var unchecked []string
			for _, p := range lookup {
				i := lookupIdx[p.Key()]
				d := servers[i]
				if records[i] == nil {
					unchecked = append(unchecked, d.Ecosystem+":"+d.Package+"@"+d.Version)
					if sc.mcpCache != nil {
						_ = sc.mcpCache.Put(ctx, MCPScanRecord{Ecosystem: d.Ecosystem, Package: d.Package, Version: d.Version,
							Status: "error", LastChecked: now(), LastError: err.Error()})
					}
				}
			}
			if len(unchecked) > 0 {
				res.Findings = append(res.Findings, Finding{
					Scanner: "S7/osv-error", Severity: SevMedium, Confidence: ConfHigh,
					Title:    "Vulnerability lookup failed for declared MCP server(s)",
					Detail:   map[string]any{"error": err.Error(), "servers": unchecked},
					Taxonomy: []string{"LLM03", "ASI04"},
				})
			}
		} else {
			for _, p := range lookup {
				i := lookupIdx[p.Key()]
				d := servers[i]
				advs := vulns[p.Key()]
				rec := MCPScanRecord{Ecosystem: d.Ecosystem, Package: d.Package, Version: d.Version,
					Status: "safe", Advisories: advs, LastChecked: now()}
				if len(advs) > 0 {
					rec.Status = "vulnerable"
					rec.MaxSeverity = worstSeverity(advs)
				}
				if records[i] != nil {
					rec.FirstSeen = records[i].FirstSeen
				}
				if sc.mcpCache != nil {
					if err := sc.mcpCache.Put(ctx, rec); err != nil {
						sc.log.Warn("scan: S7 registry write", "server", d.Ecosystem+":"+d.Package+"@"+d.Version, "err", err)
					}
				}
				records[i] = &rec
			}
		}
	}
	for i, d := range servers {
		rec := records[i]
		if rec == nil {
			continue
		}
		ref := d.Ecosystem + ":" + d.Package + "@" + d.Version
		for _, v := range rec.Advisories {
			title := "Known vulnerability in " + ref + ": " + v.ID
			if len(v.Aliases) > 0 {
				title += " (" + strings.Join(v.Aliases, ", ") + ")"
			}
			detail := map[string]any{
				"ecosystem": d.Ecosystem, "package": d.Package, "version": d.Version,
				"advisory": v.ID, "aliases": v.Aliases, "summary": v.Summary,
				"references": v.References, "checkedAt": rec.LastChecked.UTC().Format(time.RFC3339),
			}
			if len(v.FixedIn) > 0 {
				detail["fixedIn"] = v.FixedIn
			}
			res.Findings = append(res.Findings, Finding{
				Scanner: "S7/mcp-vuln-" + findingIDSuffix(v.ID), Severity: Severity(v.Severity), Confidence: ConfHigh,
				Title: title, Detail: detail, Taxonomy: []string{"LLM03", "ASI04"},
			})
		}
	}
	return res
}

// worstSeverity is the highest severity among advisories.
func worstSeverity(advs []OSVVulnerability) string {
	worst := ""
	for _, v := range advs {
		if severityRank(Severity(v.Severity)) > severityRank(Severity(worst)) {
			worst = v.Severity
		}
	}
	return worst
}

// findingIDSuffix keeps an advisory id safe for a scanner id.
func findingIDSuffix(id string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(id) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	return b.String()
}
