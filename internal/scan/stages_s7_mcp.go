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
// DEV-090). A `capabilities.mcpServers` package entry is an exact npm
// or PyPI package version; a remote entry (agentry#910) has no package
// and is reported as S7/remote-server, never looked up. S7 asks the vulnerability database about each one — live
// the first time a package version is seen, from the mcp_server_scans
// registry when it was checked within mcpScanTTL — and reports every
// advisory as a finding at the gate's rating of it (AdvisoryGateSeverity:
// a Critical rejects, a High holds from CVSS 8.5 and is medium below it;
// agentry#774). A server it has no data for is one medium finding,
// S7/osv-no-data, which publishes (the tweaks plan's D3).
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
	// Status is "safe" (no known advisories at LastChecked), "vulnerable",
	// "error" (a lookup failed before any answer: no Advisories, and S7
	// counts it as no answer) or "not-found" (the server's package registry
	// does not publish this version, agentry#1036: OSV is not asked, and the
	// daily sweep leaves the row as it is). A lookup that fails after an
	// answer keeps the answer's Status and only sets LastError.
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

// scannerOSVNoData is the finding for declared servers the scan has no
// vulnerability data for: the lookup failed with no earlier answer, the
// ecosystem is not one S7 covers, or the server has no pinned version. It
// is medium and does not force review, so the version publishes with it on
// its report (the tweaks plan's D3); the daily sweep asks again about every
// registry row, a failed one included. A package the database knows
// nothing about is not "no data" (the operator,
// 2026-09-30: no reported issues yet is not a risk) and is recorded with
// no advisories.
const scannerOSVNoData = "S7/osv-no-data"

// scannerRemoteServer is the finding for a remote MCP server (agentry#910,
// plan mcp-oauth-connections.md D11): it runs at its vendor, so there is no
// package or version to look up and no code the pipeline reads. It is low
// and publishes; it names the address, the auth and the scopes, which are
// what the pipeline can state about it, and says nothing of the vendor's
// code (honest posture).
const scannerRemoteServer = "S7/remote-server"

// scannerVersionNotPublished is the finding for a declared server whose
// package registry does not publish the pinned version (agentry#1036). No
// run can install it, so the version is refused: the finding is critical,
// which the gate rejects (the operator, 2026-10-10). OSV answers "no
// advisories" for a version that does not exist, which is how such a
// release used to publish with its server recorded as safe.
const scannerVersionNotPublished = "S7/version-not-published"

// scannerVersionNotChecked is the finding for declared servers whose
// registry gave no answer: medium, and it publishes, as S7/osv-no-data does
// (the operator, 2026-10-10: a registry that cannot be reached is "not
// checked", never "safe").
const scannerVersionNotChecked = "S7/version-not-checked"

// The reasons S7/osv-no-data names per server.
const (
	noDataLookupFailed = "lookup failed"
	noDataEcosystem    = "ecosystem not covered"
	noDataNoVersion    = "no pinned version"
)

// scored reports whether every advisory on the row was read since CVSS
// vectors were scored. A row written before that is asked about again, so
// a High below 8.5 is not judged high for want of a score (agentry#774).
func (r *MCPScanRecord) scored() bool {
	for _, a := range r.Advisories {
		if !a.Scored {
			return false
		}
	}
	return true
}

// scoredAdvisories marks advisories as read since scores were (see
// OSVVulnerability.Scored), for a registry row about to be written from a
// lookup's answer.
func scoredAdvisories(advs []OSVVulnerability) []OSVVulnerability {
	out := make([]OSVVulnerability, len(advs))
	for i, a := range advs {
		a.Scored = true
		out[i] = a
	}
	return out
}

// DeclaredMCPServers lists a manifest's declared servers (ecosystem "npm" or
// "pypi"). The pipeline uses it to record the version ↔ server join.
func DeclaredMCPServers(manifestJSON []byte) []declaredServer {
	out, _, _, _ := mcpServerEntries(manifestJSON)
	return out
}

// mcpServerEntries splits a manifest's declared servers into those S7 can
// look up, sorted; in manifest order with a reason each, those it cannot
// (neither npm nor PyPI, or no pinned version: manifest validation (V5)
// refuses both, so they only reach S7 in a manifest that came some other
// way, and S7 still names them rather than drop them); and the remote
// servers, which S7 reports and never looks up.
func mcpServerEntries(manifestJSON []byte) (declared []declaredServer, uncovered []string, reasons map[string]string, remote []manifest.MCPServer) {
	var m manifest.Manifest
	if len(manifestJSON) == 0 || json.Unmarshal(manifestJSON, &m) != nil {
		return nil, nil, nil, nil
	}
	reasons = map[string]string{}
	for i, s := range m.Capabilities.MCPServers {
		var ref, why string
		switch {
		case s.IsRemote():
			remote = append(remote, s)
			continue
		case s.NPM != "" && s.Version != "":
			declared = append(declared, declaredServer{Ecosystem: "npm", Package: s.NPM, Version: s.Version})
			continue
		case s.PyPI != "" && s.Version != "":
			declared = append(declared, declaredServer{Ecosystem: "pypi", Package: s.PyPI, Version: s.Version})
			continue
		case s.NPM != "":
			ref, why = "npm:"+s.NPM, noDataNoVersion
		case s.PyPI != "":
			ref, why = "pypi:"+s.PyPI, noDataNoVersion
		default:
			ref, why = fmt.Sprintf("capabilities.mcpServers[%d]", i), noDataEcosystem
		}
		uncovered = append(uncovered, ref)
		reasons[ref] = why
	}
	sort.Slice(declared, func(a, b int) bool {
		if declared[a].Ecosystem != declared[b].Ecosystem {
			return declared[a].Ecosystem < declared[b].Ecosystem
		}
		if declared[a].Package != declared[b].Package {
			return declared[a].Package < declared[b].Package
		}
		return declared[a].Version < declared[b].Version
	})
	return declared, uncovered, reasons, remote
}

// remoteServerFindings reports each remote server: its address, its auth
// and its scopes.
func remoteServerFindings(remote []manifest.MCPServer) []Finding {
	var out []Finding
	for _, srv := range remote {
		scopes := srv.Scopes
		if scopes == nil {
			scopes = []string{}
		}
		title := "Remote MCP server " + srv.URL + " (auth " + string(srv.Auth)
		if len(scopes) > 0 {
			title += "; scopes " + strings.Join(scopes, ", ")
		}
		out = append(out, Finding{
			Scanner: scannerRemoteServer, Severity: SevLow, Confidence: ConfHigh,
			Title:    title + "): it runs at its vendor; the pipeline checked its address and scopes, not its code",
			Detail:   map[string]any{"url": srv.URL, "host": srv.RemoteHost(), "auth": string(srv.Auth), "scopes": scopes},
			Taxonomy: []string{"LLM03", "ASI04"},
		})
	}
	return out
}

// Run implements Stage.
func (s S7MCPServers) Run(sc stageContext, in *Input) StageResult {
	res := StageResult{Scanner: "S7", NoCache: true}
	servers, noData, reasons, remote := mcpServerEntries(in.ManifestJSON)
	res.Findings = append(res.Findings, remoteServerFindings(remote)...)
	if len(servers) == 0 && len(noData) == 0 {
		return res
	}
	now := time.Now
	if s.now != nil {
		now = s.now
	}
	// Each declared version is asked of its own registry first. One it does
	// not publish is refused and never asked of OSV, whose "no advisories"
	// would only say nothing about a version that does not exist.
	servers, res.Findings = s.checkPublished(sc, servers, now, res.Findings)
	if len(servers) == 0 && len(noData) == 0 {
		return res
	}
	if !osvEnabled(sc.osv) {
		res.Findings = append(res.Findings, Finding{
			Scanner: "S7/osv-not-checked", Severity: SevInfo, Confidence: ConfLow,
			Title: fmt.Sprintf("%d declared MCP server(s); no vulnerability database consulted", len(servers)+len(noData)),
			Detail: map[string]any{
				"servers": len(servers) + len(noData),
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
		// A not-found row is no OSV answer: the registry has published the
		// version since (checkPublished just said so), so OSV is asked.
		if rec != nil && rec.Status != "error" && rec.Status != "not-found" && now().Sub(rec.LastChecked) < mcpScanTTL && rec.scored() {
			records[i] = rec
			continue
		}
		records[i] = rec // stale, errored or unscored: kept as the fallback
		p := OSVPackage{Ecosystem: osvEcosystem(d.Ecosystem), Name: d.Package, Version: d.Version}
		lookupIdx[p.Key()] = i
		lookup = append(lookup, p)
	}
	var lookupErr error
	if len(lookup) > 0 {
		vulns, err := sc.osv.Query(ctx, lookup)
		if err != nil {
			// Registry rows, stale or not, are better evidence than nothing;
			// a server with no row at all has no data, and neither has one
			// whose only row is the error row an earlier failed lookup wrote:
			// that row holds no answer, and counting it as one let the second
			// submission during an outage pass with no finding at all
			// (agentry#480).
			lookupErr = err
			for _, p := range lookup {
				i := lookupIdx[p.Key()]
				d := servers[i]
				if records[i] == nil || records[i].Status == "error" || records[i].Status == "not-found" {
					ref := d.Ecosystem + ":" + d.Package + "@" + d.Version
					noData = append(noData, ref)
					reasons[ref] = noDataLookupFailed
					if sc.mcpCache != nil {
						_ = sc.mcpCache.Put(ctx, MCPScanRecord{Ecosystem: d.Ecosystem, Package: d.Package, Version: d.Version,
							Status: "error", LastChecked: now(), LastError: err.Error()})
					}
				}
			}
		} else {
			for _, p := range lookup {
				i := lookupIdx[p.Key()]
				d := servers[i]
				advs := scoredAdvisories(vulns[p.Key()])
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
	if len(noData) > 0 {
		detail := map[string]any{"servers": noData, "reasons": reasons}
		if lookupErr != nil {
			detail["error"] = lookupErr.Error()
		}
		res.Findings = append(res.Findings, Finding{
			Scanner: scannerOSVNoData, Severity: SevMedium, Confidence: ConfHigh,
			Title:    "No vulnerability data for declared MCP server(s)",
			Detail:   detail,
			Taxonomy: []string{"LLM03", "ASI04"},
		})
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
			// The finding carries the gate's rating; the detail keeps the
			// advisory's own severity and its score, which the report shows.
			detail["advisorySeverity"] = v.Severity
			if v.CVSSScore != nil {
				detail["cvssScore"] = *v.CVSSScore
			}
			res.Findings = append(res.Findings, Finding{
				Scanner: "S7/mcp-vuln-" + findingIDSuffix(v.ID), Severity: AdvisoryGateSeverity(v), Confidence: ConfHigh,
				Title: title, Detail: detail, Taxonomy: []string{"LLM03", "ASI04"},
			})
		}
	}
	return res
}

// checkPublished asks each declared server's registry whether it publishes
// the pinned version (agentry#1036), and answers the servers that remain to
// be looked up in OSV and the findings with S7's own added. It asks on every
// submission, one GET a server, and never answers from the not-found row:
// that row would stand while the sweep refreshed it, so a version published
// after one refusal, or a future version someone submitted early to poison
// it, would read as missing for good. The row only keeps OSV and the sweep
// from calling the version safe.
func (s S7MCPServers) checkPublished(sc stageContext, servers []declaredServer, now func() time.Time, findings []Finding) (keep []declaredServer, out []Finding) {
	out = findings
	if sc.registries == nil {
		return servers, out // not wired (tests, a process with no scan config)
	}
	if !registriesEnabled(sc.registries) {
		if len(servers) > 0 {
			out = append(out, Finding{
				Scanner: scannerVersionNotChecked, Severity: SevInfo, Confidence: ConfLow,
				Title:    fmt.Sprintf("%d declared MCP server version(s); not checked against their package registries", len(servers)),
				Detail:   map[string]any{"reason": "the version check is off (AGENTRY_SCAN_NPM_REGISTRY=none)"},
				Taxonomy: []string{"LLM03", "ASI04"},
			})
		}
		return servers, out
	}
	ctx := sc.Context()
	var unchecked []string
	var lastErr error
	for _, d := range servers {
		ref := d.Ecosystem + ":" + d.Package + "@" + d.Version
		published, err := sc.registries.Published(ctx, d.Ecosystem, d.Package, d.Version)
		if err != nil {
			// No answer: the server goes on to OSV as before, and the report
			// says its version was not checked.
			unchecked = append(unchecked, ref)
			lastErr = err
			keep = append(keep, d)
			continue
		}
		if published {
			keep = append(keep, d)
			continue
		}
		if sc.mcpCache != nil {
			rec := MCPScanRecord{Ecosystem: d.Ecosystem, Package: d.Package, Version: d.Version,
				Status: "not-found", LastChecked: now()}
			if err := sc.mcpCache.Put(ctx, rec); err != nil {
				sc.log.Warn("scan: S7 registry write", "server", ref, "err", err)
			}
		}
		out = append(out, Finding{
			Scanner: scannerVersionNotPublished, Severity: SevCritical, Confidence: ConfHigh,
			Title: "Declared MCP server " + ref + " is not published: its package registry does not have this version, so no run could install it",
			Detail: map[string]any{"ecosystem": d.Ecosystem, "package": d.Package, "version": d.Version,
				"checkedAt": now().UTC().Format(time.RFC3339)},
			Taxonomy: []string{"LLM03", "ASI04"},
		})
	}
	if len(unchecked) > 0 {
		out = append(out, Finding{
			Scanner: scannerVersionNotChecked, Severity: SevMedium, Confidence: ConfHigh,
			Title:    "Could not check that declared MCP server version(s) are published",
			Detail:   map[string]any{"servers": unchecked, "error": lastErr.Error()},
			Taxonomy: []string{"LLM03", "ASI04"},
		})
	}
	return keep, out
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
