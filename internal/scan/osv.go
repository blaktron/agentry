package scan

import "context"

// The OSV seam for S7 (§8.3: "osv-scanner … for known-vuln deps"). The scanner
// task profile has no outbound network (§8.2), so the default implementation
// is an offline no-op: it answers "no advisories known" rather than pretending
// to have looked. The interface is the swap point for an embedded osv-scanner
// database or a VPC-endpoint client (DEV-006, DEV-026) — nothing in this
// package ever dials.

// OSVPackage identifies one resolved dependency to query.
type OSVPackage struct {
	// Ecosystem is the OSV ecosystem name ("npm", "PyPI").
	Ecosystem string
	// Name is the package name as the ecosystem knows it.
	Name string
	// Version is the exact resolved version from the lockfile.
	Version string
}

// OSVVulnerability is one advisory affecting a queried package.
type OSVVulnerability struct {
	// ID is the advisory id (e.g. "GHSA-…", "OSV-…").
	ID string
	// Summary is the advisory's one-line summary.
	Summary string
	// Severity is the OSV severity mapped to the finding vocabulary
	// ("low".."critical").
	Severity string
	// KnownExploited marks advisories with a documented exploit; §8.3 makes
	// these the ones that produce a high finding.
	KnownExploited bool
	// References are advisory URLs.
	References []string
}

// OSVClient looks up known vulnerabilities for resolved dependencies. An
// implementation MUST be deterministic for a given input set (the §8.7
// results cache keys stage output by archive digest) and MUST NOT block
// beyond its context.
type OSVClient interface {
	// Query returns advisories per package, keyed by "<ecosystem>/<name>".
	// Packages with no advisories may be omitted.
	Query(ctx context.Context, pkgs []OSVPackage) (map[string][]OSVVulnerability, error)
}

// OfflineOSV is the default client: it performs no lookup and reports no
// advisories. It exists so the absence of a vulnerability database is a
// visible, testable configuration rather than a silently skipped stage.
type OfflineOSV struct{}

// Query implements OSVClient by returning an empty result.
func (OfflineOSV) Query(context.Context, []OSVPackage) (map[string][]OSVVulnerability, error) {
	return map[string][]OSVVulnerability{}, nil
}

// Enabled reports whether an OSV client will actually consult a database. It
// lets S7 record "not checked" instead of "no vulnerabilities" on the report.
func osvEnabled(c OSVClient) bool {
	if c == nil {
		return false
	}
	_, offline := c.(OfflineOSV)
	return !offline
}

// osvEcosystem maps a lockfile kind to its OSV ecosystem name.
func osvEcosystem(kind string) string {
	switch kind {
	case "npm":
		return "npm"
	case "uv", "pip":
		return "PyPI"
	}
	return ""
}

// osvSeverityRank maps an advisory severity onto the finding severity, with
// the §8.3 rule that a known-exploited critical is a high finding.
func osvSeverity(v OSVVulnerability) Severity {
	switch v.Severity {
	case "critical":
		if v.KnownExploited {
			return SevHigh
		}
		return SevMedium
	case "high":
		return SevMedium
	case "moderate", "medium":
		return SevLow
	default:
		return SevInfo
	}
}
