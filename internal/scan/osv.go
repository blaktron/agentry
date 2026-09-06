package scan

import (
	"context"
	"strings"
)

// The OSV seam for S7 (§8.3; reinstated for declared MCP servers by
// agentry#177, DEV-090). S7 asks a vulnerability database about the exact
// npm / PyPI package versions a manifest declares under
// capabilities.mcpServers. The interface is the swap point for an OSV
// mirror behind a VPC endpoint; the default when nothing is configured is
// an offline no-op that answers "not checked", never "no advisories".

// OSVPackage identifies one package version to query.
type OSVPackage struct {
	// Ecosystem is the OSV ecosystem name ("npm", "PyPI").
	Ecosystem string
	// Name is the package name as the ecosystem knows it.
	Name string
	// Version is the exact declared version.
	Version string
}

// Key is the per-package key Query results are grouped under.
func (p OSVPackage) Key() string { return p.Ecosystem + "/" + p.Name + "@" + p.Version }

// OSVVulnerability is one advisory affecting a queried package version.
type OSVVulnerability struct {
	// ID is the advisory id (e.g. "GHSA-…", "PYSEC-…").
	ID string `json:"id"`
	// Aliases are the other ids for the same advisory, CVE ids included.
	Aliases []string `json:"aliases,omitempty"`
	// Summary is the advisory's one-line summary.
	Summary string `json:"summary"`
	// Severity is the advisory's own severity mapped onto the finding
	// vocabulary ("low".."critical"); a finding carries it unchanged (D2).
	Severity string `json:"severity"`
	// FixedIn lists the versions the advisory names as fixed for the
	// package, when it names any.
	FixedIn []string `json:"fixedIn,omitempty"`
	// References are advisory URLs.
	References []string `json:"references,omitempty"`
}

// OSVClient looks up known vulnerabilities for exact package versions. An
// implementation MUST NOT block beyond its context.
type OSVClient interface {
	// Query returns advisories per package, keyed by OSVPackage.Key().
	// Packages with no advisories may be omitted.
	Query(ctx context.Context, pkgs []OSVPackage) (map[string][]OSVVulnerability, error)
}

// OfflineOSV is the default client: it performs no lookup and reports no
// advisories. It exists so the absence of a vulnerability database is a
// visible, testable configuration (S7/osv-not-checked) rather than a
// silently skipped stage.
type OfflineOSV struct{}

// Query implements OSVClient by returning an empty result.
func (OfflineOSV) Query(context.Context, []OSVPackage) (map[string][]OSVVulnerability, error) {
	return map[string][]OSVVulnerability{}, nil
}

// osvEnabled reports whether an OSV client will actually consult a database.
func osvEnabled(c OSVClient) bool {
	if c == nil {
		return false
	}
	_, offline := c.(OfflineOSV)
	return !offline
}

// osvEcosystem maps a manifest ecosystem to its OSV ecosystem name.
func osvEcosystem(eco string) string {
	switch strings.ToLower(eco) {
	case "npm":
		return "npm"
	case "pypi":
		return "PyPI"
	}
	return ""
}
