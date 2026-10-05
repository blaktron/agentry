package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/blaktron/agentry/internal/registry"
	"github.com/blaktron/agentry/pkg/manifest"
)

// The §8.6 policy knobs that reject BEFORE the state machine: submissions
// declaring a blocked capability, public publishes under a license outside
// the allowed set, and (when requireEvals is on) packages with no evals.
//
// All three were parsed, merged and snapshotted onto every scan run — and
// then consulted by nobody. An org could set blockedCapabilities: ["exec"],
// watch it round-trip through the API, and still have exec agents published
// into its namespace.

// CheckSubmission implements registry.PolicyGate.
func (p *Pipeline) CheckSubmission(ctx context.Context, in registry.PolicySubmission) []error {
	pol, _, err := effectivePolicyFor(ctx, p.st.Queries(), in.NamespaceKind, in.NamespaceID)
	if err != nil {
		// Fail closed: a policy we cannot read is not a policy we may skip.
		p.log.Error("scan: submission policy unavailable", "err", err)
		return []error{fmt.Errorf("the registry could not read this namespace's policy and refused the submission: %w", err)}
	}
	return CheckSubmissionPolicy(pol, in)
}

// CheckSubmissionPolicy is the pure form: effective policy + submission →
// blocking issues. Exported so the knobs are testable without a database.
func CheckSubmissionPolicy(pol Policy, in registry.PolicySubmission) []error {
	var issues []error

	// blockedCapabilities: "submissions declaring these are rejected at
	// V-validation" (§8.6). Compared against the same capability vocabulary
	// S6 diffs the manifest with, so policy and findings speak one language.
	if len(pol.BlockedCapabilities) > 0 {
		declared := declaredCaps(in.ManifestJSON)
		var hit []string
		for _, c := range pol.BlockedCapabilities {
			if declared[strings.TrimSpace(c)] {
				hit = append(hit, c)
			}
		}
		sort.Strings(hit)
		for _, c := range hit {
			issues = append(issues, fmt.Errorf(
				"this namespace's policy blocks capability %q (blockedCapabilities); remove it from the manifest", c))
		}
	}

	// allowedLicenses: "public publishes outside list are rejected" (§8.6).
	// Private agents are out of scope by the same wording — the list governs
	// what the namespace puts into the world.
	if len(pol.BlockedMcpServers) > 0 {
		for _, srv := range declaredMcpServers(in.ManifestJSON) {
			for _, pat := range pol.BlockedMcpServers {
				if ok, _ := path.Match(strings.TrimSpace(pat), srv); ok {
					issues = append(issues, fmt.Errorf(
						"this namespace's policy blocks MCP server %q (blockedMcpServers pattern %s); remove it from the manifest", srv, pat))
					break
				}
			}
		}
	}

	if in.Public && len(pol.AllowedLicenses) > 0 && !licenseAllowed(pol.AllowedLicenses, in.License) {
		issues = append(issues, fmt.Errorf(
			"license %q is not one this namespace allows for public publishes (allowedLicenses: %s)",
			in.License, strings.Join(pol.AllowedLicenses, ", ")))
	}

	// requireEvals: "evals/ dir must exist and be non-empty" (§8.6).
	if pol.RequireEvals && !hasEvals(in.Files) {
		issues = append(issues, fmt.Errorf(
			"add an evals/ directory with at least one file; this namespace's policy requires it (requireEvals)"))
	}
	return issues
}

// licenseAllowed compares SPDX ids case-insensitively: SPDX ids are
// case-sensitive by spec, but rejecting a publish over "apache-2.0" vs
// "Apache-2.0" would be a policy engine failing on punctuation. A license
// EXPRESSION (agentry#28) is allowed only when every identifier in it is —
// the strict reading: an org that allows MIT has not allowed
// "MIT AND Proprietary-EULA", and for a disjunction the consumer may end
// up under whichever side, so both must be acceptable.
func licenseAllowed(allowed []string, license string) bool {
	if strings.TrimSpace(license) == "" {
		return false
	}
	_, ids, err := manifest.ParseSPDXExpression(license)
	if err != nil || len(ids) == 0 {
		return false
	}
	for _, id := range ids {
		ok := false
		for _, a := range allowed {
			if strings.EqualFold(strings.TrimSpace(a), id) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// hasEvals reports whether the workspace carries a non-empty evals/ tree.
// A present-but-empty directory does not count: the knob exists so that
// something was actually evaluated.
func hasEvals(files []manifest.FileInfo) bool {
	for _, f := range files {
		if f.Symlink {
			continue
		}
		p := strings.TrimPrefix(f.Path, "./")
		if strings.HasPrefix(p, "evals/") && f.Size > 0 {
			return true
		}
	}
	return false
}

// declaredMcpServers lists a manifest's capabilities.mcpServers as
// "npm:<package>" / "pypi:<package>", or "url:<host>" for a remote
// server, sorted, for the blocklist compare.
func declaredMcpServers(manifestJSON []byte) []string {
	var m manifest.Manifest
	if err := json.Unmarshal(manifestJSON, &m); err != nil {
		return nil
	}
	var out []string
	for _, srv := range m.Capabilities.MCPServers {
		switch {
		case srv.IsRemote():
			// A remote server is matched by its host (agentry#910).
			if host := srv.RemoteHost(); host != "" {
				out = append(out, "url:"+host)
			}
		case srv.NPM != "" || srv.PyPI != "":
			out = append(out, srv.SourceID())
		}
	}
	sort.Strings(out)
	return out
}
