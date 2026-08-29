package scan

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/PLACEHOLDER_ORG/agentry/internal/registry"
	"github.com/PLACEHOLDER_ORG/agentry/pkg/manifest"
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
		return []error{fmt.Errorf("policy could not be evaluated for this namespace; submission refused: %w", err)}
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
				"capability %q is blocked by policy for this namespace (§8.6 blockedCapabilities)", c))
		}
	}

	// allowedLicenses: "public publishes outside list are rejected" (§8.6).
	// Private agents are out of scope by the same wording — the list governs
	// what the namespace puts into the world.
	if in.Public && len(pol.AllowedLicenses) > 0 && !licenseAllowed(pol.AllowedLicenses, in.License) {
		issues = append(issues, fmt.Errorf(
			"license %q is not in the allowed set for public publishes (%s) (§8.6 allowedLicenses)",
			in.License, strings.Join(pol.AllowedLicenses, ", ")))
	}

	// requireEvals: "evals/ dir must exist and be non-empty" (§8.6).
	if pol.RequireEvals && !hasEvals(in.Files) {
		issues = append(issues, fmt.Errorf(
			"policy requires an evals/ directory with at least one file (§8.6 requireEvals)"))
	}
	return issues
}

// licenseAllowed compares SPDX ids case-insensitively: SPDX ids are
// case-sensitive by spec, but rejecting a publish over "apache-2.0" vs
// "Apache-2.0" would be a policy engine failing on punctuation.
func licenseAllowed(allowed []string, license string) bool {
	got := strings.ToLower(strings.TrimSpace(license))
	if got == "" {
		return false
	}
	for _, a := range allowed {
		if strings.ToLower(strings.TrimSpace(a)) == got {
			return true
		}
	}
	return false
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
