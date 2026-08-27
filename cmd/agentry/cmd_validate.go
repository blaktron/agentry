// `agentry validate` (§11, D-12): offline parity with the server's submit
// validation — manifest rules V1–V8 via pkg/manifest plus the S3/S4 scan
// via pkg/rules, run over the files that publish would actually ship.
package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/PLACEHOLDER_ORG/agentry/internal/registry"
	"github.com/PLACEHOLDER_ORG/agentry/internal/scan/ruleset"
	"github.com/PLACEHOLDER_ORG/agentry/pkg/manifest"
	"github.com/PLACEHOLDER_ORG/agentry/pkg/rules"
)

// newValidateCmd builds the validate command.
func newValidateCmd() *cobra.Command {
	var strict bool
	cmd := &cobra.Command{
		Use:   "validate [dir]",
		Short: "Validate a workspace offline (manifest rules V1-V8 + S3/S4 content scan)",
		Long: "Validate a workspace offline with the same code the registry runs at submit\n" +
			"time (D-12 local/remote parity): manifest rules V1-V8 (public-publish context,\n" +
			"so V7 runs) plus the S3 hidden-content detectors and the S4 injection-signature\n" +
			"scan over the files publish.include would ship.\n\n" +
			"The S4 rule bundle is read from $AGENTRY_RULES_DIR, else ./rules; when absent,\n" +
			"S4 is skipped with a warning (S3 needs no bundle and always runs). Release\n" +
			"builds will embed the bundle — deferred until the CLI release pipeline exists.\n\n" +
			"Exit code: 0 clean; 1 on manifest errors or scan findings. Manifest warnings\n" +
			"fail only with --strict.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := "."
			if len(args) == 1 {
				dir = args[0]
			}
			return runValidate(cmd, dir, strict)
		},
	}
	cmd.Flags().BoolVar(&strict, "strict", false, "treat manifest warnings as errors")
	return cmd
}

// runValidate executes the offline validation over dir.
func runValidate(cmd *cobra.Command, dir string, strict bool) error {
	out := cmd.OutOrStdout()

	m, err := readWorkspaceManifest(dir)
	if err != nil {
		return err
	}

	files, err := registry.WalkWorkspace(dir)
	if err != nil {
		return fmt.Errorf("walk workspace %s: %w", dir, err)
	}

	// Server parity context: namespace/name from the manifest itself (the
	// CLI cannot know the target repo), Public so V7 runs, no tag (upload
	// source semantics), no existing versions.
	issues := manifest.ValidateInContext(m, manifest.Context{
		Namespace: m.Namespace,
		Name:      m.Name,
		Public:    true,
		Files:     files,
	})
	var errCount, warnCount int
	for _, issue := range issues {
		if manifest.IsWarning(issue) {
			warnCount++
		} else {
			errCount++
		}
	}
	if len(issues) == 0 {
		_, _ = fmt.Fprintln(out, "manifest: OK (rules V1-V8, public-publish context)")
	} else {
		_, _ = fmt.Fprintf(out, "manifest: %d error(s), %d warning(s)\n", errCount, warnCount)
		printManifestIssues(out, issues)
	}

	// Scan exactly what publish would ship: the resolved include set.
	scanFiles, readErrs := loadScanFiles(dir, m, files)
	errCount += len(readErrs)
	for _, e := range readErrs {
		_, _ = fmt.Fprintf(out, "  ERROR read: %v\n", e)
	}

	bundle, err := loadRulesBundle()
	if err != nil {
		// Fail closed: never report PASSED on content S4 did not examine.
		return err
	}
	findings := rules.Scan(bundle, scanFiles)
	sortFindings(findings)

	switch {
	case len(findings) == 0:
		_, _ = fmt.Fprintf(out, "scan: clean — %d file(s), S3 + S4 (bundle %s)\n", len(scanFiles), bundle.Version())
	default:
		_, _ = fmt.Fprintf(out, "scan: %d finding(s) over %d file(s)\n", len(findings), len(scanFiles))
		for _, f := range findings {
			printFinding(out, f)
		}
	}
	failed := errCount > 0 || len(findings) > 0 || (strict && warnCount > 0)
	if failed {
		return fmt.Errorf("validate failed: %d error(s), %d warning(s), %d finding(s)", errCount, warnCount, len(findings))
	}
	_, _ = fmt.Fprintln(out, "validate: PASSED")
	return nil
}

// readWorkspaceManifest loads and parses dir/agent.yaml.
func readWorkspaceManifest(dir string) (*manifest.Manifest, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "agent.yaml")) //nolint:gosec // user-named workspace
	if err != nil {
		return nil, fmt.Errorf("read agent.yaml: %w", err)
	}
	m, err := manifest.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse agent.yaml: %w", err)
	}
	return m, nil
}

// loadScanFiles reads the resolved include set (what the archive would
// contain) for scanning; symlinks are skipped (V4 already rejects them).
func loadScanFiles(dir string, m *manifest.Manifest, files []manifest.FileInfo) ([]rules.File, []error) {
	include := manifest.ResolveInclude(m.Publish.Include, files)
	scanFiles := make([]rules.File, 0, len(include))
	var errs []error
	for _, fi := range include {
		if fi.Symlink {
			continue
		}
		content, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(fi.Path))) //nolint:gosec // paths come from WalkWorkspace
		if err != nil {
			errs = append(errs, err)
			continue
		}
		scanFiles = append(scanFiles, rules.File{Path: fi.Path, Content: content})
	}
	return scanFiles, errs
}

// loadRulesBundle resolves the S4 signature bundle.
//
// The bundle is EMBEDDED in the binary (internal/scan/ruleset), so local/remote
// scan parity (D-12) does not depend on where the CLI is run from. The
// AGENTRY_RULES_DIR environment variable and a ./rules directory override it,
// for rule development against an unreleased bundle.
//
// A malformed override is a hard error, not a warning: silently skipping S4
// would report "validate: PASSED" on content the signature engine never
// examined, which is the same failure mode §7 forbids on the server (never
// pass on scanner failure).
func loadRulesBundle() (*rules.Bundle, error) {
	if d := os.Getenv(envRulesDir); d != "" {
		b, err := rules.LoadBundle(os.DirFS(d), ".")
		if err != nil {
			return nil, fmt.Errorf("load rule bundle from %s (%s): %w", d, envRulesDir, err)
		}
		return b, nil
	}
	if st, err := os.Stat("rules"); err == nil && st.IsDir() {
		b, err := rules.LoadBundle(os.DirFS("rules"), ".")
		if err != nil {
			return nil, fmt.Errorf("load rule bundle from ./rules: %w", err)
		}
		return b, nil
	}
	b, err := ruleset.Load()
	if err != nil {
		return nil, fmt.Errorf("load embedded rule bundle: %w", err)
	}
	return b, nil
}

// printManifestIssues prints validation issues, errors before warnings.
func printManifestIssues(w io.Writer, issues []error) {
	ordered := append([]error(nil), issues...)
	sort.SliceStable(ordered, func(i, j int) bool {
		return !manifest.IsWarning(ordered[i]) && manifest.IsWarning(ordered[j])
	})
	for _, err := range ordered {
		label := "ERROR"
		if manifest.IsWarning(err) {
			label = "WARN "
		}
		if issue, ok := manifest.AsIssue(err); ok {
			loc := issue.Rule
			if issue.Path != "" {
				loc += " (" + issue.Path + ")"
			}
			_, _ = fmt.Fprintf(w, "  %s %s: %s\n", label, loc, issue.Message)
			continue
		}
		_, _ = fmt.Fprintf(w, "  %s %v\n", label, err)
	}
}

// severityRank orders finding severities most-severe-first for display.
var severityRank = map[rules.Severity]int{
	rules.SeverityCritical: 0,
	rules.SeverityHigh:     1,
	rules.SeverityMedium:   2,
	rules.SeverityLow:      3,
	rules.SeverityInfo:     4,
}

// sortFindings sorts findings by severity, then path, then line, then rule.
func sortFindings(findings []rules.Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if severityRank[a.Severity] != severityRank[b.Severity] {
			return severityRank[a.Severity] < severityRank[b.Severity]
		}
		if a.FilePath != b.FilePath {
			return a.FilePath < b.FilePath
		}
		if a.LineStart != b.LineStart {
			return a.LineStart < b.LineStart
		}
		return a.RuleID < b.RuleID
	})
}

// printFinding prints one scan finding with its excerpt.
func printFinding(w io.Writer, f rules.Finding) {
	loc := f.FilePath
	if f.LineStart > 0 {
		loc = fmt.Sprintf("%s:%d", f.FilePath, f.LineStart)
	}
	_, _ = fmt.Fprintf(w, "  %-8s %s %s — %s\n", strings.ToUpper(string(f.Severity)), f.RuleID, loc, f.Title)
	if f.Excerpt != "" {
		_, _ = fmt.Fprintf(w, "           %s\n", f.Excerpt)
	}
}
