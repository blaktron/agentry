// `agentry verify` (§11): download a pinned version and check its sha256
// digest against the registry (§9.4 step 3). DSSE attestation signature
// verification arrives with M4 signing; until the API serves an
// attestation, the command says so.
package main

import (
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/spf13/cobra"

	"github.com/PLACEHOLDER_ORG/agentry/internal/registry"
)

// exactVersionRe mirrors the API's VersionString pattern: verify only works
// on exact pins.
var exactVersionRe = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+([-+].*)?$`)

// newVerifyCmd builds the verify command.
func newVerifyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "verify <ns/name@version>",
		Short: "Verify a published version's archive digest (exit code for CI)",
		Long: "Resolve an exact version, download its archive, recompute the sha256\n" +
			"digest, and compare it to the registry's (§9.4). Prints PASS/FAIL and\n" +
			"exits accordingly. DSSE attestation verification lands with M4 signing.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runVerify(cmd, args[0])
		},
	}
}

// verifyReport is the --json output shape.
type verifyReport struct {
	Ref            string `json:"ref"`
	Version        string `json:"version"`
	RegistryDigest string `json:"registryDigest"`
	ComputedDigest string `json:"computedDigest"`
	DigestMatch    bool   `json:"digestMatch"`
	Attestation    string `json:"attestation"`
	Yanked         bool   `json:"yanked"`
}

// runVerify executes the verification.
func runVerify(cmd *cobra.Command, ref string) error {
	parsed, err := registry.ParseRef(ref)
	if err != nil {
		return err
	}
	if !exactVersionRe.MatchString(parsed.Range) {
		return fmt.Errorf("verify requires an exact version pin, e.g. %s/%s@1.2.3", parsed.Namespace, parsed.Name)
	}

	reg := registryURL()
	token := credentialFor(reg)
	client, err := newAPIClient(reg, token)
	if err != nil {
		return err
	}
	res, err := resolveRef(cmd.Context(), client, ref, false)
	if err != nil {
		return err
	}
	archive, err := downloadArchive(cmd.Context(), reg, token, res)
	if err != nil {
		return err
	}

	report := verifyReport{
		Ref:            ref,
		Version:        res.Version,
		RegistryDigest: res.Digest,
		ComputedDigest: sha256Digest(archive),
		Yanked:         res.Yanked,
		Attestation:    "not yet available (M4 signing)",
	}
	report.DigestMatch = report.ComputedDigest == report.RegistryDigest
	if res.AttestationUrl != nil && *res.AttestationUrl != "" {
		report.Attestation = "present at " + *res.AttestationUrl + " (signature verification lands with M4)"
	}

	out := cmd.OutOrStdout()
	if flags.jsonOut {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			return fmt.Errorf("encode report: %w", err)
		}
	} else {
		_, _ = fmt.Fprintf(out, "%s/%s@%s\n", res.Namespace, res.Name, res.Version)
		_, _ = fmt.Fprintf(out, "  registry digest: %s\n", report.RegistryDigest)
		_, _ = fmt.Fprintf(out, "  computed digest: %s\n", report.ComputedDigest)
		_, _ = fmt.Fprintf(out, "  attestation:     %s\n", report.Attestation)
		if report.Yanked {
			_, _ = fmt.Fprintln(out, "  yanked:          yes")
		}
		if report.DigestMatch {
			_, _ = fmt.Fprintln(out, "digest: PASS")
		} else {
			_, _ = fmt.Fprintln(out, "digest: FAIL")
		}
	}
	if !report.DigestMatch {
		return fmt.Errorf("digest mismatch for %s", ref)
	}
	return nil
}
