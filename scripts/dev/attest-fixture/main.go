// attest-fixture writes what a third-party verifier needs to check one of
// this registry's attestations: a blob, the DSSE
// envelope this code produces over the blob's digest — the exact bytes the
// server would store and serve — and the signing public key. CI then runs
// `cosign verify-blob-attestation` against them, which turns "our DSSE and
// in-toto are format-compatible" from a belief into a test.
//
//	go run ./scripts/dev/attest-fixture OUTDIR
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/blaktron/agentry/internal/scan"
	"github.com/blaktron/agentry/pkg/attest"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: attest-fixture OUTDIR")
		os.Exit(2)
	}
	out := os.Args[1]
	if err := run(out); err != nil {
		fmt.Fprintln(os.Stderr, "attest-fixture:", err)
		os.Exit(1)
	}
}

func run(out string) error {
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	blob := make([]byte, 4096)
	if _, err := rand.Read(blob); err != nil {
		return err
	}
	sum := sha256.Sum256(blob)
	digest := "sha256:" + hex.EncodeToString(sum[:])

	// The ephemeral dev-mode signer: the same code path as `signing.kind:
	// file`, with a fresh P-256 key.
	signer, err := scan.NewFileSigner("", true)
	if err != nil {
		return err
	}
	stmt := attest.BuildStatement("https://registry.example", "acme/interop", "1.0.0", digest, "", "cli-upload",
		attest.ScanRunRef{ID: "run-interop", RulesetVer: "0.2.0", ReportDigest: "sha256:0"}, 1)
	env, err := signer.Sign(stmt)
	if err != nil {
		return err
	}
	envJSON, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}
	// A ruleset attestation too: same key, the other predicate type.
	rsEnv, err := signer.Sign(attest.BuildRulesetStatement("https://registry.example", "0.2.0", digest))
	if err != nil {
		return err
	}
	rsJSON, err := json.MarshalIndent(rsEnv, "", "  ")
	if err != nil {
		return err
	}
	files := map[string][]byte{
		"blob.bin":              blob,
		"publish.dsse.json":     envJSON,
		"ruleset.dsse.json":     rsJSON,
		"public.pem":            []byte(signer.PublicKeyPEM()),
		"predicate-publish.txt": []byte(attest.PredicateType + "\n"),
		"predicate-ruleset.txt": []byte(attest.RulesetPredicateType + "\n"),
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(out, name), data, 0o644); err != nil { //nolint:gosec // fixture output
			return err
		}
	}
	fmt.Printf("attest-fixture: wrote %s (subject %s, key %s)\n", out, digest, signer.KeyID())
	return nil
}
