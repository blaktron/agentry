// Package rules is the embedded scanner engine that powers both the
// server-side publication pipeline stages S3 and S4 (PLAN §8.3) and the
// offline `agentry validate` command (D-12). Server and CLI run the same
// code over the same versioned rule bundle, so a local scan is a faithful
// subset of what the registry runs at publish time — "local/remote parity".
//
// The package has two scanners:
//
//   - S3 (ScanS3) is a set of deterministic detectors for hidden and
//     obfuscated content: zero-width characters, bidi controls (Trojan
//     Source), the Unicode tag block (ASCII smuggling), private-use runs,
//     mixed-script confusable tokens, HTML comments, CSS-hidden markup,
//     oversized data: URIs, entropy-gated base64/hex blobs, trailing
//     whitespace columns, and NFC-normalization deltas. No configuration:
//     the rules are the code.
//
//   - S4 (Bundle) is a signature engine that loads a versioned YAML rule
//     bundle (see the repo's /rules directory, shipped as ruleset_releases)
//     and evaluates regex + suppression rules over prose and prompt files.
//     Rules carry an id, severity, confidence, references, and match /
//     non-match fixtures so every rule ships with tests (§8.3).
//
// Scan runs both scanners over a file set. Every finding carries the OWASP
// taxonomy ids required by §8.10 (LLM01 prompt injection, ASI06 memory &
// context poisoning).
//
// Nothing in this package executes, decodes, or renders untrusted content:
// it only inspects bytes and reports. That property is what lets it run
// inside the sandboxed scanner task profile (§8.2) and unchanged in the CLI.
package rules
