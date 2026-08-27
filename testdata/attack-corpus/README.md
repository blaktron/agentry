# Agentry attack corpus (pipeline golden corpus, PLAN §17.3)

**These directories are TEST FIXTURES for a defensive scanner.** Every file
here is a defanged, text-only *pattern* reproduction of a prompt-injection or
hidden-instruction technique, written so that Agentry's S3/S4 scanners
(`pkg/rules`) can be regression-tested. Nothing in this tree is functional
malware: there is no executable code, no real endpoint (all URLs use
`*.invalid.example`, a reserved-style non-resolvable name), and no real
secret. The "payloads" are inert sentences that merely *look like* attacks so
the scanner can prove it detects the technique.

## Layout

Each technique class gets a **pair** of directories:

- `s3-<technique>/` or `s4-<family>/` — a minimal agent file exhibiting the
  technique, plus `expected.yaml` naming the rule ids the scanner MUST emit
  (recall: the corpus test requires 100% of `expect` ids to be present).
- `…-benign/` — the benign-lookalike twin: text that superficially resembles
  the attack (e.g. security documentation *discussing* injection) which MUST
  NOT produce the paired rule's findings (precision: `forbid` ids must be
  absent and, with `expectClean: true`, the fixture must produce zero findings
  for that scanner family). Per §17.3, an agent about prompt-injection defense
  must be publishable.

## expected.yaml schema

```yaml
technique: "human-readable technique name"
expect:      # rule ids that MUST be found (empty for benign twins)
  - S3/zero-width
forbid:      # rule ids that MUST NOT be found
  - S4/exfiltration-001
expectClean: true   # when true, the fixture must yield ZERO findings at all
```

## Fixture classes

S3 (hidden & obfuscated content, one per §8.3 S3 technique class):
`s3-zero-width`, `s3-bidi` (Trojan Source), `s3-tag-block` (ASCII smuggling),
`s3-private-use`, `s3-mixed-script` (confusables), `s3-html-comment`,
`s3-css-hidden`, `s3-data-uri`, `s3-encoded-blob` (entropy-gated base64),
`s3-trailing-whitespace`, `s3-nfc-delta`.

S4 (injection signature families, one per §8.3 S4 family):
`s4-instruction-override`, `s4-exfiltration`, `s4-tool-coercion`,
`s4-credential-harvest`, `s4-persistence`, `s4-obfuscation`.

## Rules for extending the corpus

1. Every new S4 rule ships with corpus additions — a match fixture and a
   benign non-match twin (§17.3 CI gate).
2. Keep fixtures defanged: text patterns only; `*.invalid.example` hosts;
   placeholder tokens only (never real credentials); nothing executable.
3. New incident reproductions (GlassWorm-style hidden Unicode, postmark-style
   clean-then-malicious diffs, …) reproduce the *pattern*, never the payload.
4. The corpus test (`pkg/rules/corpus_test.go`) walks every directory here;
   a directory without `expected.yaml` fails the build — document intent.
