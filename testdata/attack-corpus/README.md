# Agentry attack corpus (pipeline golden corpus, PLAN §17.3)

**These directories are TEST FIXTURES for a defensive scanner.** Every file
here is a defanged, text-only *pattern* reproduction of a prompt-injection or
hidden-instruction technique, written so that Agentry's scanners can be
regression-tested. Nothing in this tree is functional malware: there is no
executable code, no real endpoint (all URLs use `*.invalid.example`, a
reserved-style non-resolvable name), and no real secret. The "payloads" are
inert sentences and inert JSON that merely *look like* attacks so the scanner
can prove it detects the technique.

PLAN §17.3 calls this corpus the crown jewel and a product asset. It is the
only place the pipeline's reason for being is written down as something a
machine can check.

## Layout

Each technique class gets a **pair** of directories:

- `s3-<technique>/`, `s4-<family>/` or `incident-<name>/` — a minimal agent
  exhibiting the technique, plus `expected.yaml` naming the finding ids the
  scanner MUST emit (recall: the corpus test requires 100% of `expect` ids to
  be present).
- `…-benign/` — the benign-lookalike twin: text that superficially resembles
  the attack (e.g. security documentation *discussing* injection) which MUST
  NOT produce the paired finding (precision: `forbid` ids must be absent and,
  with `expectClean: true`, the fixture must produce zero rule-level findings).
  Per §17.3, an agent about prompt-injection defense must be publishable.

Two runners read this tree:

| Runner | Scope | Asserts |
|---|---|---|
| `pkg/rules/corpus_test.go` | S3 + S4 only, no pipeline | the `S3/…` and `S4/…` entries of `expect`/`forbid`; `expectClean` ⇒ zero findings |
| `internal/scan/corpus_test.go` | the whole orchestrator | every `expect`/`forbid` id including S6–S9; attack fixtures must not auto-publish; benign fixtures must not be rejected |

## expected.yaml schema

```yaml
technique: "human-readable technique name"
incident: "Appendix A incident this reproduces"   # optional, documentation
expect:            # finding ids that MUST be found (empty for benign twins)
  - S3/zero-width
forbid:            # finding ids that MUST NOT be found
  - S4/exfiltration-001
expectClean: true  # when true, the fixture must yield ZERO rule-level findings

# --- optional pipeline context (read by internal/scan's runner only) ---
kind: mcp-server                 # default prompt-agent; S6/S7 only run for code kinds
manifest: |                      # default {"kind":"<kind>","capabilities":{}}
  {"kind":"mcp-server","license":"MIT","capabilities":{}}
version: "1.0.1"                 # this version's semver
prev: incident-postmark-v1       # sibling fixture = the PREVIOUS published version
agentName: "crypto-assistant"    # feeds S8 name similarity
summary: "…"                     # feeds S8 keyword-stuffing
popularAgents: ["github-mcp"]    # the top-N list S8 compares against
publisher:                       # absent means "no publisher signal"
  accountAgeDays: 2
  recentPublishes: 41
```

A fixture with `prev:` is staged **as a pair**: both directories are unpacked,
the sibling becomes `Input.PrevArchiveDir`, and S9 runs its content diff across
them. That is the only way to exercise the clean-then-malicious release shape,
and the pipeline runner fails the build if the corpus contains no such pair.

## Incident reproductions (PLAN Appendix A)

| Incident | Pattern | Fixture(s) | Stage that must catch it |
|---|---|---|---|
| postmark-mcp (2025-09): 15 clean releases, then one line BCC-ing all mail | rug-pull diff | `incident-postmark-v1` + `incident-postmark-v2` (pair), `incident-postmark-benign-docs` | **S9** new egress destination in package content on a patch bump + **S6** undeclared network |
| GlassWorm (2025-10): worm hidden via invisible Unicode in editor extensions | invisible payload | `incident-glassworm`, `incident-glassworm-benign` (also `s3-tag-block`) | **S3** Unicode tag block (high on sight — no legitimate prose use) |
| Amazon Q extension wiper prompt (2025-07): destructive instruction shipped to ~1M installs | malicious instructions in prose | `incident-amazonq-wiper`, `incident-amazonq-wiper-benign` | **S4** `destructive` family (added in ruleset 0.2.0) + S5 C6 |
| Shai-Hulud npm worm (2025-09/11): postinstall credential stealer | install-script supply chain | `incident-shai-hulud`, `incident-shai-hulud-benign` | **S7** install-script detection (+ lockfile audit, + S9 escalation when the hook is new) |
| ClawHavoc (2026-02): 1,184 malicious skills from 12 accounts | mass-publish + content | `incident-clawhavoc`, `incident-clawhavoc-benign` | **S8** young-account velocity + keyword stuffing |
| s1ngularity/nx (2025-08): stolen-token publishes | provenance gap | *not a content fixture* — the defense is S8 publisher signals plus the attestation's `source` field (§8.8), exercised in `internal/scan/signing_test.go` | — |

## Fixture classes

S3 (hidden & obfuscated content, one per §8.3 S3 technique class):
`s3-zero-width`, `s3-bidi` (Trojan Source), `s3-tag-block` (ASCII smuggling),
`s3-private-use`, `s3-mixed-script` (confusables), `s3-html-comment`,
`s3-css-hidden`, `s3-data-uri`, `s3-encoded-blob` (entropy-gated base64),
`s3-trailing-whitespace`, `s3-nfc-delta`.

The **EXIF / image-metadata** class of §8.3 S3 has no directory here: this tree
is text-only by policy, and a committed binary would be the one fixture nobody
could review by reading it. Its pair lives in
`internal/scan/imagemeta_test.go` (`TestImageMetadataInjectionFixture`), which
generates a PNG carrying an injection directive in a tEXt chunk and a JPEG
carrying one in EXIF `UserComment`, plus ordinary-caption twins of both, and
runs all four through the orchestrator. Markdown **alt-text** needs no
extractor — it is literal text in the `.md` file — and
`TestMarkdownAltTextIsScanned` exists to keep it that way.

S4 (injection signature families, one per §8.3 S4 family):
`s4-instruction-override`, `s4-exfiltration`, `s4-tool-coercion`,
`s4-credential-harvest`, `s4-persistence`, `s4-obfuscation`. The seventh
family, `destructive`, is covered by the Amazon Q pair above.

## Rules for extending the corpus

1. Every new S4 rule ships with corpus additions — a match fixture and a
   benign non-match twin (§17.3 CI gate).
2. Keep fixtures defanged: text patterns only; `*.invalid.example` hosts;
   placeholder tokens only (never real credentials); nothing executable. Where
   a fixture references a script (`incident-shai-hulud`'s postinstall hook),
   that script is deliberately *absent* — the shape is the fixture, not a
   working payload.
3. New incident reproductions reproduce the *pattern*, never the payload, and
   add a row to the Appendix A table above.
4. Both runners walk every directory here; a directory without `expected.yaml`
   is skipped by the pipeline runner and fails the rules runner — document
   intent by writing the file.
