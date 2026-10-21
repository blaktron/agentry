# Agentry attack corpus (pipeline golden corpus)

**These directories are TEST FIXTURES for a defensive scanner.** Every file
here is a defanged, text-only *pattern* reproduction of a prompt-injection or
hidden-instruction technique, written so that Agentry's scanners can be
regression-tested. Nothing in this tree is functional malware: there is no
executable code, no real endpoint (all URLs use `*.invalid.example`, a
reserved-style non-resolvable name), and no real secret. The "payloads" are
inert sentences and inert JSON that merely *look like* attacks so the scanner
can prove it detects the technique.

The corpus is a product asset. It is the only place the pipeline's reason
for being is written down as something a machine can check.

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
  An agent about prompt-injection defense must be publishable.

Two runners read this tree:

| Runner | Scope | Asserts |
|---|---|---|
| `pkg/rules/corpus_test.go` | S3 + S4 only, no pipeline | the `S3/…` and `S4/…` entries of `expect`/`forbid`; `expectClean` ⇒ zero findings |
| `internal/scan/corpus_test.go` | the whole orchestrator | every `expect`/`forbid` id including S8–S9; attack fixtures must not auto-publish; benign fixtures must not be rejected; a fixture with `expectOutcome` gets exactly that outcome at the baseline |

## expected.yaml schema

```yaml
technique: "human-readable technique name"
incident: "public incident this reproduces"   # optional, documentation
expect:            # finding ids that MUST be found (empty for benign twins)
  - S3/zero-width
forbid:            # finding ids that MUST NOT be found
  - S4/exfiltration-001
expectClean: true  # when true, the fixture must yield ZERO rule-level findings
expectOutcome: published  # optional: the gate's exact outcome at the baseline
                          # (published, needs_review, rejected); marks a loosening

# --- optional pipeline context (read by internal/scan's runner only) ---
manifest: |                      # default {"kind":"<kind>","capabilities":{}}
  {"license":"MIT","capabilities":{}}
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

## Incident reproductions

| Incident | Pattern | Fixture(s) | Stage that must catch it |
|---|---|---|---|
| postmark-mcp (2025-09): 15 clean releases, then one line BCC-ing all mail | rug-pull diff | `incident-postmark-v1` + `incident-postmark-v2` (pair), `incident-postmark-benign-docs` | **S9** new egress destination in package content on a patch bump |
| GlassWorm (2025-10): worm hidden via invisible Unicode in editor extensions | invisible payload | `incident-glassworm`, `incident-glassworm-benign` (also `s3-tag-block`) | **S3** Unicode tag block (high on sight — no legitimate prose use) |
| Amazon Q extension wiper prompt (2025-07): destructive instruction shipped to ~1M installs | malicious instructions in prose | `incident-amazonq-wiper`, `incident-amazonq-wiper-benign` | **S4** `destructive` family (added in ruleset 0.2.0) + S5 C6 |
| ClawHavoc (2026-02): 1,184 malicious skills from 12 accounts | mass-publish + content | `incident-clawhavoc`, `incident-clawhavoc-benign` | **S8** young-account velocity + keyword stuffing |
| s1ngularity/nx (2025-08): stolen-token publishes | provenance gap | *not a content fixture* — the defense is S8 publisher signals plus the attestation's `source` field, exercised in `internal/scan/signing_test.go` | — |

## Fixture classes

S3 (hidden & obfuscated content, one per S3 technique class):
`s3-zero-width`, `s3-bidi` (Trojan Source), `s3-tag-block` (ASCII smuggling),
`s3-private-use`, `s3-mixed-script` (confusables), `s3-html-comment`,
`s3-css-hidden`, `s3-data-uri`, `s3-encoded-blob` (entropy-gated base64),
`s3-trailing-whitespace`, `s3-nfc-delta`, `s3-variation-selector` (emoji
smuggling; its benign twin `s3-variation-selector-benign` keeps the standard
variation sequences: emoji and text presentation, keycaps, a ZWJ flag).

The **EXIF / image-metadata** class of S3 has no directory here: this tree
is text-only by policy, and a committed binary would be the one fixture nobody
could review by reading it. Its pair lives in
`internal/scan/imagemeta_test.go` (`TestImageMetadataInjectionFixture`), which
generates a PNG carrying an injection directive in a tEXt chunk and a JPEG
carrying one in EXIF `UserComment`, plus ordinary-caption twins of both, and
runs all four through the orchestrator. Markdown **alt-text** needs no
extractor — it is literal text in the `.md` file — and
`TestMarkdownAltTextIsScanned` exists to keep it that way.

S4 (injection signature families, one per S4 family):
`s4-instruction-override`, `s4-exfiltration`, `s4-tool-coercion`,
`s4-credential-harvest`, `s4-persistence`, `s4-obfuscation`. The seventh
family, `destructive`, is covered by the Amazon Q pair above.
`s4-heading-framed` sets a live exfiltration directive under a `## Findings`
heading, whose word is a bundle-level descriptive-framing suppression; since
ruleset 0.3.3 a Markdown heading ends the paragraph those suppressions read,
so it fires. Its twin `s4-heading-framed-benign` is
review prose under the same headings whose marker wraps onto the line before
the match, which the paragraph scope must still suppress.
`s4-heading-framed-nbsp` is the same attack with a no-break space after the
hashes, the red team's whitespace-noise mutant that 0.3.3 missed; since 0.3.4
any Unicode space after the hashes makes a heading.

S6 over the instruction (ruleset 0.4.10): `s6-ungranted-browser` is an
instruction that works a site through the runner's browser tools in a release
that declares no `capabilities.browser`, so its runs would have none of them;
S6 reports `S6/ungranted-tool` and the version goes to a person. Its twin
`s6-ungranted-browser-benign` is the same instruction with the browser line
declared, and must draw no finding, including for the `browser_evaluate` the
instruction names only to turn it away.

S6 over a support script (ruleset 0.4.12): `script-network-forms` is a shell
script that reaches four undeclared hosts without a curl, wget or ssh on the
line: a redirection to `/dev/tcp`, a `socat` address, a `git clone` of an
scp-like remote and a `docker pull` from a registry with a port; S6 reports
`S6/undeclared-network` and the version goes to a person. Its twin
`script-network-forms-benign` is the same script with the four hosts declared
in `network.egress`.

S6 over a support script (ruleset 0.4.13): `script-quoted-command` is a shell
script that reaches an undeclared host through a quoted `"curl"` and through
an `ssh` written quoted after a wrapper and an assignment
(`sudo LC_ALL=C 'ssh' …`), which the shell runs exactly as the unquoted
forms; S6 reports `S6/undeclared-network` and the version goes to a person.
Its twin `script-quoted-command-benign` is the same script with the host
declared in `network.egress`.

S6 over a support script (ruleset 0.4.16): `script-wrapped-shell-pipe` is a
shell script that pipes a download into a shell behind a wrapper
(`| env sh`, `| sudo -E /bin/sh`), which runs the download exactly as a bare
`| sh`; S6 reports `S6/remote-exec`. Its twin `script-wrapped-shell-pipe-benign`
pipes the same downloads, behind the same wrappers, into `jq` and `tee`, which
run nothing they are fed.

S6 over a support script (ruleset 0.4.14): `script-quoted-option` is a shell
script whose `ssh` reaches an undeclared host with its options quoted
(`ssh '-p' 2222 '-o' BatchMode=yes deploy@…`), which the shell runs exactly
as the unquoted form; S6 reports `S6/undeclared-network` and the version goes
to a person. Its twin `script-quoted-option-benign` is the same script with
the host declared in `network.egress`.

S2 over a file (ruleset 0.4.15): `s2-key-behind-placeholder` holds one line
with two `aws_secret` assignments, a placeholder first and a generated
credential-shaped value second; S2 reports `S2/aws-secret-key` for the second
and the version goes to a person. Its twin `s2-key-behind-placeholder-benign`
is the same line with both values placeholders. The value was generated for
the corpus.

S2 over the manifest (a declared MCP server's plain `env`):
`manifest-env-secret` (a prefixed token under a credential-named key:
the line rule and the name finding),
`manifest-env-token-unquoted` (an unquoted value no prefix rule knows under a
credential-named key: both manifest-pass findings), `manifest-env-token-plain-key`
(a bare hex token under a plainly named key: the value finding only), and the
benign twins `manifest-env-secret-benign` (the credential named under
`secrets`) and `manifest-env-config-benign` (long configuration values — a
URL, a path, a timezone, a model name, a timestamp, a digest, a number, a
mode, an id — under plain keys). The two token fixtures cannot carry a
self-evident placeholder, since the shape is what the rule reads; their
values were generated for the corpus.

Loosenings (ruleset 0.3.2): each rule a ruleset stops holding
for something that is not a major risk gets a fixture that was held before
and now publishes (`expectOutcome: published`), and an attack fixture of the
shape the rule must still hold.

| Loosening | Publishes now | Still held |
|---|---|---|
| `S3/zero-width` leaves a joiner inside an emoji sequence and a leading byte-order mark | `s3-zero-width-emoji-benign` | `s3-zero-width-beside-emoji` (a joiner before a letter, a zero-width space between emoji, a byte-order mark mid-file), and `s3-zero-width` |
| `S9/new-obfuscation` only for a new S3 class rated medium or above | `s9-patch-comment-v2` (a patch adds a plain HTML comment; baseline `s9-patch-comment-v1`) | `s9-patch-hidden-v2` (a patch adds CSS-hidden text) |
| a host the manifest declares is low (`S9/new-egress`, `S9/new-egress-content`), even when this patch declares it | `s9-declared-host-v2` (a patch declares a host and starts using it; baseline `s9-declared-host-v1`, no egress) | `s9-undeclared-host-v2` (the same, plus a host it does not declare), and `incident-postmark-v2` |
| a bare name is a destination only under a top-level domain ICANN delegates, and not as a two-label name under a file-like domain (`.md`, `.zip`, `.sh`, `.py` and the like) or a dotted name outside a string in program source (ruleset 0.4.3) | `s9-uncommon-tld-benign` (a patch names `report.md`, `areas.yaml` and `tickets.zip`; baseline `s9-uncommon-tld-v1`) | `s9-uncommon-tld-v2` (a patch starts mirroring to `webhook.site/…`, a TLD the old list did not know) |
| a host the manifest's browser may open (`capabilities.browser.hosts`, exact or below a `*.` entry) is declared to S4's rating by declaration: medium, not high (ruleset 0.4.9) | `s4-exfiltration-browser-host` (the directive names a host below the browser's `*.drop.invalid.example`) | `s4-exfiltration-browser-host-bare-name` (the same, to the bare `drop.invalid.example`, which the browser may not open) |

## Rules for extending the corpus

1. Every new S4 rule ships with corpus additions — a match fixture and a
   benign non-match twin.
2. Keep fixtures defanged: text patterns only; `*.invalid.example` hosts
   (one exception: `s9-uncommon-tld-v2` names `webhook.site`, a public
   request catcher, bare and with an inert path, because what it tests is a
   top-level domain no list of common ones holds; a reserved name cannot be
   that);
   placeholder tokens only (never real credentials); nothing executable. Where
   a fixture carries a script (the `script-*` fixtures S6 reads), it is a
   text pattern that could not do what it describes — the shape is the
   fixture, not a working payload.
3. New incident reproductions reproduce the *pattern*, never the payload, and
   add a row to the incident table above.
4. Both runners walk every directory here; a directory without `expected.yaml`
   is skipped by the pipeline runner and fails the rules runner — document
   intent by writing the file.
