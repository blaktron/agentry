# Trust and security model

What Agentry checks before a version becomes installable, what its signature
proves, and — the part most registries leave out — what none of it
guarantees. This is the repository-side companion to the `/trust` page any
running instance serves; that page additionally shows the live signing keys
and the current ruleset version.

## The premise

An agent instruction file is executed with the reader's credentials and the
reader's tool access. It is, functionally, code. It is also — today, across
every mainstream distribution channel — shipped with no signature, no
malware scan, and no review. Agentry's whole reason to exist is that gap,
and the whole reason for this document is to be precise about how far it
closes.

## Nothing publishes unscanned

There is no flag, plan, or role that lets a public version skip the pipeline
(PLAN §1.6 principle 1). A version is scanned on **the exact bytes that will
ship** — the deterministic archive, not the working tree, not the tag as the
author describes it.

Ten stages run against those bytes:

| | |
|---|---|
| **S1** | Inventory and hygiene: safe unpack, content-sniffed types, archive anomalies, binaries |
| **S2** | Secrets, including Agentry's own `agy_` token format |
| **S3** | Hidden and obfuscated content: zero-width and bidi characters, Unicode tag blocks, confusables, private-use codepoints, HTML comments, CSS-hidden text, data URIs, entropy-gated encoded blobs |
| **S4** | Prompt-injection signatures: instruction override, exfiltration, tool coercion, credential harvesting, persistence, obfuscation |
| **S5** | LLM adjudication against a fixed rubric, with no tools; a judge showing signs of manipulation is itself a finding |
| **S6** | Capability consistency: what the manifest declares versus what the code does |
| **S7** | Dependencies, licenses, install scripts, typosquat heuristics |
| **S8** | Metadata, namespace and publisher-behaviour abuse |
| **S9** | Release-diff risk — the rug-pull check, comparing a version against its predecessor |
| **S10** | Report assembly into a canonical, digest-addressed document |

The gate then decides: clean and low-severity versions publish
automatically, medium and high findings go to human review, critical
findings are rejected. **A scanner that errors or times out fails toward
review, never through** — any stage error becomes an `S0/pipeline-error`
finding that forces a human look, and "no path to `published` skips the
gate" is a property test, not a promise.

## What a signature proves

Each published release is content-addressed. On the transition to
`published` — once, and never re-issued — the registry signs an in-toto
statement binding the archive digest to the scan report that produced the
decision, the ruleset version, the judge model, and the policy in force.
It is wrapped in a DSSE envelope and served alongside the archive.

```bash
agentry verify acme/incident-summarizer@1.4.2
```

A verified signature means: **these exact bytes are the ones this registry
scanned and published.** It does not mean the contents are benign. Those
are different claims and the product never conflates them.

Verification keys are served at
`/.well-known/agentry/signing-keys.json`; the CLI pins them on first use and
warns when the advertised key ids change.

## What this does not guarantee

The language throughout the product is **"scanned, N findings, signed"** —
never "safe", never "verified secure" (PLAN §1.6 principle 3). That is a
rule about honesty, and these are the specific things behind it:

- **Static analysis cannot prove an agent safe.** A sufficiently novel
  injection technique will pass a scan written before it existed. PLAN's
  own threat table records this as unresolvable rather than mitigated. Every
  agent page publishes finding counts and the ruleset version so a reader
  can judge the freshness of the check instead of trusting a badge.
- **Declared capabilities are a contract, not a sandbox.** The manifest says
  what an agent claims to need — network egress, filesystem access,
  subprocess execution, secrets. The registry checks that claim against the
  code (S6) and gates on it (§8.6 policy), but it cannot enforce anything
  once the agent is running on your machine. Your runtime should read the
  manifest and sandbox accordingly. That is what it is for.
- **Scanning happens at publication, not at push and not at run time.** A
  private repository's contents are not scanned until a version is submitted.
- **The shipped scanners are good, not identical to the tools PLAN §8.3
  names.** S2, S6 and S7 use native Go implementations behind adapter
  interfaces rather than gitleaks, opengrep and osv-scanner. They detect
  everything the committed attack corpus exercises; they are not those
  tools. See DEV-006.
- **Review is human, and humans are the ones deciding.** Reviewer
  dismissals — false positive, or accepted risk — stay on the public report
  with their rationale, so a waived finding is visible rather than erased.

## Because detection improves after publication

A scan is a statement about one moment. Published versions are therefore
**rescanned when a new ruleset ships** — the sweep is triggered by ruleset
registration, not by a human remembering. A version that newly trips a
high-severity finding is quarantined: it stops resolving for new installs,
a direct download is refused with `409 Conflict` and the reason, the web
page carries the warning, and an advisory is raised against it. A version
or agent that trust & safety has confirmed malicious is **blocked**, and
downloads then return `410 Gone`.

What that cannot do is reach a copy already on someone's disk. Advisories
and the `advisory.published` / `agent.quarantined` webhooks are the
notification path, which is why pinning versions in a lockfile you actually
review is worth the trouble.

Advisories are currently shown on the affected agent's page; there is no
global advisory feed (DEV-038).

## Everything here is auditable

The scanners, the rulesets, the gate and the review queue are open source.
The attack corpus that gates CI — attack fixtures and their benign
lookalikes, including a security-documentation agent that must stay
publishable — is in `testdata/attack-corpus/`. The claims on this page are
checkable against the code that makes them.

Known departures from the plan, including the ones that weaken a claim, are
recorded in [DEVIATIONS.md](https://github.com/blaktron/agentry/blob/main/DEVIATIONS.md) rather than left implicit.

## Reporting

- **Malicious content on a registry:** the report link on the agent page, or
  `abuse@` the registry's domain.
- **A vulnerability in Agentry itself:** [SECURITY.md](https://github.com/blaktron/agentry/blob/main/SECURITY.md), which
  documents the coordinated-disclosure process and — deliberately — the
  classes of finding that are *not* vulnerabilities because they are
  documented limitations of a static pipeline.
