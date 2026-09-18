# Trust and security model

What Agentry checks before a version becomes installable, what its signature
proves, and what none of it guarantees. This is the repository-side companion
to the `/trust` page the hosted site serves; every registry publishes the same
posture machine-readably — its live signing keys at
`/.well-known/agentry/signing-keys.json`, the API, git and version
endpoints at `/.well-known/agentry/registry.json`, and the current ruleset
version on the rule bundle's headers (`/api/v1/ruleset-releases/latest/bundle`)
— and a site in front renders them.

## The premise

An agent instruction file is executed with the reader's credentials and the
reader's tool access. It is, functionally, code. Today it is also shipped
through every mainstream distribution channel with no signature and no
malware scan, and no one reviews it. Agentry exists for that gap, and this
document is precise about how far it closes.

## Nothing publishes unscanned

There is no flag, plan, or role that lets a public version skip the pipeline
(PLAN §1.6 principle 1). A version is scanned on **the exact bytes that will
ship**: the deterministic archive, not the working tree, not the tag as the
author describes it.

Ten stages run against those bytes:

| | |
|---|---|
| **S1** | Inventory and hygiene: safe unpack, content-sniffed types, archive anomalies, binaries |
| **S2** | Secrets, including Agentry's own `agy_` token format, and the values a declared MCP server's `env` carries in the manifest; on a git-tag publish also the added lines of every commit reachable from the tag, so a key committed and later removed still surfaces |
| **S3** | Hidden and obfuscated content: zero-width and bidi characters, Unicode tag blocks, confusables, private-use codepoints, HTML comments, CSS-hidden text, data URIs, entropy-gated encoded blobs |
| **S4** | Prompt-injection signatures: instruction override, exfiltration, tool coercion, credential harvesting, persistence, obfuscation |
| **S5** | LLM adjudication against a fixed rubric, with no tools; a judge showing signs of manipulation is itself a finding. The judge is an Anthropic-, OpenAI-compatible or Bedrock model, or a PromptGuard-class classifier that scores only the injection axis and therefore always routes to human review |
| **S6** | Support scripts against the manifest: every shell, Python or JavaScript file in the package (by extension or shebang) is read for network calls, file writes, subprocesses, `eval`, environment reads and download-and-run remote execution (a fetched script piped into a shell), and each is compared with `capabilities`. A script in a package whose `exec` is `none`, a call to a host outside `network.egress`, a write under `filesystem.write: none`, an undeclared subprocess and any remote execution are high; an environment variable outside `secrets` is medium. The stage matches text and never runs the script; a host counts only inside a network call, so a URL in a comment is not a finding |
| **S7** | Declared MCP servers: every `capabilities.mcpServers` package version is checked against the OSV vulnerability database — live the first time a version is seen, from the registry of scanned server versions afterwards — and each advisory is a finding at the advisory's own severity, CVE ids included. A lookup that fails routes to review; a database that is switched off says "not checked", never "no advisories" |
| **S8** | Metadata, namespace and publisher-behaviour abuse |
| **S9** | Release-diff risk: the rug-pull check, comparing a version against its predecessor |
| **S10** | Report assembly into a canonical, digest-addressed document |

The gate then decides: clean and low-severity versions publish
automatically, medium and high findings go to human review, critical
findings are rejected. **A scanner that errors or times out fails toward
review, never through.** Any stage error becomes an `S0/pipeline-error`
finding that forces a human look, and "no path to `published` skips the
gate" is a property test, not a promise.

## What a signature proves

Each published release is content-addressed. On the transition to
`published` (once, and never re-issued), the registry signs an in-toto
statement binding the archive digest to the scan report that produced the
decision, the ruleset version, the judge model, and the policy in force.
It is wrapped in a DSSE envelope and served alongside the archive. The
envelope is standard DSSE over a standard in-toto v1 statement, and that is
tested rather than asserted: CI verifies one of our envelopes with
`cosign verify-blob-attestation`, a verifier that shares no code with ours
(`make attest-interop`).

```bash
agentry verify acme/incident-summarizer@1.4.2
```

A verified signature means: **these exact bytes are the ones this registry
scanned and published.** It does not mean the contents are benign. Those
are different claims and the product never conflates them.

Verification keys are served at
`/.well-known/agentry/signing-keys.json`; the CLI pins them on first use and
warns when the advertised key ids change.

A key rotation orphans nothing. The registry keeps every key it has signed
with, and the well-known set lists each one with a `status`: `active` for the
key signing today, `retired` (with `retiredAt`) for a key that signed releases
before and no longer does. A retired key stays listed for as long as an
attestation carries its signature, so a client that pinned it keeps
verifying. When the registry starts signing with a new key it also
countersigns every existing attestation: the statement inside the envelope is
untouched, and a second signature by the new key is appended to it. A client
that pins only the new key verifies a release published before the rotation;
a client that pinned the old key sees the original signature still standing.
The attestation is the same envelope at the same URL with one more signature,
which is why it is served with a short cache lifetime rather than as
immutable.

## What this does not guarantee

The language throughout the product is **"scanned, N findings, signed"**,
never "safe" or "verified secure" (PLAN §1.6 principle 3). That is a
rule about honesty, and these are the specific things behind it:

- **Static analysis cannot prove an agent safe.** A sufficiently novel
  injection technique will pass a scan written before it existed. PLAN's
  own threat table records this as unresolvable rather than mitigated. Every
  agent page publishes finding counts and the ruleset version so a reader
  can judge the freshness of the check instead of trusting a badge.
- **Declared capabilities are a contract, not a sandbox.** The manifest says
  what an agent claims to need: network egress, filesystem access,
  subprocess execution, secrets. The registry checks that claim against the
  manifest and gates on it (§8.6 policy), but it cannot enforce anything
  once the agent is running on your machine. Your runtime should read the
  manifest and sandbox accordingly. That is what it is for.
- **Scanning happens at publication, not at push and not at run time.** A
  private repository's contents are not scanned until a version is submitted.
- **The shipped scanners are good, not identical to the tools PLAN §8.3
  names.** S2 uses a native Go implementation behind an adapter interface,
  with gitleaks optional beside it. It detects everything the committed
  attack corpus exercises. See DEV-006.
- **Review is human, and humans are the ones deciding.** Reviewer
  dismissals (false positive, or accepted risk) stay on the public report
  with their rationale, so a waived finding is visible rather than erased.

## Because detection improves after publication

A scan is a statement about one moment. Published versions are therefore
**rescanned when a new ruleset ships**. The sweep is triggered by ruleset
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

The same holds for the MCP servers a BriefAgent declares. Every scanned
server version is re-checked daily against the vulnerability database; a
version that gains a high or critical advisory raises a **dependency
alert** on each published BriefAgent version declaring it — shown on the
agent page and the author's dashboard, mailed to the author once their
address is verified, recorded in the audit trail, and sent to org webhooks as `agent.dependency_alert`. An
alert is not an advisory: it says the dependency has a known fix to pin,
and it closes when the affected version is yanked or the advisory is
withdrawn.

Advisories are shown on the affected agent's page, and the site's
`/advisories` page is the global feed — every advisory published against a
public BriefAgent, newest first, each with a permalink — followed by the
explainer of the model and the notification paths. The API serves the same
feed at `GET /api/v1/advisories` (keyset-paged) and one advisory at
`GET /api/v1/advisories/{id}`; `?affecting=namespace/name` narrows the feed
to one BriefAgent.

## Everything here is auditable

The scanners, the rulesets, the gate and the review queue are open source.
The attack corpus that gates CI (attack fixtures and their benign
lookalikes, including a security-documentation agent that must stay
publishable) is in `testdata/attack-corpus/`. The claims on this page are
checkable against the code that makes them.

Known departures from the plan, including the ones that weaken a claim, are
recorded in [DEVIATIONS.md](https://github.com/blaktron/agentry-notes/blob/main/agentry/DEVIATIONS.md) rather than left implicit.

## Reporting

- **Malicious content on a registry:** there is no report control on the agent
  page yet. A signed-in account posts the report to
  `POST /api/v1/agents/{ns}/{name}/abuse-reports`, and it lands in the platform
  triage queue. Without an account, email the security address the instance's
  operator publishes; that is where abuse reports go until the control ships.
- **A vulnerability in Agentry itself:** [SECURITY.md](https://github.com/blaktron/agentry/blob/main/SECURITY.md), which
  documents the coordinated-disclosure process and, deliberately, the
  classes of finding that are *not* vulnerabilities because they are
  documented limitations of a static pipeline.
