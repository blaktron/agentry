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
| <span id="s1">**S1**</span> | Inventory and hygiene: safe unpack, content-sniffed types, archive anomalies, binaries |
| <span id="s2">**S2**</span> | Secrets, including Agentry's own `agy_` token format, and the values a declared MCP server's `env` carries in the manifest; on a git-tag publish also the added lines of every commit reachable from the tag, so a key committed and later removed still surfaces |
| <span id="s3">**S3**</span> | Hidden and obfuscated content: zero-width and bidi characters, Unicode tag blocks, confusables, private-use codepoints, HTML comments, CSS-hidden text, data URIs, entropy-gated encoded blobs |
| <span id="s4">**S4**</span> | Prompt-injection signatures: instruction override, exfiltration, tool coercion, credential harvesting, persistence, obfuscation |
| <span id="s5">**S5**</span> | AI Review. A model reads the manifest and every text file of the release, scripts included, against a fixed six-axis rubric — override of the consuming agent, exfiltration, undeclared capability, user deception, obfuscation, destructive actions — with no tools, and returns a score per axis. Agentry's hosted registry uses TypeSafe AI's Jev, pinned to one version (`jev-1.13.0`), which answers each axis with a probability. The run records the model id and a hash of the questions, the thresholds and the request shape, so a verdict can be traced to what produced it. An axis scored 2 (probable) is a medium finding and one scored 3 (clear presence) a high one, except the override and undeclared-capability axes, which are high from 2. Its findings carry medium confidence, so this stage alone never rejects a release; the vendor publishes no accuracy figures for these questions and two identical requests may not answer identically, which is why the version is pinned, a borderline answer is asked three times, and S3, S4 and S6 gate deterministically underneath. A review that fails or answers out of shape routes the release to human review rather than through. A self-hosted registry may use Jev with its own key, an Anthropic-, OpenAI-compatible or Bedrock model (whose output is text, so a judge that shows signs of having been manipulated is itself a finding), a PromptGuard-class classifier that scores only the injection axis and therefore always routes to human review, or no model at all, in which case every release goes to a reviewer |
| <span id="s6">**S6**</span> | Support scripts against the manifest: every shell, Python or JavaScript file in the package (by extension or shebang) is read for network calls, file writes, subprocesses, `eval`, environment reads and download-and-run remote execution (a fetched script piped into a shell), and each is compared with `capabilities`. A script in a package whose `exec` is `none`, a call to a host outside `network.egress`, a write under `filesystem.write: none`, an undeclared subprocess and any remote execution are high; an environment variable outside `secrets` is high too, since it is an undeclared capability. The stage matches text and never runs the script; a host counts only inside a network call, so a URL in a comment is not a finding |
| <span id="s7">**S7**</span> | Declared MCP servers: every `capabilities.mcpServers` package version is checked against the OSV vulnerability database — live the first time a version is seen, from the registry of scanned server versions afterwards — and each advisory is a finding at the advisory's own severity, CVE ids included. A lookup that fails routes to review; a database that is switched off says "not checked", never "no advisories" |
| <span id="s8">**S8**</span> | Metadata, namespace and publisher-behaviour abuse: names that imitate popular agents, suspicious links, keyword stuffing, and two publisher signals, a young account publishing fast and several accounts publishing from one address in a day. The publisher signals are skipped for platform staff, the account set the registry's operator controls; S8's other checks and every other stage still run for them |
| <span id="s9">**S9**</span> | Release-diff risk: the rug-pull check, comparing a version against its predecessor |
| <span id="s10">**S10**</span> | Report assembly into a canonical, digest-addressed document |

The gate then decides: clean and low-severity versions publish
automatically, medium and high findings go to human review, critical
findings are rejected. **A scanner that errors or times out fails toward
review, never through.** Any stage error becomes an `S0/pipeline-error`
finding that forces a human look, and so does a finding that says content
went unread: a file that could not be read, text past the 1 MiB scan cap,
a secrets tool or a git history scan that failed, or a shipped knowledge
pack's text that was not read. And "no path to `published` skips the gate"
is a property test, not a promise.

## What a signature proves

Each published release is content-addressed. On the transition to
`published` (once, and never re-issued), the registry signs an in-toto
statement binding the archive digest to the scan report that produced the
decision, the ruleset version, the judge that reviewed it (the model id where the provider has one), and the policy in force.
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
`/.well-known/agentry/signing-keys.json`. The CLI and the desktop share one
pin store, and pin the keys when you log in, or at the first verification if
you never did. After that, a signature counts only if a pinned key made it.
When a later login finds a different key set, the client says what changed
and keeps the pin:

- If the registry added a key and still lists every pinned one, the client
  reports a possible key rotation. It cannot tell a rotation from a key
  added by whoever answers for the registry's address, so it asks you to
  confirm with the registry's operator and then re-pin deliberately. Until
  you do, a release signed only by the new key is refused.
- If a pinned key is gone, or a pinned key id now carries a different
  public key, the client warns. A rotation never does either.

When the key that verified a release is one the registry lists as retired,
`agentry verify` prints `signed by a retired key (retired <date>)`. The
signature still verifies exactly as before.

A key rotation orphans nothing. The registry keeps every key it has signed
with, and the well-known set lists each one with a `status`: `active` for the
key signing today, `retired` (with `retiredAt`) for a key that signed releases
before and no longer does. A retired key stays listed for as long as an
attestation carries its signature, so a client that pinned it keeps
verifying. When the registry starts on a key that some attestation lacks, it
queues a sweep that countersigns those attestations: the statement inside the
envelope is checked against the release it belongs to and left untouched, and
a second signature by the new key is appended to it. A client that pins only
the new key then verifies a release published before the rotation; a client
that pinned the old key sees the original signature still standing. The
attestation is the same envelope at the same URL with one more signature,
which is why it is served with a short cache lifetime rather than as
immutable. Keys the registry signed with before it kept this record cannot
be listed; the attestations they signed verify through the countersignature.

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
  manifest and sandbox accordingly. That is what it is for. Agentry's own
  runner (`agentry run`, [runner.md](runner.md)) does for everything that
  goes through its gateway; a harness it runs on the host is bounded by its
  configuration and the proxy variables, not by Docker, and another runtime
  may enforce nothing.
- **Scanning happens at publication, not at push and not at run time.** A
  private repository's contents are not scanned until a version is submitted.
  Text a model is about to read can also be scanned, by the registry's
  model-input scan (`POST /model-input/scan`, [model-input.md](model-input.md)).
  The Drafter will use it: AI Review will read each thing the Drafter is about
  to read (the person's description, a search result, a page, a registry
  answer), and the Drafter's model will not be given what AI Review flags or
  cannot scan. That scan covers inputs, not a release, and a draft is scanned
  at publication like any other. A finished draft can also be read the way
  AI Review will read it at publication, before it is submitted
  (`POST /model-input/check`): that tells the person what will be flagged,
  and changes nothing about the publication scan.
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

The same holds for the MCP servers a QuickAgent declares. Every scanned
server version is re-checked daily against the vulnerability database; a
version that gains a high or critical advisory raises a **dependency
alert** on each published QuickAgent version declaring it — shown on the
agent page and the author's dashboard, mailed to the author once their
address is verified, recorded in the audit trail, and sent to org webhooks as `agent.dependency_alert`. An
alert is not an advisory: it says the dependency has a known fix to pin,
and it closes when the affected version is yanked or the advisory is
withdrawn.

Advisories are shown on the affected agent's page, and the site's
`/advisories` page is the global feed — every advisory published against a
public QuickAgent, newest first, each with a permalink — followed by the
explainer of the model and the notification paths. The API serves the same
feed at `GET /api/v1/advisories` (keyset-paged) and one advisory at
`GET /api/v1/advisories/{id}`; `?affecting=namespace/name` narrows the feed
to one QuickAgent.

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
