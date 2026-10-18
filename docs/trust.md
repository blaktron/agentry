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

There is no flag, plan, or role that lets a public version skip the pipeline.
A version is scanned on **the exact bytes that will
ship**: the deterministic archive, not the working tree, not the tag as the
author describes it.

Ten stages run against those bytes:

| | |
|---|---|
| <span id="s1">**S1**</span> | Inventory and hygiene: safe unpack, content-sniffed types, archive anomalies, binaries. An `exec` declaration that names `ssh`, `scp`, `sftp` or `rsync` is a low finding pointing at `capabilities.targetHosts`, under which the runner makes the connection rather than the agent |
| <span id="s2">**S2**</span> | Secrets, including Agentry's own `agy_` token format, and the values a declared MCP server's `env` carries in the manifest; on a git-tag publish also the added lines of every commit reachable from the tag, so a key committed and later removed still surfaces |
| <span id="s3">**S3**</span> | Hidden and obfuscated content: zero-width and bidi characters, Unicode tag blocks, variation selectors (emoji smuggling), confusables, private-use codepoints, HTML comments, CSS-hidden text, data URIs, entropy-gated encoded blobs. A zero-width joiner inside an emoji sequence, a byte-order mark at the start of a file and one variation selector that completes a standard variation sequence (a red heart's U+FE0F, a keycap) are how ordinary text is written and are not findings; the same characters anywhere else are high |
| <span id="s4">**S4**</span> | Prompt-injection signatures: instruction override, exfiltration, tool coercion, credential harvesting, persistence, obfuscation, destructive instructions. The exfiltration and credential-harvesting signatures look for an instruction addressed to the agent (a sentence or clause that opens with the verb, or follows "you", "then", "please" and the like), so a security review's code samples, tables and descriptions of a risk do not match them; a paraphrase they do not anticipate is not matched either, which AI Review and S6 sit underneath. The injection families are high. A credential-harvesting, exfiltration or destructive match is rated by what its lines name against what the manifest declares: high for a host, address, secret, credential file or program the manifest does not declare (an email recipient is never declared), or when it declares nothing of the kind (a browser's own hosts are a way out, the site the person names at run time is not); medium for declared egress hosts, hosts a declared browser may open (its `hosts`, exact or below a `*.` entry, or any host where its scope is `public`; since ruleset 0.4.9), declared programs a hosted run does not provide, and an instruction that names no secret or program where the capability is declared; low for named declared secrets, the base commands every run has, and declared MCP servers. The runner refuses at run time any capability the manifest does not declare, whatever the rating |
| <span id="s5">**S5**</span> | AI Review. A model reads the manifest and every text file of the release, scripts included, against a fixed six-axis rubric — override of the consuming agent, exfiltration, undeclared capability, user deception, obfuscation, destructive actions — with no tools, and returns a score per axis. Agentry's hosted registry uses TypeSafe AI's Jev, pinned to one version (`jev-1.13.0`), which answers each axis with a probability. The run records the model id and a hash of the questions, the thresholds and the request shape, so a verdict can be traced to what produced it. An axis scored 2 (probable) is a medium finding and one scored 3 (clear presence) a high one, except that the override, undeclared-capability and user-deception axes are high from 2, and the exfiltration and destructive-action axes are medium at most: sending data somewhere or deleting it needs a capability, and a capability the manifest does not declare is held by the undeclared-capability axis and by S4's rating, and refused by the runner at run time. The undeclared-capability axis is given the release's stated purpose (its name, summary and guide overview) and holds only an instruction to do something dangerous — reading secrets, sending data to a host, downloading or running code, changing files outside the run's own output, keeping anything between runs — that needs a capability the manifest does not declare and is out of line with that purpose. An undeclared capability that serves the stated purpose is not held, because the runner refuses it at run time. The axis is also told what every run is given whatever it declares (the person's files read-only, its own output, its answer), and, when the manifest declares `targetHosts`, that running commands on and administering the machine the person names is declared, while reaching another machine from it or sending what the agent reads there to any other host is not, unless the stated purpose intends it; text that describes a risk for the agent to look for, and an example of the request the agent is given, do not count. Hidden instructions or instructions against the person's wishes are the override, user-deception and obfuscation axes' to hold. Its findings carry medium confidence, so this stage alone never rejects a release; the vendor publishes no accuracy figures for these questions and two identical requests may not answer identically, which is why the version is pinned, a borderline answer is asked three times, and S3, S4 and S6 gate deterministically underneath. A review that fails or answers out of shape routes the release to human review rather than through. A self-hosted registry may use Jev with its own key, an Anthropic-, OpenAI-compatible or Bedrock model (whose output is text, so a judge that shows signs of having been manipulated is itself a finding), a PromptGuard-class classifier that scores only the injection axis and therefore always routes to human review, or no model at all, in which case every release goes to a reviewer |
| <span id="s6">**S6**</span> | Support scripts against the manifest: every shell, Python or JavaScript file in the package (by extension or shebang) is read for network calls, file writes, subprocesses, `eval`, environment reads and download-and-run remote execution (a fetched script piped into a shell), and each is compared with `capabilities`. A declared target host or browser changes none of this: a script that runs `ssh` itself, or calls a host the browser may open, is the release reaching a host on its own. A script in a package whose `exec` is `none`, a call to a host outside `network.egress`, a write under `filesystem.write: none`, an undeclared subprocess and any remote execution are high; an environment variable outside `secrets` is high too, since it is an undeclared capability. The stage matches text and never runs the script; a host counts only inside a network call, so a URL in a comment is not a finding. An `ssh`, `scp`, `sftp` or `rsync` destination or jump host counts written `user@host` or `user@host:path` too (since ruleset 0.4.6); an e-mail address in a comment, in another command's arguments or in the command `ssh` runs remotely does not. A command written with its path (`/usr/bin/curl`), inside backticks or escaped with a backslash (`\curl`) is that command (since ruleset 0.4.7), and so is a pipe into a path-qualified shell (`| /bin/sh`); a word that only contains a command's name, such as `/etc/ssh/sshd_config`, is not. Since ruleset 0.4.8 a host may also be an IP address, the host of an `ftp`, `sftp`, `scp`, `ssh`, `rsync`, `telnet` or `ws` URL, a destination with no user or a dynamic one (`$(whoami)@host`), the destination of `ssh-copy-id`, `autossh`, `mosh` or `sshfs`, or a destination the script keeps in a variable it assigns; commands run in a quoted command substitution or by `sh -c` and `eval` are read too, and a loopback address is not a host. An IPv6 address cannot yet be declared in `network.egress`, so a script that reaches one is held unless the manifest declares `"*"`. Since ruleset 0.4.12 a host may also be the target of a redirection to `/dev/tcp/HOST/PORT` or `/dev/udp/HOST/PORT`, the host of a connecting `socat` address (`TCP:`, `TCP4:`, `TCP6:`, `UDP:`, `OPENSSL:` and their `-CONNECT`, `-SENDTO` and `-DATAGRAM` spellings), the `user@host:path` remote of a `git` `clone`, `fetch`, `pull`, `push`, `ls-remote`, `remote`, `submodule` or `subtree`, the registry of a `docker` or `podman` `pull` or `push` (`registry.example.org:5000/app`), or an IPv6 address written without brackets as a word of `nc`, `telnet` and the other network commands or as an ssh destination; an e-mail address, a `git` commit message and an image name with a tag (`ubuntu:22.04`) are not hosts. A host that reaches a command through a loop over an array, a line read from a file (`while read h`) or the output of another command (`H=$(cat host.txt)`) is beyond what a scan of text can know and is not read: the run holds a script to the declared `network.egress` whatever the scan read ([the runner](runner.md#support-scripts-what-the-scan-reads)). Since ruleset 0.4.10 S6 also reads the other direction, needed but not declared: the runner tools the instruction file calls for by name, against the line of `capabilities` that gives each (the browser tools against `browser`, `run_command` against `exec` commands, `fetch` against `network.egress` hosts, the host tools against `targetHosts`, `fs_read`, `fs_list` and `fs_write` against `filesystem`, and a `<server>__<tool>` name against `mcpServers`). A run has no tool its manifest does not grant, so each line missing is one high finding, `S6/ungranted-tool`, naming the tools and the line to add: the version goes to a person and is never rejected. A tool named only where the instruction turns it away ("not `browser_pdf_save`", "never call `fetch`", "if you have `run_command`"), or in a paragraph that speaks of another package as "a QuickAgent" or "the QuickAgent's own", is not counted, and neither is a word such as "browser" or "fetch the page" in prose. A rescan under a new ruleset weighs the finding at medium, so it never quarantines a published version |
| <span id="s7">**S7**</span> | Declared MCP servers: every `capabilities.mcpServers` package version is first asked of its own registry (npm or PyPI). A version the registry does not publish is the finding `S7/version-not-published`, critical, so the version is rejected: no run could install it, and its registry row records it as not published. A registry that does not answer is `S7/version-not-checked`, medium, and the version publishes with it. Every published version is then checked against the OSV vulnerability database — live the first time a version is seen, from the registry of scanned server versions afterwards — and each advisory is a finding, CVE ids included. A Critical advisory rejects the version. A High one is a high finding from a CVSS base score of 8.5, computed from its v3.x or v4.0 vector, and when it has no score; below 8.5 it is medium. A Moderate or Low one keeps its own severity, and the registry records and alerts on each advisory's own severity. A server with no data (a failed lookup with no earlier answer, or no npm or PyPI pin) is the finding `S7/osv-no-data`, medium, so the version still publishes, and the daily sweep looks it up again. The registry records a package with no known advisory as having none. A database that is switched off says "not checked", never "no advisories". A remote MCP server, declared by its address, has no package to look up: it is the finding `S7/remote-server`, low, naming its address, auth and scopes, and the version publishes with it. The pipeline has checked the address and scopes, not the vendor's code |
| <span id="s8">**S8**</span> | Metadata, namespace and publisher-behaviour abuse: names that imitate popular agents, suspicious links, keyword stuffing, and two publisher signals, a young account publishing fast and several accounts publishing from one address in a day. The publisher signals are skipped for platform staff, the account set the registry's operator controls; S8's other checks and every other stage still run for them |
| <span id="s9">**S9**</span> | Release-diff risk: the rug-pull check, comparing a version against its predecessor. A host the manifest declares in `network.egress` is a low finding, whether it was declared before or in this release, in the manifest and in the content: reaching the internet is what an agent is for, the host is shown to whoever installs it and the runner holds the run to it. So is a host a declared browser may open, named in its `hosts` exactly or below a `*.` entry (since ruleset 0.4.9): in the content it reads as declared, and a new one in the manifest is a low finding, or medium for a `*.` entry, which names every host below it. A destination the manifest does not declare that first appears in the content is high in a patch release and medium otherwise, and an email recipient is never declared that way. A destination is a URL's host, an email recipient, an IPv4 address, or a bare name under a top-level domain ICANN delegates (or a reserved one such as `.example`). A two-label name under a domain that is also a common file extension (`.md`, `.zip`, `.mov`, `.java`, and `.sh`, `.py`, `.pl`, `.pm`, `.rs` or `.so` with no path after it), and a dotted name in program source outside a string (`user.email`), are not; in a Markdown code span or fenced block a bare name counts when it is quoted, has a path after it, or is under a top-level domain hosts are usually under (`.com`, `.io`, a country code), so `` `window.name` `` and `` `request.post` `` are not hosts and `` `crates.io` `` is. A URL's host loses the punctuation around it (so `` `https://api.example.com` `` in a code span is `api.example.com`), but a character no host name holds inside one keeps the whole name, which matches no declared host. A suspicious link is S8's finding. A hidden-content technique the previous release did not use is high when S3 rates it medium or above, and a medium S3 or S4 finding that arrives with the release is raised to high, except an S4 finding rated by what the manifest declares, whose capability the manifest diff reports; a newly added HTML comment on its own is not held. A version published as a hosted Drafter revision of the agent's current release (Edit with AI's *Publish this version*) is scanned as a first release where its draft is proved: the registry computes a proof of the manifest and the instruction file it received and asks the deployment whether the submitter ran that draft against that release and recorded the same proof. When it did, the version's source is `drafter-revision`, and the manifest and instruction file get no content diff and no raise. The manifest diff still reports, every other file is diffed as usual, and the report carries an info finding naming the draft. A claim that does not match, or a registry without the hosted extension, gets the usual S9 |
| <span id="s10">**S10**</span> | Report assembly into a canonical, digest-addressed document |

The gate then decides: a version whose findings are low or medium
publishes automatically, with every finding on its report; a high finding
goes to human review; a critical one is rejected. Attempted injections,
dangerous undeclared capabilities out of line with the release's stated
purpose, and instructions to mislead the user are rated high, so they
always reach a person; text about a capability the manifest declares is
not.
This is the baseline of ruleset 0.3.0, which moved it from holding medium
too; the threshold is released with the ruleset that judges the findings,
and an organization that wants medium held sets its policy's
`maxAutoPublishSeverity` to `low`. **A scanner that errors or times out
fails toward review, never through.** Any stage error becomes an
`S0/pipeline-error` finding that forces a human look, and so does a finding
that says content went unread: a file that could not be read, text past
the 1 MiB scan cap, a secrets tool or a git history scan that failed, or a
shipped knowledge pack's text that was not read. The one lookup that can
fail without holding the version is S7's: a failed advisory lookup is
reported as a finding and looked up again by the daily sweep. And "no path
to `published` skips the gate" is a property test, not a promise.

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
never "safe" or "verified secure". That is a
rule about honesty, and these are the specific things behind it:

- **Static analysis cannot prove an agent safe.** A sufficiently novel
  injection technique will pass a scan written before it existed. That limit is unresolvable,
  not mitigated. Every
  agent page publishes finding counts and the ruleset version so a reader
  can judge the freshness of the check instead of trusting a badge.
- **Declared capabilities are a contract, not a sandbox.** The manifest says
  what an agent claims to need: network egress, filesystem access,
  subprocess execution, secrets. The registry checks that claim against the
  manifest and gates on it (the publication policy), but it cannot enforce anything
  once the agent is running on your machine. Your runtime should read the
  manifest and sandbox accordingly. That is what it is for. Agentry's own
  runner (`agentry run`, [runner.md](runner.md)) does for everything that
  goes through its gateway; a harness it runs on the host is bounded by its
  configuration and the proxy variables, not by Docker, and another runtime
  may enforce nothing.
- **Scanning happens at publication, not at push and not at run time.** A
  private repository's contents are not scanned until a version is submitted.
  That is a release's scan. What a run is given is checked when it runs: a
  run's files are checked by ClamAV and, for the risky types, looked up on
  Hybrid Analysis by their SHA-256 (never uploaded) before the agent starts,
  locally and on Agentry, and on Agentry AI Review also reads their text
  ([running with files](runner.md#running-with-files)). Those checks find
  known malware and instructions aimed at the model; they do not prove a
  file harmless, and a local run without a Hybrid Analysis key of your own
  makes no lookup. Text a model is about to read can also be scanned, by the registry's
  model-input scan (`POST /model-input/scan`, [model-input.md](model-input.md)).
  The Drafter uses it: AI Review reads each thing the Drafter is about
  to read (the person's description, a search result, a page, a registry
  answer), and the Drafter's model is not given what AI Review flags or
  cannot scan. That scan covers inputs, not a release, and a draft is scanned
  at publication like any other. A finished draft can also be read the way
  AI Review will read it at publication, before it is submitted
  (`POST /model-input/check`): that tells the person what will be flagged,
  and changes nothing about the publication scan.
- **The shipped scanners are good, not identical to the established tools
  they stand in for.** S2 uses a native Go implementation behind an adapter
  interface, with gitleaks optional beside it. It detects everything the
  committed attack corpus exercises.
- **Review is human, and humans are the ones deciding.** Reviewer
  dismissals (false positive, or accepted risk) stay on the public report
  with their rationale, so a waived finding is visible rather than erased.
  An author never decides their own version, nor confirms or dismisses
  one of its findings, with one exception: platform staff may review any
  version in review, their own included, and such a decision or verdict is
  marked as theirs in the audit log.

## Because detection improves after publication

A scan is a statement about one moment. Published versions are therefore
**rescanned when a new ruleset ships**. The sweep is triggered by ruleset
registration, not by a human remembering. A version that newly trips a
high-severity finding is quarantined: it stops resolving for new installs,
a direct download is refused with `409 Conflict` and the reason, the web
page carries the warning, and an advisory is raised against it. A version
or agent that trust & safety has confirmed malicious is **blocked**, and
downloads then return `410 Gone`.

Lifting a block or a quarantine is a scan too. Platform staff's
reinstate publishes nothing by itself: it asks for a fresh scan of each
blocked or quarantined version of the agent and runs it through the same
gate, under the policy then in force. A version the gate passes is published
again, and its review item is closed with the reinstate's reason. Every other
version stays quarantined (a blocked one becomes quarantined), with an open
platform review item for a person to decide against the new scan. A version
admitted without a scan has nothing to scan and stays as it is.

A new ruleset also judges the review queue again. Every version still
waiting for a person is scanned under the new rules and run through the
same gate as a fresh submission, under the policy then in force. One that
now passes is published and signed like any other, and its review item is
closed as superseded rather than approved, since no person decided it. One
that is still held, or that the new rules would reject, stays with the
person already asked, with the new scan as its report. Only the gate's
verdict on the new scan counts: a forced review in it (no AI Review ran, a
stage failed, content went unread, a policy that requires a person) holds
the version as it would a submission, and a version first held because the
pipeline failed is published only if the new scan completes and passes.
While that scan runs, a reviewer still sees, and approves, the last
finished report.

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

The feed and the permalinks name public QuickAgents only. A QuickAgent its
publisher made private, retired or deleted leaves them, and so does every
advisory against it, published before or after. The people who installed it
while it was public still get those advisories through
`?affecting=namespace/name`: a signed-in account whose install record names
it, or any client that adds `&digest=sha256:…`, the archive digest of a
release of it that it holds. Anyone else gets the same "not found" a name
that never existed gets.

## Everything here is auditable

The scanners, the rulesets, the gate and the review queue are open source.
The attack corpus that gates CI (attack fixtures and their benign
lookalikes, including a security-documentation agent that must stay
publishable) is in `testdata/attack-corpus/`. The gate's cases (sets of
findings, flags and policies, each with the outcome the gate reaches) are
published as data in `pkg/gatecases`, which the gate's own test runs case by
case, so a client can test what it says about the gate against the same
table. The claims on this page are checkable against the code that makes
them.

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
