# Security policy

Agentry is a registry and git host for agents: people rely on its scan reports
and its signatures when they decide what to install. We treat vulnerabilities in
Agentry itself, and malicious content hosted on an Agentry instance, as two
separate reporting paths.

## Reporting a vulnerability in Agentry

**Do not open a public issue for a security vulnerability.**

Email **security@secureagentry.net** — the hosted service's address, which
also covers this code. (A self-hosted registry shows its own operator's
address, from `brand.securityEmail` / `AGENTRY_SECURITY_EMAIL`, on its pages;
a problem in the software itself is still ours to fix, so copy us.) Include:

- what you found and where (file, endpoint, or version),
- how to reproduce it — a minimal case is worth more than a long report,
- what an attacker gains, and
- whether you have shared it anywhere else.

If you cannot use email, use GitHub's private vulnerability reporting on this
repository.

### What to expect

| Stage | Target |
|---|---|
| Acknowledgement that a human has read your report | 2 business days |
| Initial assessment (severity, whether we can reproduce it) | 5 business days |
| Fix or documented mitigation for high/critical issues | 30 days |
| Public advisory + credit (if you want it) | with the fix release |

We will tell you honestly if we disagree that something is a vulnerability,
and why. We will not ask you to sign anything to receive a fix.

### Scope

In scope: the server (`agentryd`) including its `/ui/` pages, the CLI
(`agentry`), the desktop app, the scanner engine and rulesets, the deployment
templates in `deploy/`, and the hosted service if you have an account on it.
Its site and its enterprise build are closed repositories, but a report about
them comes to the same address.

Particularly interesting to us:

- **Authorization bypass** — reaching another org's or user's private agents,
  audit log, or policy; anything the `authz.Check` chokepoint should have
  refused.
- **Publication-gate bypass** — any path that reaches `published` without the
  gate deciding, including scanner errors, timeouts, or races (the pipeline is
  designed to fail closed; a way through it is a serious bug).
- **Scanner escape** — content that executes code in, crashes, or hangs a
  scanner; archive-extraction escapes (path traversal, links, bombs).
- **Signing** — anything that yields a valid attestation for bytes the
  registry did not publish, or that gets a client to accept the wrong key.
- **Git endpoints** — auth bypass, ref smuggling, resource exhaustion.
- **SSRF** — webhooks or any other server-side fetch reaching internal
  addresses or cloud metadata.
- **XSS / content injection** in the server's `/ui/` pages, the rendered
  README (`internal/render`) or the hosted site, via README, manifest, or
  finding excerpts.

Out of scope: findings that require a compromised operator machine or a
malicious platform administrator; missing hardening headers with no
demonstrated impact; automated-scanner output without a working case; denial
of service by sending a lot of traffic; and the known, documented limitations
below.

### Known and documented limitations

These are design facts, not vulnerabilities. Reporting them is welcome as
discussion, but they will not be treated as security bugs:

- **Static scanning cannot prove an agent safe.** A novel injection technique
  can pass a ruleset written before it existed. This is why versions are
  rescanned, and why the product never says "safe" (see `/trust`).
- **Declared capabilities are not runtime-enforced.** The manifest is a
  contract and a policy input; the consuming runtime does the sandboxing.
  Agentry's own runner (`agentry run`) is one such runtime: it enforces them
  for everything that goes through its gateway, while a harness it runs on
  the host is bounded by its configuration and the proxy variables, not by
  Docker (`docs/runner.md`). A third-party runtime may enforce nothing.
- **No transparency log in v1.** Signing-key misuse is detectable after the
  fact through audit logs and KMS alerting, not through a Rekor-style log.
  That is planned, not shipped.
- **Single-administrator self-host risk.** An instance admin can quarantine,
  block, and read everything on their own instance, by design.

## Reporting malicious content on a registry

If an agent hosted on an Agentry instance is malicious — hidden instructions,
credential theft, a rug-pull release, typosquatting — report it. There is no
report control on the agent page yet. A signed-in account posts the report to
`POST /api/v1/agents/{ns}/{name}/abuse-reports`. Without an account, email the
security address the instance's operator publishes; that is where abuse reports
go until the control ships. Include the `namespace/name@version` and what you
observed.

Valid reports are triaged into the platform review queue. Confirmed malicious
content is quarantined (resolution stops, downloads warn) and then blocked
(downloads return 410) with an advisory published against the affected
versions. Authors are notified and can appeal with the scan report and
reviewer rationale in hand.

## Our own supply chain

We hold ourselves to the standard we ask of publishers:

- dependencies are lockfile-pinned and scanned in CI (`govulncheck`,
  `osv-scanner`), with a minimal-dependency policy;
- releases are signed and ship an SBOM;
- no AGPL dependencies are bundled, and no rules under licenses that restrict
  competing use are imported (see the deviations register in [agentry-notes](https://github.com/blaktron/agentry-notes) and PLAN §14.4);
- CI runs an adversarial suite against our own scanners so we find out when
  our detection regresses.

## Credit

We credit reporters in the advisory unless you ask us not to. We do not
currently run a paid bounty; if that changes, this file changes with it.
