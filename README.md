# Agentry

**A registry and git host for single-purpose AI agents, with a mandatory
pre-publication security pipeline and signed provenance.**

> Codename. All names here are placeholders pending a trademark decision
> (PLAN §20 Q1); the module path, binaries, and env prefix keep the
> `agentry` / `agentryd` / `AGENTRY_` forms so a rename stays mechanical.

Agent instruction files — skills, system prompts, small MCP servers — are
executed with your credentials and your tool access. They are also, today,
distributed with no signing, no malware scanning, and no review. Agentry
treats that as the problem worth solving: every published version is scanned
on the exact bytes that will ship, and nothing becomes installable until the
gate decides.

## What it does

- **Hosts agents in git.** Smart-HTTP push/clone, per-agent permissions, a
  protected `v*` tag namespace so releasing is a distinct right from editing.
- **Gates publication.** Ten scanner stages look for prompt injection, hidden
  and obfuscated content, secrets, undeclared capabilities, dependency and
  install-script risk, publisher anomalies, and rug-pull release diffs. Clean
  versions publish; medium and high findings go to human review; critical
  findings are rejected. A scanner that errors or times out fails **toward**
  review — never through.
- **Makes capabilities explicit.** The manifest declares network egress,
  filesystem access, subprocess execution, and expected secrets. Consumers see
  it before installing, policy engines act on it, and the code scanner diffs it
  against what the code actually does.
- **Signs what it publishes.** Each release is content-addressed and carries an
  in-toto/DSSE attestation binding the archive digest to its scan report,
  ruleset version, and policy. `agentry verify` checks it offline.
- **Says what it does not know.** Static analysis cannot prove an agent safe,
  and the product never claims it does. Pages show the findings and the
  ruleset version they came from; published versions are rescanned as detection
  improves, with quarantine and advisories when something new surfaces.

## Quick look

```bash
# Author
agentry init --kind=skill incident-summarizer
agentry validate                 # the server's V-rules + S3/S4 scanners, offline
git push origin main && git tag v1.0.0 && git push origin v1.0.0

# Consumer
agentry install acme/incident-summarizer --target=claude-skill
agentry verify  acme/incident-summarizer@1.0.0
```

Install prints the declared capabilities and asks before installing anything
that can reach the network or run commands.

## Try it locally

```bash
make db-up      # local Postgres 16
make dev        # migrations + agentryd (all roles) on :8080
```

Then [docs/self-hosting.md](docs/self-hosting.md) for a real deployment, or
`cd web && npm run dev` for the web app.

## Repository layout

| Path | What |
|---|---|
| `cmd/agentryd` | the server: `agentryd api\|git\|worker\|all` |
| `cmd/agentry` | the CLI |
| `internal/scan` | the security pipeline: orchestrator, stages S1–S10, gate, judge, signing |
| `internal/registry` | agents, versions, the publication state machine, deterministic archives |
| `internal/gitsrv` | git smart-HTTP, repo storage, policy hooks |
| `internal/api` `internal/auth` `internal/store` | HTTP layer, identity/authz, Postgres |
| `internal/render` | the only path by which author markdown reaches a browser |
| `pkg/manifest` `pkg/rules` | public: the manifest spec, and the rules engine that powers `agentry validate` |
| `rules/` | the versioned S3/S4 rule bundle |
| `testdata/attack-corpus/` | the golden corpus: attack fixtures and their benign twins |
| `web/` | the Next.js registry UI |
| `deploy/` | compose, Helm, Terraform |
| `docs/` | user, operator, and API docs — start with `trust.md`, `self-hosting.md`, `api-conventions.md` |

## Documentation

- [Trust and security model](docs/trust.md) — what the pipeline checks, what a
  signature proves, and what none of it guarantees; the `/trust` page on any
  running instance shows the same posture plus that instance's live signing keys
- [Self-hosting](docs/self-hosting.md)
- [Operational runbooks](docs/ops/runbooks.md)
- [Contributing](CONTRIBUTING.md) — including the rules that actually matter (route authorization, scanner fixtures)
- [Reporting a vulnerability](SECURITY.md)
- [PLAN.md](PLAN.md) — the full build plan this implementation follows; [WORKGROUPS.md](WORKGROUPS.md) tracks progress against it, and [DEVIATIONS.md](DEVIATIONS.md) records where reality differed

## Status

Milestones **M0–M7** of the v1 plan are implemented, each with an automated
acceptance script in `scripts/acceptance/`: scaffolding and CI (M0), identity
and authorization (M1), git hosting (M2), the registry and publication state
machine (M3), the security pipeline (M4), the web UI (M5), enterprise SSO/SCIM
and webhooks (M6), and the AWS reference deployment (M7 — Terraform validated,
never applied to a live account).

**M8 (launch hardening) is partial.** Done: SECURITY.md and coordinated
disclosure, CONTRIBUTING/DCO, signed reproducible releases with SBOM,
release-please automation, GDPR erasure, abuse intake and the trust & safety
console, the operational runbooks. Remaining: an external penetration test, a
status page, seed content beyond the four example agents (blocked on PLAN §20
Q10), and `security@` / `abuse@` addresses live before launch.

An independent audit of this repository found the tracking documents
overstating completeness and roughly nineteen departures from PLAN.md that were
never recorded; remediation waves have since fixed the substantive gaps in the
code and backfilled the register.

See [WORKGROUPS.md](WORKGROUPS.md) for the state of each workgroup and what is
explicitly deferred, and [DEVIATIONS.md](DEVIATIONS.md) for where the
implementation departs from the plan — including the departures that make a
claim weaker, not just the ones that make it stronger.

Not yet decided (they need a human, per PLAN §20): the product name, the open
source license, the SaaS judge provider and region, and how strict the launch
baseline policy should be.

## License

Pending (PLAN §20 Q2); the planning default is Apache-2.0 with a DCO and no
CLA. Contributions are accepted on that basis — see
[CONTRIBUTING.md](CONTRIBUTING.md).
