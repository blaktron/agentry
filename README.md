# Agentry

**A registry and git host for single-purpose AI agents, with a mandatory
pre-publication security pipeline and signed provenance.**

> This repository is the **open core**: the registry server (`agentryd`), the
> security pipeline, the account and authorization system, the git host, and
> a headless deployment. It runs on its own and serves its own pages at
> `/ui/`. **SecureAgentry** ([secureagentry.net](https://secureagentry.net)) is
> the hosted product built on it: a closed front end (`blaktron/agentry-web`)
> and an enterprise build (`blaktron/agentry-enterprise`) that extend this code
> through documented seams rather than forking it. The technical identifiers —
> the Go module path, the `agentryd` / `agentry` binaries, the `AGENTRY_` env
> prefix — keep the `agentry` name.

Agent instruction files — skills, system prompts, small MCP servers — are
executed with your credentials and your tool access. They are also, today,
distributed with no signing, no malware scanning, and no review. Agentry
treats that as the problem worth solving: every published version is scanned
on the exact bytes that will ship, and nothing becomes installable until the
gate decides.

## What it does

- **Hosts agents in git.** Smart-HTTP push/clone, per-agent permissions, a `v*`
  tag namespace where tags are immutable and creating one needs publish
  permission, so releasing is a distinct right from editing.
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
  and the product never claims it does. Pages show the findings, the ruleset
  version, and when the scan ran; published versions are rescanned as detection
  improves, with quarantine and advisories when something new surfaces.

## Quick look

```bash
# Author
agentry init --modes autonomous incident-summarizer
agentry validate                 # the server's V-rules + S1/S3/S4 scanners, offline
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

Open http://localhost:8080/ui/ — sign-in, your account and tokens, the review
queue, the staff console and organization administration are served by the
server itself. Then [docs/self-hosting.md](docs/self-hosting.md) for a real
deployment.

## Headless, or behind a front end

**Headless.** `deploy/compose` runs the whole registry with no site: Postgres,
object storage, mail, the directory service (authentik, with the account flows
as blueprints), `agentryd`, and an nginx edge. The server's `/ui/` pages are
the browser surface; `agentry login` and the desktop app open its
`/ui/authorize` page to get their token, and everything else they do is the
API. The Helm chart deploys the api, git and worker roles and expects
Postgres, object storage, mail and the identity provider outside it.

**Behind a front end.** A site in front sets `web.url` (where every redirect
and email link the API writes should land), `ui.mode: authorize` (the server
keeps only the device-authorize page), and the brand hooks (`brand.name`,
`logoURL`, `cssURL`, `supportEmail`, `securityEmail`; `GET /api/v1/meta`
reports the name, the logo and the support address). It talks to the same API under the same authorization
matrix — a front end cannot do anything the API refuses. The hosted site is
closed; another one can be built on exactly these hooks
([docs/self-hosting.md](docs/self-hosting.md), "Fronting it with a site").

**Extended.** `pkg/extension` lets an outside Go module mount routes under
`/api/v1/x/<name>/`, run its own migrations in its own schema, replace the
entitlements resolver, subscribe to committed events, and add worker jobs.
The enterprise build is one such module; the core carries none.

## Repository layout

| Path | What |
|---|---|
| `cmd/agentryd` | the server: `agentryd api\|git\|worker\|all` |
| — | the CLI lives in [blaktron/agentry-cli](https://github.com/blaktron/agentry-cli) (depends on this module's `pkg/`) |
| `internal/scan` | the security pipeline: orchestrator, stages S1–S10, gate, judge, signing |
| `internal/registry` | agents, versions, the publication state machine, deterministic archives |
| `internal/gitsrv` | git smart-HTTP, repo storage, policy hooks |
| `internal/api` `internal/auth` `internal/store` | HTTP layer, identity/authz, Postgres |
| `internal/render` | the only path by which author markdown reaches a browser |
| `internal/ui` | the server's own pages at `/ui/` (Go templates, no JavaScript build): device authorize, sign-in, account, review, staff, organizations |
| `pkg/extension` | the seam a closed build extends the server through: routes, migrations, entitlements, hooks, jobs |
| `pkg/` | public: manifest spec + refs, rules engine, embedded ruleset, deterministic archives + extractor, attestation verify, generated API client — the surface the CLI and third parties build on |
| `rules/` | the versioned S3/S4 rule bundle |
| `testdata/attack-corpus/` | the golden corpus: attack fixtures and their benign twins |
| — | the hosted site (front end, brand, its compose overlay and Terraform) lives in blaktron/agentry-web and the enterprise build in blaktron/agentry-enterprise — both closed; a registry runs without them (DEV-091) |
| — | the docs & developers sites live in blaktron/agentry-docs (they clone this repo's `docs/` and `schemas/` at build, beside the site's pages) |
| `deploy/` | the headless compose stack and the Helm chart |
| `docs/` | user, operator, and API docs — start with `trust.md`, `self-hosting.md`, `api-conventions.md` |

## Documentation

- [Trust and security model](docs/trust.md) — what the pipeline checks, what a
  signature proves, and what none of it guarantees; a site in front renders
  the same posture on its `/trust` page, and every instance publishes its live
  signing keys at `/.well-known/agentry/signing-keys.json`
- [Self-hosting](docs/self-hosting.md)
- [Running BriefAgents](docs/runner.md) — every command, flag, policy key and enforcement mechanism of the runner
- [Hosted runs](docs/hosted-runs.md) — running a release on a deployment's own machine: the caps, the credit hold and its settlement, what is refused, and what the receipt carries (a deployment that mounts the runs extension; this repository's server carries none)
- [The log contract](docs/logging.md) — what a line carries, what is never in one, the `event` names a dashboard keys on
- [Operational runbooks](docs/ops/runbooks.md)
- [Contributing](CONTRIBUTING.md) — including the rules that actually matter (route authorization, scanner fixtures)
- [Reporting a vulnerability](SECURITY.md)
- Development notes — the immutable build plan, workgroup tracking, and the deviations register — live in [agentry-notes](https://github.com/blaktron/agentry-notes); new deviations continue there

## Status

Milestones **M0–M7** of the v1 plan are implemented, with automated
acceptance scripts in `scripts/acceptance/` (`m0`–`m4`, `m6`, `m7`,
`ui.sh` for the core's own pages, and `directory-signout.py` against a live
directory): scaffolding and CI (M0), identity
and authorization (M1), git hosting (M2), the registry and publication state
machine (M3), the security pipeline (M4), the web UI (M5 — since moved to the
closed site repository; the core keeps its own `/ui/` pages), enterprise
SSO/SCIM and webhooks (M6), and the AWS reference deployment (M7 — Terraform
validated, never applied to a live account; it now lives with the site).

**M8 (launch hardening) is partial.** Done: SECURITY.md and coordinated
disclosure, CONTRIBUTING/DCO, signed releases with SBOM (built with
reproducible-build flags; no step yet rebuilds and compares),
release-please automation, GDPR erasure, abuse intake and the trust & safety
console, the operational runbooks. Remaining: an external penetration test, a
status page, and `security@` / `abuse@` addresses live before launch. Seed
content is decided: PLAN §20 Q10 named the forty worked BriefAgents in
`agentry-examples` (DEV-093), and production launches with none published
(`production-on-vultr.md` D14).

An independent audit of this repository found the tracking documents
overstating completeness, and roughly nineteen departures from the plan that
were never recorded. The substantive gaps in the code have since been fixed and
the register backfilled.

The register in [agentry-notes](https://github.com/blaktron/agentry-notes)
records the departures that make a claim weaker, not only the ones that make it
stronger.

Decided since the plan was written: the product name (**Agentry**, PLAN
§20 Q1 — this module keeps the `agentry` technical name) and the license
(**MIT**, Q2), and the hosted registry's judge (Q3: TypeSafe AI's Jev as the
`typesafe` provider, DEV-113, 2026-09-20). The launch baseline policy (Q4)
is decided: the built defaults stand (DEV-093, 2026-09-07).

## License

MIT (see [LICENSE](LICENSE)), with a DCO and no CLA — see
[CONTRIBUTING.md](CONTRIBUTING.md).
