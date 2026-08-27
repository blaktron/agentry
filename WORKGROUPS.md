# Agentry — Workgroup Breakdown

Derived from [PLAN.md](PLAN.md) §18 (milestones) and §18.3 (ordering/parallelization). Each workgroup (WG) is an independently assignable unit of work with explicit dependencies and acceptance criteria. Statuses are maintained here as the build proceeds.

**Critical path:** WG-A → WG-B → (WG-D ∥ WG-G) → WG-E/WG-F → WG-H → WG-I → WG-L
**Parallel lanes:** WG-C (git) after WG-B · WG-J (enterprise) after WG-B · WG-K (infra) after WG-A

```
WG-A Foundation (M0)
 ├─ WG-B Identity & Access (M1)
 │   ├─ WG-C Git Hosting (M2)            [parallel lane]
 │   ├─ WG-E Registry Core (M3)
 │   └─ WG-J Enterprise SSO/SCIM (M6)    [parallel lane]
 ├─ WG-D Manifest & Package Format (M3)  [parallel after A]
 ├─ WG-G Rules Engine + Rulesets (M4 seed) [parallel after A]
 └─ WG-K AWS Infra (M7)                  [parallel after A]
WG-E + WG-D + WG-G
 ├─ WG-F CLI v0 (M3)
 └─ WG-H Security Pipeline (M4)
WG-H → WG-I Web UI (M5) → WG-L Launch Hardening (M8)
```

---

## WG-A — Foundation (M0, effort M)

**Plan refs:** §18.1 layout, §18.2 M0, D-04, D-09, D-17.
**Depends on:** nothing.

Scope:
- Monorepo layout exactly per §18.1; git init; `PLAN.md` immutable; `DEVIATIONS.md` created.
- Go module `github.com/PLACEHOLDER_ORG/agentry`; binaries `agentryd` (roles api|git|worker|all) and `agentry`.
- Config loading: `agentry.yaml` + `AGENTRY_*` env overrides.
- `/healthz`, `/readyz`; OpenAPI 3.1 spec-first skeleton (`schemas/openapi.yaml`) with `GET /api/v1/meta`; generated Go + TS clients.
- goose migrations wired (initial migration: extensions); pgx pool; sqlc configured.
- Compose dev stack (postgres, minio, mailpit); Makefile (`make dev`, `make check`).
- CI workflows: lint (golangci-lint), test, build, oasdiff breaking-change gate, govulncheck.

Acceptance (scripts/acceptance/m0.sh): `make check` green; server boots; smoke test hits `/api/v1/meta` through generated Go client and TS client.

**Status: ✅ complete** — layout, config loader (+tests), healthz/readyz/well-known, OpenAPI spec + oapi-codegen server/Go client + openapi-typescript TS client, goose migrations (citext/pg_trgm), sqlc wired, Makefile, compose stack, CI workflows (check/govulncheck/oasdiff), `scripts/acceptance/m0.sh` green locally against real Postgres 16. See DEV-001 (no Docker on build host), DEV-002 (OpenAPI 3.0.3).

---

## WG-B — Identity & Access core (M1, effort L)

**Plan refs:** §4 (users/orgs/handles/teams DDL), §12.1–12.3, §12.6, D-22, D-23, §17.4.
**Depends on:** WG-A.

Scope:
- Migrations + sqlc stores: handles, users, identities, orgs, memberships, teams, team_members, pats, audit_events (partitioned), sessions.
- Register/login (argon2id), TOTP 2FA setup/verify, server-side sessions (httpOnly SameSite=Lax cookie).
- PATs: `agy_` prefix + 32B random, sha256 at rest, scopes per §12.3, expiry, last-used, revocation.
- RBAC: role model §12.2, per-agent grants tables, single `authz.Check` chokepoint, every route declares `(resource, action)`.
- Audit skeleton: append-only writer, action catalog in code (`internal/audit/actions.go`).
- Rate limiting (in-memory fallback; Redis optional per D-06).
- Org/team/member management endpoints.

Acceptance: authz matrix test (§17.4) enumerates every route × role × org-boundary and passes; PAT lifecycle e2e; audit rows asserted for every mutating call.

**Status: ⏳ not started**

---

## WG-C — Git Hosting (M2, effort L)

**Plan refs:** §6 complete, D-07, D-19, §17.2.
**Depends on:** WG-B (PAT auth). Parallel with WG-E/WG-F.

Scope:
- Smart HTTP v2 (`info/refs`, `upload-pack`, `receive-pack`) shelling out to git binary; protocol v2; shallow/partial clone on.
- Bare repos at `/data/git/{uuid[0:2]}/{uuid}.git`; creation with hooks symlinked to agentryd shim.
- PAT Basic auth; per-op authz table §6.4; anonymous public read; sessions never accepted.
- pre-receive: size quota, protected `v*` tags (publish permission), no force-push default branch, nested `.git` block, oversize object block. post-receive: `repo.pushed` event, auto-publish tag trigger.
- Concurrency semaphores; gc worker job.

Acceptance: `scripts/conformance/git.sh` matrix green (clone/fetch/push × public/private × PAT states × shallow/partial × quota/tag rejections).

**Status: ⏳ not started**

---

## WG-D — Manifest & Package Format (M3 part, effort M)

**Plan refs:** §5 complete (spec, V1–V8, capability vocabulary, channels), `pkg/manifest`.
**Depends on:** WG-A. Fully parallel with WG-B.

Scope:
- `pkg/manifest`: parse (YAML 1.2, closed schema), validate V1–V8, canonical JSON form, capability vocabulary types.
- `schemas/agent-manifest-1.schema.json` generated/kept in sync.
- Quota checks (§19) as pure functions; entrypoint rules per kind; SPDX license check for public publish.

Acceptance: table-driven tests over valid/invalid manifests incl. every V-rule; fuzz target for the parser (§17.5).

**Status: ⏳ not started**

---

## WG-E — Registry Core (M3, effort L)

**Plan refs:** §7 state machine, §6.5 archive builder, §9.4 download path, §5.5 channels/yank, D-15.
**Depends on:** WG-B, WG-D. (git-tag source additionally on WG-C; cli-upload source does not.)

Scope:
- Agents CRUD + grants endpoints; version submission (both sources), immutability trigger.
- State machine on `agent_versions.status` (single writer, SELECT FOR UPDATE), all transitions audited; pipeline stubbed auto-approve in dev mode.
- Deterministic archive builder (sorted tar, zeroed mtimes, normalized modes, zstd, sha256 identity; allowlist filter; symlink/`..` rejection).
- Content-addressed storage: S3 client + local-FS fallback (self-host, dev).
- `GET /resolve` semver resolution incl. channels + yank semantics; download 302; install counting.

Acceptance: publish→install round-trip e2e for all 3 kinds × both sources; archives byte-reproducible across two builds; yank semantics test; no path to `published` skipping the gate (property test, with M4).

**Status: ⏳ not started**

---

## WG-F — CLI v0 (M3 part, effort M)

**Plan refs:** §11, D-12, §8.3 local parity note.
**Depends on:** WG-D, WG-E (API), WG-G (validate subset).

Scope:
- cobra CLI: `init` (+ `--from` import wizards that never guess capabilities silently), `validate` (V-rules + S1/S3/S4 subset via `pkg/rules`), `login` (PAT in OS keychain), `publish` (tag + upload modes; streams pipeline progress), `install` (resolve→verify digest+signature→capability diff→export claude-skill/mcp/agents-md), `verify`, `search`, `info`, `yank`.
- Multi-registry config `~/.config/agentry/config.yaml`; TOFU key pinning.

Acceptance: CLI e2e against dev stack covering §18.2 M3 round-trip; exporters produce valid target formats (fixture-verified).

**Status: ⏳ not started**

---

## WG-G — Rules Engine + Rulesets (M4 seed, effort M)

**Plan refs:** §8.3 S3/S4 definitions, `pkg/rules`, `/rules` data layout, §17.3 corpus.
**Depends on:** WG-A. Fully parallel with WG-B..WG-E.

Scope:
- `pkg/rules`: S3 detectors (zero-width, bidi/Trojan Source, Unicode tag block, confusables/mixed-script, PUA, HTML comments, CSS-hidden, data-URI, base64/hex runs entropy-gated, trailing whitespace, NFC deltas) + S4 signature engine (versioned YAML rules: id, severity, confidence, refs, match+non-match fixtures).
- `/rules` initial ruleset content: instruction-override, exfiltration, tool-coercion, credential-harvest, persistence, obfuscation families.
- Fixture runner: every rule's fixtures are tests; start `testdata/attack-corpus/` with one fixture per S3 class and S4 family + benign lookalikes.

Acceptance: corpus recall 100% on expected findings; benign lookalikes pass; rule bundle digest computed reproducibly.

**Status: ⏳ not started**

---

## WG-H — Security Pipeline (M4, effort XL)

**Plan refs:** §8 complete, §7 gates, D-13, D-16, §17.3, §17.5.
**Depends on:** WG-E, WG-G.

Scope:
- River queue + scan-orchestrator; DAG (S1 first; S2–S9 parallel; S10 assemble); idempotent stages; per-stage timeouts; fail-closed (§7 timeout rule).
- Hardened extractor (shared package, fuzzed): traversal/symlink/zip-bomb/device rejection.
- Scanners: S1 inventory/hygiene, S2 secrets (gitleaks + `agy_` rule; archive + git history), S3/S4 via pkg/rules, S5 judge (provider iface: bedrock/anthropic/none/classifier; hardening §8.4), S6 capability-consistency (opengrep rulepacks JS/TS+Python, declared-vs-detected diff), S7 deps/licenses (osv-scanner lib, typosquat, install-script detection), S8 metadata/publisher abuse, S9 release-diff risk, S10 report assembly (canonical JSON, report_digest).
- Gate (§8.5) + policy engine (§8.6, tighten-only) + review queue API + finding verdicts.
- Rescan sweeps + quarantine + advisories (§8.7).
- Signing: DSSE/in-toto via KMS or file key (D-16); attestation endpoint; well-known keys; CLI full `verify`.
- Ruleset release tooling.

Acceptance: attack-corpus gate green (100% recall, no benign regressions); state-machine property tests (no path to `published` skipping gate incl. scanner error); attestation verified offline by CLI; policy tighten-only property test.

**Status: ⏳ not started**

---

## WG-I — Web UI (M5, effort L)

**Plan refs:** §10 complete, D-08, D-11, §17.1 Playwright flows.
**Depends on:** WG-A (contract); pages grow with WG-B/E/H. Reviewer UI needs WG-H.

Scope:
- Next.js SSR app: public pages (home, search, agent page §10.2, version/report page, namespace, trust, advisories, docs), authed (dashboard, new-agent wizard, publish flow w/ live progress, settings), org admin, reviewer UI (finding overlays, invisible-char visualization, capability diff), platform staff console.
- Server-side sanitized markdown only (goldmark+bluemonday endpoint), CSP per §10.3, image proxy.
- Search UI on Postgres FTS facets (§10.4).

Acceptance: Playwright five §2.3 flows; XSS corpus rendered safe; Lighthouse a11y ≥ 90 public pages.

**Status: ⏳ not started**

---

## WG-J — Enterprise (M6, effort L)

**Plan refs:** §12.4 SSO, §12.5 SCIM, §9.3 webhooks, domain verification, audit export, org policy editor API.
**Depends on:** WG-B. Parallel with WG-C..WG-H.

Scope:
- SAML 2.0 SP (signed assertions, audience/recipient/timestamp, replay cache, clock skew ±90s) + OIDC RP (code+PKCE, issuer pinning) per org; JIT provisioning with domain-verified auto-link only; enforced SSO session tags + org-bound PATs.
- SCIM 2.0 subset (Users, Groups→teams); deactivate revokes org PATs + sessions <60s.
- Domain verification (DNS TXT); org policy PUT/GET vs schema; audit export async → NDJSON; webhooks (HMAC, SSRF guard per §9.3, retries).
- CI test-IdP suite (containerized SAML IdP + scripted OIDC provider).

Acceptance: M6 criteria — SSO test suite green incl. replay/audience negatives; SCIM deactivate <60s test; webhook SSRF guard tests; manual Okta+Entra checklist doc.

**Status: ⏳ not started**

---

## WG-K — AWS Infra (M7, effort L)

**Plan refs:** §13 complete, §16 observability, D-17, D-18, D-19.
**Depends on:** WG-A (design), production cutover needs WG-H.

Scope:
- Terraform module tree §13.7 (network, ecs-service, rds, efs, s3-suite, cloudfront, waf, observability, kms), envs dev/staging/prod; OIDC deploy roles; no IAM users.
- Service inventory §13.3 incl. sandbox/judge task profiles (no-egress SGs); data services §13.4; edge/WAF §13.5 incl. git-host tuning; backups §13.6.
- ADOT/OTel wiring, dashboards, alerts (§16.2–16.3); deploy pipeline with migrations + prod approval.

Acceptance: staging soak — conformance + e2e + k6 baselines green on real infra; `terraform plan` idempotent in CI; restore drill executed (human).

**Status: ⏳ not started**

---

## WG-L — Launch Hardening (M8, effort M)

**Plan refs:** §18.2 M8, §8.7 abuse intake, §12.7 GDPR, §14 OSS hygiene, §16.4 runbooks.
**Depends on:** everything on the critical path.

Scope:
- SECURITY.md + coordinated disclosure; abuse reporting endpoint + T&S console; quarantine mass-incident runbook; status page; CONTRIBUTING/DCO/release-please/signed releases + SBOM; GDPR deletion flow (tombstone, namespace chooser); seed content (10–20 first-party agents — needs Q10); pen test + fixes (human).

Acceptance: M8 criteria incl. fresh-machine self-host quickstart < 15 min; runbooks reviewed (human).

**Status: ⏳ not started**

---

## Open questions gating note (§20)

Nothing built so far is gated on Q1–Q10. Placeholder discipline (§0.8) is observed throughout: module `github.com/PLACEHOLDER_ORG/agentry`, binaries `agentryd`/`agentry`, env prefix `AGENTRY_`, config `agentry.yaml`. Q1 (name) blocks public repo creation only; Q2 (license) blocks first public release; Q3/Q4 land at WG-H config; Q5/Q6 launch config; Q7 none; Q8 WG-K tfvars; Q9 WG-I edge; Q10 WG-L.
