# Agentry — Workgroup Breakdown

Derived from [PLAN.md](PLAN.md) §18 (milestones) and §18.3 (ordering/parallelization). Each workgroup (WG) is an independently assignable unit of work with explicit dependencies and acceptance criteria. Statuses are maintained here as the build proceeds.

## Status at a glance

| WG | Milestone | Status | Acceptance |
|---|---|---|---|
| A — Foundation | M0 | ✅ complete | `scripts/acceptance/m0.sh` |
| B — Identity & access | M1 | ✅ complete | `scripts/acceptance/m1.sh` (566-case authz matrix) |
| C — Git hosting | M2 | ✅ core complete | `scripts/acceptance/m2.sh` (21-case conformance) |
| D — Manifest | M3 | ✅ complete | 163 subtests + fuzz |
| E — Registry core | M3 | ✅ core complete | `scripts/acceptance/m3.sh` |
| F — CLI | M3 | ✅ core complete | `scripts/acceptance/m3-cli.sh` |
| G — Rules engine | M4 seed | ✅ complete | fixture runner + corpus |
| H — Security pipeline | M4 | ✅ core complete | `scripts/acceptance/m4.sh` (attack-corpus gate) |
| I — Web UI | M5 | ✅ public + authed surface | `m5.sh` (9 live SSR flows) + `m8-console.sh` (signed-in) |
| J — Enterprise SSO/SCIM | M6 | ✅ complete | `scripts/acceptance/m6.sh` (12 criteria) |
| K — AWS infra | M7 | ✅ complete | `scripts/acceptance/m7.sh` (71 .tf validate for real) |
| L — Launch hardening | M8 | 🟡 partial | docs + GDPR + abuse intake + T&S console + release-please done; pen test 🧍 + seed content (Q10) remain |

Bugs the build itself surfaced and fixed (each with a regression test):

- **S5 false positive** — "drafts the document in your team's format" scored as destructive-actions, sending a benign agent to review. Pattern now requires a destructive operation on a named target.
- **S4 precision** (DEV-010) — security documentation that *catalogues* attacks was unpublishable; the shipped `injection-defense` example is now a corpus fixture that must stay clean.
- **CLI fail-open** (DEV-011) — `agentry validate` printed PASSED after silently skipping S4 when the rule bundle failed to load. Bundle is now embedded; a load failure exits non-zero.
- **Scope escalation** — a `repo:write`-only PAT could create `v*` tags (i.e. publish); tag creation now goes through the chokepoint with scopes.
- **Silent rescan failure** — the sweep logged unreadable archives and returned nil, so a totally failed run looked clean. It now counts and reports.
- **Fragile shared-DB test selection** (M8 console work) — `TestReviewApprovalFlow` grabbed `queue[len-1]` of the platform review queue, but that queue is shared across the whole test run (one migrated DB, no per-test truncation). New same-named review items from the console tests made it grab another author's item, so the author-self-approve assertion started passing a 204 instead of 403. Now selects its own item by namespace (the pattern the new `setupReviewItem` helper already used). A latent ordering dependency, surfaced the moment a second test wrote to the same queue.
- **Every browser form post rejected** (2026-08-31, found by a human trying to sign in to the dev stack) — `Referrer-Policy: no-referrer` (`web/next.config.mjs`) makes a browser serialize the Origin of every non-CORS POST as the string `null` (Fetch, "append a request `Origin` header"). `sameOrigin()` threw on `new URL("null")` and returned false, so **the entire authed forms surface — login, signup, publish, settings, org admin, review decisions — 403'd `cross-origin form post rejected` in Chrome and Firefox**, while curl (which applies no referrer policy) passed. Nothing caught it because no browser has ever driven this app: DEV-031 records that the M5 Playwright flows were never built, so every web test is curl- or Go-level. `sameOrigin()` now prefers `Sec-Fetch-Site` — a forbidden header name, unforgeable by page script and independent of the referrer policy — and keeps the Origin/Host comparison as the fallback for clients that omit it. Regression test: `web/lib/__tests__/forms.test.ts`. The deeper lesson is DEV-031's, not this bug's: a design whose entire mutation surface is plain HTML forms cannot be verified by a client that does not implement browser semantics.
- **Web login cookie clobber** (M8 console work) — the login route handler appended the session via a raw `Set-Cookie` header *and* set the CSRF cookie via Next's `cookies` API; the two mechanisms don't compose and only the CSRF cookie survived, so every web sign-in silently produced a session-less browser. Caught by the acceptance script asserting both cookies land. Fixed by setting both through the one `cookies` API with the API's mirrored attributes.

## Post-audit remediation (2026-08-29)

An independent audit compared the shipped code against PLAN.md and found two
things: real defects in the pipeline, git and API layers, and tracking
documents (this file included) claiming more than the code did. The work was
split across two waves of branches. Wave 1 is merged into the line these
statuses describe; wave 2 lands alongside it.

**Wave 1 — merged.**

| Branch | What it fixed |
|---|---|
| `fix/gitsrv` | `git archive` export-ignore neutralization proven at startup (DEV-017), enforced-SSO gating on git writes (DEV-018), per-repo semaphore, push-bookkeeping correctness |
| `fix/pipeline-core` | blocked versions now actually 410 (they had been serving 200s — DEV-014), a quarantine re-review exit (DEV-015), rescan sweeps triggered by ruleset registration instead of by hand, the §8.6 policy knobs (`blockedCapabilities`, `allowedLicenses`, `requireEvals`) enforced rather than merely stored, the 2FA-before-public-publish gate (DEV-016), review-decision atomicity, upload hardening, and the S0/pipeline-error finding persisted |
| `fix/api-enterprise` | social OIDC login (DEV-019), SP-initiated SAML + `/sso/{org}`, the audit NDJSON stream + retention + `GET /platform/audit` (DEV-020), SCIM PUT semantics, GDPR explicit disposition and transfer, stars/stats/activity/tags/ping/ruleset-release endpoints, the §9.1 conventions — Idempotency-Key, `RateLimit-*`, `Link` pagination, search facets (DEV-021) — `review:act` scope enforcement, and `attestationUrl` / `verdictReason` / `finishedAt` on reports |

**Wave 2 — in flight.** `fix/w2-web` (CSP nonces + hydration, light theme,
agent-settings page, stars/facets/sessions UI); `fix/w2-cli` (install-time
signature verification, capability diff, rules update, sessions endpoints);
`fix/w2-scanner-depth` (S9 content diff, S8 name signals, EXIF, S7 lockfiles,
five incident-corpus fixtures, the `make sync-rules` CI drift wiring, k6 and
seed tooling); `fix/w2-platform-seams` (OTel/Prometheus, entitlements, SMTP
notifier, S3 and KMS backends, a git-capable image, the `all`-role worker,
ranking); `fix/w2-docs` (this file, README, CONTINUE, `docs/`, and the
DEV-031..049 backfill).

Statuses below were revised in that last branch where they had drifted from
the code — the WG-B matrix count, the WG-I acceptance description and
deferred list, and the WG-L §10.1 coverage claim.

---

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

**Status: ✅ complete** — identity schema (00002: handles/users/orgs/memberships/teams/pats/sessions/audit partitioned+immutability trigger), register/login/TOTP (argon2id, sealed secrets), server-side sessions + CSRF, PATs (`agy_`, sha256-at-rest, 8 scopes), authz chokepoint + per-route declarations w/ completeness gate, audit writer + code-registered catalog, configurable §19 rate limits, org/member/team endpoints. Acceptance green (`scripts/acceptance/m1.sh`): authz matrix, PAT lifecycle e2e, audit coverage incl. append-only trigger, auth/TOTP/CSRF flows. Deferred to later WGs: social OIDC login (M6 SSO work), session-listing UI endpoint, GDPR delete (M8).

The matrix is generated from the route table, so its size tracks the API surface rather than being a fixed figure: **566 cases over 84 of the 96 declared routes** as of 2026-08-29 (it prints its own count — `authz matrix: N cases executed`). Earlier revisions of this file said 179 and CONTINUE.md said 355; both were true when written and neither was updated as routes were added. The twelve routes the matrix does **not** enumerate are the `SelfAuthorized: true` ones, covered by handler tests instead — see DEV-033, which treats that exclusion as the most important open item in the register.

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

**Status: ✅ core complete** — smart HTTP v2 (info/refs, upload-pack, receive-pack, gzip bodies, protocol v2, shallow+partial clone), UUID-sharded bare repos w/ lazy init (git role owns storage per §13.3), PAT-only Basic auth + per-op §6.4 authz w/ private-repo existence privacy, pre-receive policy hook (`agentryd hook pre-receive`: immutable v* tags, publish-permission gating incl. PAT scope, force-push/default-branch-delete denial, nested-.git + oversize-blob rejection, quota), post-receive bookkeeping (size, audit, PostReceive hook for M3 tag→submit), agents+repos+grants schema and full agents/grants API. Conformance: 21-case matrix green (`scripts/acceptance/m2.sh`); also caught+fixed a real bug where a repo:write-only PAT could create v* tags. Deferred: gc worker job (needs M4 queue), per-IP git concurrency limits (M7 WAF layer), agent delete endpoint (M3, needs never-published check).

Four departures from §6.2/§6.3 in the scope list above are recorded as **DEV-032**: there is no `post-receive` hook file (the bookkeeping runs in the HTTP handler after `receive-pack` exits), no `repo.pushed` queue event exists anywhere, hooks are installed as wrapper shell scripts rather than symlinks, and repos are initialized lazily on first git request. **DEV-045** covers the fifth: force-push to the default branch is a hardcoded deny — the "unless agent setting allows" setting §6.3 names does not exist. The 21-case matrix itself lives in `internal/gitsrv/conformance_test.go` and runs on every PR via `go test ./...`; `scripts/conformance/git.sh` is a wrapper CI never calls (DEV-047).

---

## WG-D — Manifest & Package Format (M3 part, effort M)

**Plan refs:** §5 complete (spec, V1–V8, capability vocabulary, channels), `pkg/manifest`.
**Depends on:** WG-A. Fully parallel with WG-B.

Scope:
- `pkg/manifest`: parse (YAML 1.2, closed schema), validate V1–V8, canonical JSON form, capability vocabulary types.
- `schemas/agent-manifest-1.schema.json` generated/kept in sync.
- Quota checks (§19) as pure functions; entrypoint rules per kind; SPDX license check for public publish.

Acceptance: table-driven tests over valid/invalid manifests incl. every V-rule; fuzz target for the parser (§17.5).

**Status: ✅ complete** — pkg/manifest (Parse strict-YAML closed schema, V1–V8 via Validate/ValidateInContext, capability vocabulary, canonical JSON, `**` globber, 60-id SPDX list) + schemas/agent-manifest-1.schema.json (draft 2020-12, additionalProperties:false). 28 test funcs / 163 subtests + FuzzParse (660k execs clean); §5.2 normative example validates clean end-to-end. Built by parallel workgroup agent; independently re-verified (build/test/lint) on the main line.

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

**Status: ✅ core complete** — agent_versions schema w/ DB-level immutability + never-delete triggers (§4.3), §7 state machine (SELECT FOR UPDATE single-writer, audited transitions, latest-published maintenance, edge property test incl. no-gate-skip), deterministic tar.zst archive builder (D-15, byte-reproducibility test) + hardened extractor, content-addressed LocalFS blob store (S3 impl → WG-K), submission for both sources (git-tag via MaterializeTag + §6.3 tag auto-publish on push; cli-upload w/ server re-pack + digest cross-check per §6.5), §9.4 resolve (semver ranges, channels, yank-pin semantics) + download (stream w/ immutable caching, install counting, 410 blocked / 409 quarantined), dev-mode auto-approve pipeline stub. Acceptance green (`scripts/acceptance/m3.sh`): 3 kinds × 2 sources round-trip, reproducibility, yank semantics, matrix w/ 7 new version routes.

---

## WG-F — CLI v0 (M3 part, effort M)

**Plan refs:** §11, D-12, §8.3 local parity note.
**Depends on:** WG-D, WG-E (API), WG-G (validate subset).

Scope:
- cobra CLI: `init` (+ `--from` import wizards that never guess capabilities silently), `validate` (V-rules + S1/S3/S4 subset via `pkg/rules`), `login` (PAT in OS keychain), `publish` (tag + upload modes; streams pipeline progress), `install` (resolve→verify digest+signature→capability diff→export claude-skill/mcp/agents-md), `verify`, `search`, `info`, `yank`.
- Multi-registry config `~/.config/agentry/config.yaml`; TOFU key pinning.

Acceptance: CLI e2e against dev stack covering §18.2 M3 round-trip; exporters produce valid target formats (fixture-verified).

**Status: ✅ core complete** — all §11 commands: init (3 kinds, scaffolds validate clean), validate (D-12 parity — V-rules + S3/S4 via pkg/rules, --strict for warnings), login (PAT→OS keychain w/ chmod-600 file fallback, AGENTRY_TOKEN override), publish (tag + upload modes, polls pipeline to verdict, non-zero on rejected), install (resolve→digest verify→capability summary→typed confirm on egress/exec→all three §5.6 exporters), verify, search, info, yank. Multi-registry config. Unit tests for exporters (frontmatter injection, .mcp.json merge idempotency, AGENTS.md section upsert, arg re-rooting), config round-trip+perms, capability rendering. E2E `scripts/acceptance/m3-cli.sh` green: full register→PAT→init→validate→publish→install→verify→yank round-trip against a live server. Deferred: --from import wizards, embedded rule bundle in release builds, SSE progress (polls), DSSE verify + TOFU pinning (wired next now that M4 signing exists), capability diff vs installed version.

---

## WG-G — Rules Engine + Rulesets (M4 seed, effort M)

**Plan refs:** §8.3 S3/S4 definitions, `pkg/rules`, `/rules` data layout, §17.3 corpus.
**Depends on:** WG-A. Fully parallel with WG-B..WG-E.

Scope:
- `pkg/rules`: S3 detectors (zero-width, bidi/Trojan Source, Unicode tag block, confusables/mixed-script, PUA, HTML comments, CSS-hidden, data-URI, base64/hex runs entropy-gated, trailing whitespace, NFC deltas) + S4 signature engine (versioned YAML rules: id, severity, confidence, refs, match+non-match fixtures).
- `/rules` initial ruleset content: instruction-override, exfiltration, tool-coercion, credential-harvest, persistence, obfuscation families.
- Fixture runner: every rule's fixtures are tests; start `testdata/attack-corpus/` with one fixture per S3 class and S4 family + benign lookalikes.

Acceptance: corpus recall 100% on expected findings; benign lookalikes pass; rule bundle digest computed reproducibly.

**Status: ✅ complete** — pkg/rules: 11 S3 detectors (zero-width, bidi, tag-block, PUA, confusables/mixed-script, HTML-comment w/ S4 escalation, CSS-hidden, data-URI, entropy-gated base64/hex, trailing-whitespace, NFC-delta), S4 YAML signature engine (per-line matching, same-line notPattern suppression, (?im) patterns), versioned bundle loader w/ reproducible sha256 digest + fixture enforcement (loader rejects rules lacking match+nonMatch fixtures). rules/ v0.1.0: 12 rules across 6 families. testdata/attack-corpus: 17 attack/benign fixture pairs w/ expected.yaml, 100% recall + benign precision in CI. Built by parallel workgroup agent (survived one session-limit interruption, resumed); independently re-verified on the main line.

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

**Status: ✅ core complete** — commit f1d6185. Orchestrator DAG (S1 → S2/S3-S4/S5/S6/S7/S8 in parallel → S9 → S10) with per-stage timeouts, panic isolation, a 30-min scan cap, and fail-closed behaviour (any stage error becomes S0/pipeline-error forcing review, §7). All ten stages implemented; gate §8.5 + tighten-only policy engine §8.6; review queue + finding verdicts with platform-staff/org-reviewer gating and author-cannot-self-approve; DSSE/in-toto ECDSA P-256 signing (D-16) + well-known keys + offline verify; hardened+fuzzed extractor; rescan/quarantine/advisories §8.7; Postgres SKIP-LOCKED queue behind queue.Client + worker role. Acceptance: `scripts/acceptance/m4.sh` (7 criteria incl. the attack-corpus gate at 100% recall / no benign regressions). Deferred: DEV-005 (River), DEV-006 (gitleaks/opengrep/osv native fallbacks), DEV-007 (bedrock/anthropic judge stubs).

---

## WG-I — Web UI (M5, effort L)

**Plan refs:** §10 complete, D-08, D-11, §17.1 Playwright flows.
**Depends on:** WG-A (contract); pages grow with WG-B/E/H. Reviewer UI needs WG-H.

Scope:
- Next.js SSR app: public pages (home, search, agent page §10.2, version/report page, namespace, trust, advisories, docs), authed (dashboard, new-agent wizard, publish flow w/ live progress, settings), org admin, reviewer UI (finding overlays, invisible-char visualization, capability diff), platform staff console.
- Server-side sanitized markdown only (goldmark+bluemonday endpoint), CSP per §10.3, image proxy.
- Search UI on Postgres FTS facets (§10.4).

Acceptance: Playwright five §2.3 flows; XSS corpus rendered safe; Lighthouse a11y ≥ 90 public pages. **Both tools were substituted — see DEV-031.**

**Status: ✅ core complete** — commit 7268999 (+ 64974ef advisories page, cb89938 a11y automation). Next.js 16 App Router SSR: home, search w/ facets, agent page (capability badges + security report card + install snippet), version page (report + provenance), namespace, trust, advisories, docs. Server-side sanitized rendering only (goldmark+bluemonday in internal/render; the browser never parses user markdown), CSP without inline script, invisible-Unicode rendered as visible placeholders (§10.3 GlassWorm lesson). Postgres FTS search (§10.4). Acceptance: `scripts/acceptance/m5.sh` — nine live SSR flows driven with `curl`, plus a structural accessibility pass (`scripts/dev/a11y-check.py`: landmarks, heading order and `<h1>` uniqueness, `lang`, accessible names on links and buttons, form-control labels, image `alt`) which caught and fixed a duplicate-h1. **There is no axe-core and no Playwright in this repository, and no Lighthouse score has ever been measured** — earlier revisions of this line said "an automated axe-core a11y pass", which named a tool that was never here. DEV-031 records the substitution and what it does not cover.

Authed surface (commits ee29afd + a365c43): web sign-in (API session cookie mirrored + CSRF cookie, both httpOnly; mutations are plain HTML forms → web route handlers → API, zero client JS under the strict CSP), authed dashboard, review queue (platform + org), the §10.1 **reviewer detail UI** (findings w/ excerpt highlighting + verdict forms, archive file viewer w/ line-level finding overlays and invisible-Unicode revelation, capability diff vs previous published version, manifest, decision panel), backed by new API surface (enriched review bundle, review-archive file endpoints). Acceptance: `scripts/acceptance/m8-console.sh` (live sign-in through the web tier, SSR checks incl. U+200B revelation, reject→rejected, authz refusals, cross-origin 403, authed-page a11y). Also shipped in the same pass: publish flow + live progress, org admin (members/teams/policy/SSO/SCIM/domains/webhooks/audit), user settings (profile/2FA/PATs), new-agent wizard — this line previously still listed those four as deferred after they had landed.

**Still not built (§10 gaps, now recorded):** the §10.1 agent-settings page (grants, visibility, auto-publish toggle, webhooks) — ships with wave 2's web branch; the "sessions" half of user settings — same branch; the platform-staff **ruleset release console** (deferred to v1.1; the release tooling exists as scripts); and three §10.3/§10.1 items recorded as DEV-049 — the camo-style image proxy (external images are consequently not displayed at all; the CSP is what makes that safe), server-side syntax highlighting, and the SSO connection test button. The org policy editor is a JSON textarea rather than the schema-validated form §10.1 specifies (DEV-040), and `style-src` carries `'unsafe-inline'` for Tailwind (DEV-041, script nonces added by the wave-2 web branch).

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

**Status: ✅ complete** — commit fa54dc9. SAML 2.0 SP (crewjam/saml, DEV-008) + replay cache; OIDC RP (coreos/go-oidc, PKCE, issuer pinning); per-org connection CRUD, metadata/ACS/start/callback; JIT provisioning gated on domain-verified email (T-12); enforced SSO folded into the single authorize() chokepoint (session sso_tags freshness OR org-bound PAT, 90-day cap, mintable only from an SSO-fresh session); SCIM 2.0 Users+Groups→teams with deactivate revoking org-bound PATs and sessions in-request; domain TXT verification behind a resolver interface; webhooks with HMAC + a real SSRF guard (per-attempt re-resolution, all resolved IPs must be public unicast, dials the verified IP to defeat DNS rebinding, no redirects); async audit export to NDJSON. Acceptance: `scripts/acceptance/m6.sh` (12 criteria incl. every SAML negative). Deferred: Single Logout (documented §12.4 limitation), manual Okta/Entra checklist 🧍, five further webhook emit sites.

---

## WG-K — AWS Infra (M7, effort L)

**Plan refs:** §13 complete, §16 observability, D-17, D-18, D-19.
**Depends on:** WG-A (design), production cutover needs WG-H.

Scope:
- Terraform module tree §13.7 (network, ecs-service, rds, efs, s3-suite, cloudfront, waf, observability, kms), envs dev/staging/prod; OIDC deploy roles; no IAM users.
- Service inventory §13.3 incl. sandbox/judge task profiles (no-egress SGs); data services §13.4; edge/WAF §13.5 incl. git-host tuning; backups §13.6.
- ADOT/OTel wiring, dashboards, alerts (§16.2–16.3); deploy pipeline with migrations + prod approval.

Acceptance: staging soak — conformance + e2e + k6 baselines green on real infra; `terraform plan` idempotent in CI; restore drill executed (human).

**Status: ✅ complete (IaC authored + validated; apply needs an AWS account)** — 71 .tf files in the exact §13.7 layout: 10 modules (network w/ 3-AZ + VPC endpoints, ecs-service, rds, elasticache, efs, s3-suite, cloudfront, waf, kms, observability), envs dev/staging/prod, global accounts/dns/ecr w/ GitHub OIDC deploy role (no IAM users). The 6 §13.3 services are 6 instantiations of one ecs-service module. Security-critical bits verified by hand: worker-sandbox and worker-judge carry `allow_all_egress=false` so no 0.0.0.0/0 rule exists and their only routes are the scoped ones (§8.2); `kms:Sign` is restricted to the single worker-core task role by both IAM policy and a key-policy condition (D-16, T-09); the git-host WAF downgrades body-inspection rules to COUNT because they false-positive on packfiles (§13.5). Helm chart for the §2.4 HA shape (api/git/worker/web + shared RWX PVC + HPAs). Acceptance green: `terraform fmt -check` + `init -backend=false && validate` on all 14 roots against the real AWS provider (via OpenTofu, terraform-compatible), plus helm lint + template. Real validation caught two genuine bugs in the module code. Open as tfvars: Q8 region, Q3 judge model, domains/cert ARNs, state bucket names. `terraform apply` needs an AWS account (out of scope here).

---

## WG-L — Launch Hardening (M8, effort M)

**Plan refs:** §18.2 M8, §8.7 abuse intake, §12.7 GDPR, §14 OSS hygiene, §16.4 runbooks.
**Depends on:** everything on the critical path.

Scope:
- SECURITY.md + coordinated disclosure; abuse reporting endpoint + T&S console; quarantine mass-incident runbook; status page; CONTRIBUTING/DCO/release-please/signed releases + SBOM; GDPR deletion flow (tombstone, namespace chooser); seed content (10–20 first-party agents — needs Q10); pen test + fixes (human).

Acceptance: M8 criteria incl. fresh-machine self-host quickstart < 15 min; runbooks reviewed (human).

**Status: 🟡 in progress** — done: SECURITY.md (coordinated disclosure, scope oriented at gate-bypass/scanner-escape/signing-forgery, honest non-vulnerability limitations), CONTRIBUTING.md (DCO, the two load-bearing rules: route authz declarations + scanner fixtures w/ benign lookalikes), README (front door + status), docs/self-hosting.md (<15-min quickstart, config, policy choices, operator responsibilities), docs/ops/runbooks.md (all 10 §16.4 procedures incl. the ClawHavoc-scale quarantine wave and signing-key rotation), docs/rfcs template, release workflow (reproducible cross-platform builds, keyless cosign signatures, SPDX SBOM, refuses to release if the attack-corpus gate is red), GDPR erasure endpoint + flow test (§12.7: PII purged, credentials revoked, published versions yanked-not-deleted with digests intact, tombstone leak-free), abuse-report intake + staff triage list (§8.7). T&S console (commits ee29afd + a365c43): staff `/staff` console — platform-queue summary, abuse-report triage (state tabs, resolution required, audited `abuse.triage`), quarantine/block/reinstate enforcement forms; plus the abuse triage API and state-filtered listing.

release-please (commit b818fef, DEV-013): `.github/workflows/release-please.yaml` + config + manifest + seeded CHANGELOG; conventional-commit-driven release PR → CHANGELOG → `vX.Y.Z` tag → the existing `release.yaml` builds/signs/publishes. Authored + syntax-validated, not executed here (needs the GitHub API). CONTRIBUTING gained a Releasing section documenting the `RELEASE_PLEASE_TOKEN` handoff gotcha.

Remaining M8: status page setup (operational/external SaaS), external pen test 🧍, seed content (10–20 first-party agents, blocked on Q10), `security@`/`abuse@` addresses live before launch.

**§10.1 UI coverage, accurately.** A previous revision of this line said "All §10.1 UI rows are now built"; that was not true. Built: every Public row, every Reviewer row, the Org-admin row (with the policy editor as a JSON textarea rather than a form — DEV-040), the platform-staff T&S queue and quarantine console, and all of the Authed row except agent settings. **Not built:** the agent-settings page and the sessions view (both ship with wave 2's web branch), and the platform-staff **ruleset release console**, which stays deferred to v1.1 — the release tooling exists as scripts. The public docs page is hand-authored TSX rather than a rendering of the repository's `docs/` tree (DEV-037), and `/advisories` is an explainer page rather than the advisory feed the row implies (DEV-038).

---

## Open questions gating note (§20)

Nothing built so far is gated on Q1–Q10. Placeholder discipline (§0.8) is observed throughout: module `github.com/PLACEHOLDER_ORG/agentry`, binaries `agentryd`/`agentry`, env prefix `AGENTRY_`, config `agentry.yaml`. Q1 (name) blocks public repo creation only; Q2 (license) blocks first public release; Q3/Q4 land at WG-H config; Q5/Q6 launch config; Q7 none; Q8 WG-K tfvars; Q9 WG-I edge; Q10 WG-L.
