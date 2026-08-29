# Agentry — Continuation Brief

**For:** the next builder agent (fresh context) picking up this build.
**Written:** 2026-08-27; updated 2026-08-28 (session 2: web authed surface + T&S console + release-please); **updated 2026-08-29** after an independent audit and two waves of remediation branches.
**Repo:** `/Users/chrisdupres/Documents/ClaudeWorkspace/agentry` (git, clean tree, no remote).

## What changed on 2026-08-29 — read this first

An **independent audit** compared the shipped code against PLAN.md. It found two distinct problems, and both matter to how you should read the rest of this file.

**1. Real defects.** Fixed across three wave-1 branches, all merged:

- `fix/gitsrv` — `git archive` export-ignore neutralization proven at startup (DEV-017), enforced-SSO gating on git writes (DEV-018), per-repo semaphore, push-bookkeeping correctness.
- `fix/pipeline-core` — **blocked versions were serving 200s on download**, making the handler's 410 branch dead code (DEV-014); quarantine had no re-review exit (DEV-015); rescan sweeps had to be triggered by hand and now fire on ruleset registration; the §8.6 policy knobs `blockedCapabilities` / `allowedLicenses` / `requireEvals` were **stored and then consulted by nobody**; the 2FA-before-public-publish gate (DEV-016); review-decision atomicity; upload hardening; the S0/pipeline-error finding is now persisted.
- `fix/api-enterprise` — social OIDC login (DEV-019), SP-initiated SAML + `/sso/{org}`, audit NDJSON stream + retention + `GET /platform/audit` (DEV-020), SCIM PUT semantics, GDPR explicit disposition + transfer, stars/stats/activity/tags/ping/ruleset-release endpoints, the §9.1 conventions (Idempotency-Key, `RateLimit-*`, `Link` pagination, search facets — DEV-021), `review:act` scope enforcement, `attestationUrl` / `verdictReason` / `finishedAt` on reports.

Wave 2 is landing alongside: `fix/w2-web` (CSP nonces + hydration, light theme, agent-settings page, stars/facets/sessions UI), `fix/w2-cli` (install-time signature verification, capability diff, rules update, sessions endpoints), `fix/w2-scanner-depth` (S9 content diff, S8 name signals, EXIF, S7 lockfiles, five incident-corpus fixtures, `make sync-rules` + its CI drift check, k6 and seed tooling), `fix/w2-platform-seams` (OTel/Prometheus, entitlements, SMTP notifier, S3 and KMS backends, git-capable image, `all`-role worker, ranking), `fix/w2-docs` (this file and the register).

**2. The tracking documents were overclaiming.** This is the part to internalize. Roughly nineteen departures from PLAN.md had never been recorded in DEVIATIONS.md, which §0.5 makes mandatory; three recorded deviations asserted things that were not true; and this file, README.md and WORKGROUPS.md each carried statements that had been correct once and were never revised. Specifically, **the "§4.2 is fully done" claim below was wrong** — the reviewer UI and the org-admin surface shipped, but the §10.1 agent-settings page and the sessions view did not, and nobody noticed because the line said "ALL DONE". The backfill is `DEVIATIONS.md` DEV-031…DEV-049, plus dated errata under DEV-005, DEV-006 and DEV-011.

**Read DEV-033 first** if you touch authorization: "a single `authz.Check` chokepoint" is actually three regimes, and twelve routes — most of the trust & safety surface — are excluded from the §17.4 matrix test. It is the highest-value open item in the register.

**Design note (unchanged):** the entire authed web surface is server components + plain HTML forms → Next route handlers → API, session in httpOnly cookies, zero client-side auth JS (one small `Refresher` component for live progress). See DEV-012 before changing it.

---

## 1. Read these first, in this order

Do **not** read PLAN.md end-to-end (it is ~44k tokens). Read targeted sections.

| Order | File | Why / how much |
|---|---|---|
| 1 | **this file** | current state, what's left |
| 2 | `WORKGROUPS.md` | the twelve workgroups (WG-A…WG-L) with per-WG status, what landed, what was deferred; plus a **Post-audit remediation** section naming each fix branch. Statuses were re-verified against the code on 2026-08-29 — treat anything not revised then with the suspicion this file earned. |
| 3 | `DEVIATIONS.md` | **38 recorded deviations** (DEV-001…021 and DEV-031…049; 003/004 were never issued and the 022…030 block belongs to the wave-2 branches). PLAN.md §0.5 makes PLAN immutable; deviations go here. Read before questioning any design choice — and note the "Post-audit backfill" divider, after which entries are recorded after the fact rather than at the time. |
| 4 | `PLAN.md` **§0** (builder contract) + **§18.2** (milestone table w/ acceptance criteria) + **§20** (open questions) + **§21** (decision log index) | the contract and the map. ~3k tokens total. |
| 5 | PLAN.md sections **on demand only** | §5 manifest, §6 git, §7 state machine, §8 security pipeline, §9 API, §10 web, §11 CLI, §12 identity/enterprise, §13 AWS, §17 testing, §19 quotas. Grep for what you need. |
| 6 | `WORKGROUPS.md` — the "Bugs the build itself surfaced" list, and the "Post-audit remediation" section above it | the seven bugs the build caught itself, plus the ones the audit caught that it did not. Together they are the best available map of where the sharp edges are. |

**Golden rule from PLAN §0.1:** do not re-research settled decisions. If you disagree, record it in `DEVIATIONS.md` and proceed as specified.

---

## 2. Environment (matters — no Docker here)

```bash
export PATH=/opt/homebrew/bin:$PATH          # go 1.27, sqlc, golangci-lint, helm, tofu live here
./scripts/dev/pg.sh up                       # local Postgres 16 on :5477 (NOT docker — see DEV-001)
export AGENTRY_TEST_DATABASE_URL="$(./scripts/dev/pg.sh test-url)"
```

- **No container runtime** on this host (DEV-001). Integration tests use native Postgres via that DSN; CI uses GH Actions service containers. `deploy/compose/` is authored but unexecuted here.
- **Terraform is absent; OpenTofu 1.12.6 is installed** and is what validated the IaC (drop-in compatible).
- `make check` = generated-code drift + lint + test + build. `make generate` after touching `schemas/openapi.yaml` or `internal/store/queries/*.sql`.
- Regenerate explicitly:
  `go tool oapi-codegen -config schemas/codegen-server.yaml schemas/openapi.yaml && go tool oapi-codegen -config schemas/codegen-goclient.yaml schemas/openapi.yaml && sqlc generate`

---

## 3. Current state

Verify it yourself before trusting it — that is the lesson of the audit, and it takes two minutes (§7 below). Scale after wave 1, measured 2026-08-29: **~70k lines of Go, 261 test/fuzz functions, 11 migrations, 94 OpenAPI operations, 71 Terraform files, 18 web pages + 19 route handlers, 35 attack-corpus fixtures.**

### Milestones M0–M7 are done; M8 is partial

| M | What | Acceptance |
|---|---|---|
| M0 | Scaffolding, config, OpenAPI-first skeleton, migrations, CI | `scripts/acceptance/m0.sh` |
| M1 | Identity: argon2id auth, TOTP, sessions+CSRF, `agy_` PATs, RBAC chokepoint, audit | `m1.sh` — the authz matrix, **566 cases over 84 of 96 routes** as of 2026-08-29 (it prints its own count; earlier revisions of this file said 355 and WORKGROUPS said 179, and neither was updated as routes grew). The other 12 routes are `SelfAuthorized` and excluded — DEV-033 |
| M2 | Git hosting: smart HTTP v2, PAT auth, pre-receive policy hooks | `m2.sh` (21-case conformance vs real git CLI) |
| M3 | Registry: versions, §7 state machine, deterministic tar.zst, resolve/download + CLI | `m3.sh`, `m3-cli.sh` |
| M4 | **Security pipeline** S1–S10, gate, policy, review queue, DSSE signing | `m4.sh` (attack corpus 100% recall) |
| M5 | Web UI: SSR public pages + **authed/reviewer/org-admin/staff surface** (session 2), sanitized rendering, FTS search | `m5.sh` + `m8-console.sh` |
| M6 | Enterprise: SAML/OIDC, enforced SSO, SCIM, webhooks, audit export | `m6.sh` (12 criteria) |
| M7 | AWS: 71 .tf modules+envs, Helm chart, dashboards/alarms | `m7.sh` (real `validate` on 14 roots) |
| M8 | **PARTIAL** — T&S console + release-please done; remaining is pen test 🧍 + seed content (Q10) + operational. See §4.1 | `m8-console.sh` |

Two acceptance criteria are **adapted rather than met**, and both were being reported as passes: M5's Playwright flows and Lighthouse a11y ≥ 90 (DEV-031 — neither tool is in the repo; no score has ever been measured), and M2's `scripts/conformance/git.sh`, which CI never calls because the matrix runs inside `go test ./...` (DEV-047).

---

## 4. What remains — start here

### 4.1 M8 / WG-L (the only incomplete workgroup)

Already done: SECURITY.md, CONTRIBUTING.md (DCO + Releasing), README, `docs/trust.md`, `docs/self-hosting.md` (the <15-min quickstart — **documented, never executed**, see item 6 below), `docs/api-conventions.md`, `docs/ops/runbooks.md` (all 10 §16.4 procedures), release workflow (reproducible builds + cosign + SBOM, refuses to release if the corpus gate is red), release-please automation (DEV-013 — authored, not executed here), GDPR erasure flow (§12.7), abuse-report intake + T&S console UI, 4 seed example agents in `examples/`.

**Remaining:**

1. **External pen test** 🧍 — human-scheduled; §17.5 scope: authz, git endpoints, SSRF, sandbox escape. DEV-033 (the twelve routes outside the authz matrix) is the thing to point it at first.
2. **Status page** — operational setup (external SaaS). Not a code task.
3. **`security@` / `abuse@` addresses live** before launch (§16.5). Not a code task, and the `/trust` page and `docs/trust.md` both already tell people to use them.
4. **Seed content** — 4 examples exist; PLAN §18.2 wants 10–20. **Blocked on Q10** (which agents, who writes them).
5. **Okta + Entra ID manual interop checklist** 🧍 — the one human step §12.4 requires; the in-process test IdPs (DEV-009) deliberately do not claim to cover real-IdP interop.
6. **The `<15-min` fresh-machine self-host quickstart is still unverified.** `docs/self-hosting.md` documents it and the compose stack is structurally validated, but per **DEV-001** this host has no container runtime, so the Docker path in that document **has never been executed by anyone**. It needs one run on a Docker-equipped machine before M8 can be called done — this is the M8 acceptance criterion most likely to fail on first contact.

### 4.2 Deferred UI from WG-I (M5) — mostly done, and previously overclaimed

This section said "✅ ALL DONE" and it was not. What genuinely exists (commits `a365c43` + `a2da09b`), each backed by tested APIs:

- authed **dashboard** → `/dashboard`
- **publish flow** with live pipeline progress → `/{ns}/{name}/publish` + `.../versions/{v}/progress` (polled by a small `Refresher` client component)
- **org admin** → `/orgs/{org}/admin` (members/teams, SSO, SCIM, policy editor, audit browser + export, domain verification, webhooks)
- **reviewer detail UI** → `/review/{id}` (file tree + viewer with finding overlays + invisible-char visualization, capability diff vs previous version, decision panel) — the §10.1 "Reviewer" row
- beyond the original list: `/login`, `/settings` (profile/2FA/PATs), `/new` (new-agent wizard), `/staff`

**Still missing from §10.1:** the **agent-settings page** (grants, visibility, auto-publish toggle, webhooks) and the **sessions** view in user settings — both ship with wave 2's `fix/w2-web` branch. The **ruleset release console** stays deferred to v1.1 (the release tooling exists as scripts). The org **policy editor** is a JSON textarea, not the schema-validated form §10.1 asks for (DEV-040). And three §10.3 items were never built and are now recorded as DEV-049: the camo-style **image proxy** (so external images in READMEs do not display at all — the CSP refuses them, which is safe but silent), **server-side syntax highlighting**, and the **SSO connection test button**.

### 4.3 Deferred engineering (each has a working seam; none are blockers)

| Item | Where | Note |
|---|---|---|
| River queue driver | `internal/queue` | DEV-005. **Still deferred.** Interface + Postgres SKIP-LOCKED impl in place; add a `queue.Client` impl + River migrations. No enqueue-site changes. Wave 1 added the failure-path tests the entry had claimed — see its errata. |
| Real gitleaks / opengrep / osv-scanner exec adapters | `internal/scan` S2/S6/S7 | DEV-006. **Still deferred.** Native Go implementations detect everything the corpus exercises; add exec-adapters behind the existing interfaces. Note the errata on that entry: S7 parsed no lockfiles at all until wave 2's scanner-depth branch. |
| Bedrock / Anthropic judge providers | `internal/scan/judge.go` | DEV-007. **Still stubs** returning "not configured"; `none` + `static` work. **Blocked on Q3** (model/region). |
| S3 blob store and KMS signer against live AWS | `internal/registry/blobstore.go`, `internal/scan/signing.go` | Implementations land with wave 2's `fix/w2-platform-seams`; the config keys (`storage.kind: s3`, `signing.kind: kms`) and the Terraform that provisions the bucket and restricts `kms:Sign` already exist. **Neither has been exercised against a live AWS account** — no credentials here, and `m7.sh` validates Terraform without applying it. Treat the first real deployment as the integration test. |
| Device-code / browser `agentry login` | `cmd/agentry/cmd_login.go` | §11 lists "device-code or browser flow"; only PAT paste + `AGENTRY_TOKEN` are implemented, deferred with the web login UX. The file says so in its header comment. |
| git-history secrets pass (S2) | `internal/scan` | Archive scanning done; §8.3 also wants full-history scan for `source=git-tag`. |
| S8 IP-cluster mass-upload signal | `internal/scan/stages_s7_s9.go` | The account half of §8.3's ClawHavoc signal ships (`S8/publisher-velocity`: young account × publish velocity). The "**or IP cluster**" half does not — publisher IPs are not correlated across accounts, which is the axis the actual ClawHavoc incident turned on (1,184 skills, 12 accounts). Needs an IP to reach the scanner's `Input`. |
| gc worker job, per-IP git concurrency | `internal/gitsrv` | See WG-C; needs the queue (now available). |
| SSH git transport | — | **Q7** explicitly defers to v1.1. |
| 5 further webhook emit sites | `internal/api`, `internal/registry` | `agent.created`, `version.submitted`, `scan.completed`, `advisory.published`, `policy.updated`. The `SetEventSink` hook exists and fires for `version.*`. |
| Single Logout | `internal/auth/saml` | **Still deferred.** Documented §12.4 v1 limitation; sessions capped at 24h. |

Also deferred, and newly written down rather than assumed — see DEVIATIONS: the `post-receive` hook and the `repo.pushed` event (DEV-032), the force-push agent setting (DEV-045), the image proxy / syntax highlighting / SSO test button (DEV-049), the global advisory feed (DEV-038), and a `docs/` markdown pipeline for the `/docs` page (DEV-037).

### 4.4 Not in v1 (do not build — PLAN §8.9, §1.5)

Agent execution / "try it" playground (needs microVM sandbox), dynamic analysis, Rekor transparency log + TUF, GraphQL, multi-region, billing, embedding-similarity corpus matching, push-time secret protection.

---

## 5. Open questions blocking work (PLAN §20)

None of these block anything already built — placeholders are mechanical per PLAN §0.8.

| Q | Question | Blocks |
|---|---|---|
| **Q1** | Product name (replaces `agentry`) | public repo creation. Rename is mechanical: module `github.com/PLACEHOLDER_ORG/agentry`, binaries `agentryd`/`agentry`, env prefix `AGENTRY_`, config `agentry.yaml` |
| **Q2** | OSS license (planning default Apache-2.0) | first public release |
| **Q3** | SaaS judge provider + model | wiring the bedrock/anthropic providers |
| **Q4** | Launch policy strictness (e.g. all first-time publishers → human review) | policy seed only; engine supports it today |
| **Q5** | Personal-namespace public publishing at launch | launch config only |
| **Q6** | Beta shape | M8 |
| **Q7** | SSH git transport | nothing now (roadmap comms) |
| **Q8** | AWS region / data residency | `deploy/terraform/envs/*/terraform.tfvars` (default us-east-1) |
| **Q9** | Hosted docs site: in-app vs separate | M5 edge; currently in-app (`/docs`) |
| **Q10** | Which 10–20 seed agents, who writes them | M8 seed content |

---

## 6. Architecture orientation (so you don't have to rediscover it)

- **One Go binary, role-selected** (D-02): `agentryd api|git|worker|all`. `cmd/agentryd/main.go` → `buildHandler()` wires roles; `runWorker()` runs the queue.
- **Spec-first** (D-09): edit `schemas/openapi.yaml`, regenerate, then implement the method on `internal/api.Server`. **Every route needs a `RouteDecl` in `internal/api/authz_routes.go`** — a completeness test fails CI otherwise. Routes doing bespoke authz set `SelfAuthorized: true` and are covered by their own handler tests instead of the matrix.
- **Authorization is three regimes, not one** (DEV-033 — the plan says "a single `authz.Check` chokepoint" and that is not what exists): `internal/auth.Check` for org/self actions with enforced SSO folded in, `auth.CheckAgent` for per-agent roles and grants, and **12 routes marked `SelfAuthorized: true`** that authorize inside the handler and are skipped by the §17.4 matrix test — the review queue, finding verdicts, platform agent actions, ruleset release, platform audit, and abuse reporting. Every route still needs a `RouteDecl`; `SelfAuthorized` opts out of the enumeration, not the declaration. Do not add a thirteenth without reading DEV-033.
- **All SQL in `internal/store`** via sqlc (D-04); domain packages take `*storegen.Queries`. `store.WithTx` passes transaction-bound queries so an audit row commits with its mutation.
- **The pipeline is the product** (§8): `internal/scan`. `Orchestrator.Run` is pure over its `Input`; `Pipeline` does the DB + state-machine side. Fail-closed everywhere: any stage error becomes an `S0/pipeline-error` finding that forces human review — **no path to `published` skips the gate** (property-tested).
- **Two load-bearing test rules** (from CONTRIBUTING.md): every route declares authz; every scanner rule ships match **and** benign-lookalike fixtures. The attack corpus (`testdata/attack-corpus`, 35 fixtures) gates CI on 100% recall and zero benign false positives — a security doc *discussing* injection must stay publishable.
- **Rules bundle is duplicated by necessity**: canonical `/rules`, embedded copy `internal/scan/ruleset/rules/` (go:embed can't reach outside a package). `make sync-rules` + a CI drift check keep them identical. Note the DEV-011 errata: `scripts/dev/sync-rules.sh --check` existed from M4 but its only caller was `m4.sh`, which CI did not run — so the drift gate was claimed long before it was real, that gap is closed as of the wave-2 merge: `make sync-rules` / `make sync-rules-check` exist, and `make check` (and CI) run the drift check.

---

## 7. Suggested first moves for the next session

1. Verify the baseline yourself (2 min): `pg.sh up`, export the DSN, `go build ./... && go test ./... && golangci-lint run ./...`, then run `scripts/acceptance/m4.sh` (the differentiator) and `m6.sh`. Do this even though a previous session wrote "verified green" — that habit is what the audit was correcting.
2. Read **DEV-033** and decide whether to close it: either express queue-scoped review access as a first-class resource, or extend the matrix harness to drive the twelve `SelfAuthorized` routes. It is the largest remaining correctness gap and it sits on the trust & safety surface.
3. Then **DEV-036**'s second half: a text file over 1 MB is silently truncated for S3/S4/S5, which is an evasion window nobody is told about. Make it a finding.
4. Keep the discipline that produced the caught bugs: write the acceptance script *with* the feature, run it repeatedly (the GDPR handle-collision bug only appeared on the second run in the same minute), and prefer real dependencies over mocks.
5. Record any deviation in `DEVIATIONS.md` as `DEV-050`+ with what/why/impact **at the time you make it**, and update the relevant WG status in `WORKGROUPS.md`. The nineteen-entry backfill exists because that step kept getting skipped; a deviation recorded a week late is a deviation someone has already been misled by.

---

## 8. Honest posture note (§1.6.3 — keep this)

The product's language must stay **"scanned, N findings, signed"** — never "safe" or "verified secure". Static scanning reduces risk; it cannot prove an agent safe (T-02 is explicitly unresolvable). The capability manifest exists so consuming runtimes can enforce least privilege at run time; publication scanning is one layer of defense in depth. The shipped scanners are good but not identical to the tools §8.3 names (DEV-006) — don't let docs or UI overclaim.

The audit made the scope of that rule clearer than it had been: it applies to **the engineering documents too**, not only to product copy. "All §10.1 UI rows are now built", "an automated axe-core a11y pass", "CI fails if it drifts", "the §4.2 list is fully done" — each was written in good faith and each was false, and each one made the next reader's picture of the system slightly wrong. Prefer "not built", "not measured", "not verified" to a claim that will age into a lie. `docs/trust.md` is the reference for how this reads when it is done properly.
