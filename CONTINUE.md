# Agentry — Continuation Brief

**For:** the next builder agent (fresh context) picking up this build.
**Written:** 2026-08-27, at the end of the first build session.
**Repo:** `/Users/chrisdupres/Documents/ClaudeWorkspace/agentry` (git, 20 commits, clean tree, no remote).

---

## 1. Read these first, in this order

Do **not** read PLAN.md end-to-end (it is ~44k tokens). Read targeted sections.

| Order | File | Why / how much |
|---|---|---|
| 1 | **this file** | current state, what's left |
| 2 | `WORKGROUPS.md` | the twelve workgroups (WG-A…WG-L) with per-WG status, what landed, what was deferred. **Statuses are accurate as of this commit.** |
| 3 | `DEVIATIONS.md` | 9 recorded deviations (DEV-001…011). PLAN.md §0.5 makes PLAN immutable; deviations go here. Read before questioning any design choice. |
| 4 | `PLAN.md` **§0** (builder contract) + **§18.2** (milestone table w/ acceptance criteria) + **§20** (open questions) + **§21** (decision log index) | the contract and the map. ~3k tokens total. |
| 5 | PLAN.md sections **on demand only** | §5 manifest, §6 git, §7 state machine, §8 security pipeline, §9 API, §10 web, §11 CLI, §12 identity/enterprise, §13 AWS, §17 testing, §19 quotas. Grep for what you need. |
| 6 | `WORKGROUPS.md` — the "Bugs the build itself surfaced" list (~line 22) | the 8 real bugs this build caught and how — useful signal on where the sharp edges are. |

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

## 3. Current state: verified green

Last full verification (all from a clean tree):

```
go build ./...            OK
go test ./...             15/15 packages ok
golangci-lint run ./...   0 issues
9/9 acceptance scripts    m0 m1 m2 m3 m3-cli m4 m5 m6 m7 — all PASSED
```

Scale: **53k lines of Go** across 164 files, **165 test/fuzz functions**, 8 migrations, **79 OpenAPI operations**, 71 Terraform files, 8 web pages, 35 attack-corpus fixtures.

### Milestones M0–M7 are done; M8 is partial

| M | What | Acceptance |
|---|---|---|
| M0 | Scaffolding, config, OpenAPI-first skeleton, migrations, CI | `scripts/acceptance/m0.sh` |
| M1 | Identity: argon2id auth, TOTP, sessions+CSRF, `agy_` PATs, RBAC chokepoint, audit | `m1.sh` (355-case authz matrix) |
| M2 | Git hosting: smart HTTP v2, PAT auth, pre-receive policy hooks | `m2.sh` (21-case conformance vs real git CLI) |
| M3 | Registry: versions, §7 state machine, deterministic tar.zst, resolve/download + CLI | `m3.sh`, `m3-cli.sh` |
| M4 | **Security pipeline** S1–S10, gate, policy, review queue, DSSE signing | `m4.sh` (attack corpus 100% recall) |
| M5 | Web UI: SSR public pages, sanitized rendering, FTS search | `m5.sh` (incl. axe-core a11y) |
| M6 | Enterprise: SAML/OIDC, enforced SSO, SCIM, webhooks, audit export | `m6.sh` (12 criteria) |
| M7 | AWS: 71 .tf modules+envs, Helm chart, dashboards/alarms | `m7.sh` (real `validate` on 14 roots) |
| M8 | **PARTIAL** — see §4 below | — |

---

## 4. What remains — start here

### 4.1 M8 / WG-L (the only incomplete workgroup)

Already done: SECURITY.md, CONTRIBUTING.md (DCO), README, `docs/self-hosting.md` (<15-min quickstart), `docs/ops/runbooks.md` (all 10 §16.4 procedures), release workflow (reproducible builds + cosign + SBOM, refuses to release if the corpus gate is red), GDPR erasure flow (§12.7), abuse-report intake, 4 seed example agents in `examples/`.

**Remaining, in suggested order:**

1. **T&S console UI** — the API exists (`/platform/agents/{ns}/{name}/{action}`, `/review-queue?queue=platform`, abuse-report triage list); the *reviewer/staff web UI* is not built. This is the largest remaining piece and pairs with 4.2.
2. **`release-please` changelog automation** — workflow scaffolding exists; wire the changelog/version PR bot.
3. **Status page** — operational setup (external SaaS), plus `security@`/`abuse@` addresses live before launch (§16.5).
4. **Seed content** — 4 examples exist; PLAN §18.2 wants 10–20. **Blocked on Q10** (which agents, who writes them).
5. **External pen test** 🧍 — human-scheduled; §17.5 scope: authz, git endpoints, SSRF, sandbox escape.

### 4.2 Deferred UI from WG-I (M5) — API-complete, UI pending

All of these have working, tested APIs; only the pages are missing:
- authed **dashboard** (my agents, review items assigned to me, activity)
- **publish flow** with live pipeline progress (SSE or poll — CLI already polls)
- **org admin** (members/teams, SSO config, SCIM tokens, policy editor, audit browser, domain verification)
- **reviewer detail UI**: file tree + content viewer with finding overlays, invisible-char visualization, capability diff vs previous version, decision panel. (§10.1 "Reviewer" row — the highest-value remaining UI.)

### 4.3 Deferred engineering (each has a working seam; none are blockers)

| Item | Where | Note |
|---|---|---|
| River queue driver | `internal/queue` | DEV-005. Interface + Postgres SKIP-LOCKED impl in place; add a `queue.Client` impl + River migrations. No enqueue-site changes. |
| Real gitleaks / opengrep / osv-scanner | `internal/scan` S2/S6/S7 | DEV-006. Native Go fallbacks detect everything the corpus exercises; add exec-adapters behind the existing interfaces. |
| Bedrock / Anthropic judge providers | `internal/scan/judge.go` | DEV-007. `none` + `static` work; the two real providers return "not configured". **Blocked on Q3** (model/region). |
| S3 blob store | `internal/registry/blobstore.go` | `LocalFS` implements `BlobStore`; add an S3 impl (WG-K's tfvars already expose the bucket). |
| KMS signer | `internal/scan/signing.go` | `NewSigner` has a `kms` branch returning "not yet wired"; file signer works. Terraform already provisions the key + restricts `kms:Sign`. |
| git-history secrets pass (S2) | `internal/scan` | Archive scanning done; §8.3 also wants full-history scan for `source=git-tag`. |
| gc worker job, per-IP git concurrency | `internal/gitsrv` | DEV note in WG-C; needs the queue (now available). |
| SSH git transport | — | **Q7** explicitly defers to v1.1. |
| 5 further webhook emit sites | `internal/api`, `internal/registry` | `agent.created`, `version.submitted`, `scan.completed`, `advisory.published`, `policy.updated`. The `SetEventSink` hook exists and fires for `version.*`. |
| Single Logout | `internal/auth/saml` | Documented §12.4 v1 limitation; sessions capped at 24h. |

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
- **One authz chokepoint**: `internal/auth.Check` (org/self actions) and `CheckAgent` (per-agent roles). Enforced SSO is folded in there too. Never authorize inline in a handler.
- **All SQL in `internal/store`** via sqlc (D-04); domain packages take `*storegen.Queries`. `store.WithTx` passes transaction-bound queries so an audit row commits with its mutation.
- **The pipeline is the product** (§8): `internal/scan`. `Orchestrator.Run` is pure over its `Input`; `Pipeline` does the DB + state-machine side. Fail-closed everywhere: any stage error becomes an `S0/pipeline-error` finding that forces human review — **no path to `published` skips the gate** (property-tested).
- **Two load-bearing test rules** (from CONTRIBUTING.md): every route declares authz; every scanner rule ships match **and** benign-lookalike fixtures. The attack corpus (`testdata/attack-corpus`, 35 fixtures) gates CI on 100% recall and zero benign false positives — a security doc *discussing* injection must stay publishable.
- **Rules bundle is duplicated by necessity**: canonical `/rules`, embedded copy `internal/scan/ruleset/rules/` (go:embed can't reach outside a package). `make sync-rules` + a CI drift check keep them identical.

---

## 7. Suggested first moves for the next session

1. Verify the baseline yourself (2 min): `pg.sh up`, export the DSN, `go build ./... && go test ./... && golangci-lint run ./...`, then run `scripts/acceptance/m4.sh` (the differentiator) and `m6.sh`.
2. Pick up **§4.2 reviewer UI + §4.1 T&S console** together — one coherent chunk of work, highest remaining product value, and the APIs are already tested.
3. Keep the discipline that produced the 8 caught bugs: write the acceptance script *with* the feature, run it repeatedly (the GDPR handle-collision bug only appeared on the second run in the same minute), and prefer real dependencies over mocks.
4. Record any deviation in `DEVIATIONS.md` as `DEV-012`+ with what/why/impact, and update the relevant WG status in `WORKGROUPS.md`.

---

## 8. Honest posture note (§1.6.3 — keep this)

The product's language must stay **"scanned, N findings, signed"** — never "safe" or "verified secure". Static scanning reduces risk; it cannot prove an agent safe (T-02 is explicitly unresolvable). The capability manifest exists so consuming runtimes can enforce least privilege at run time; publication scanning is one layer of defense in depth. The shipped scanners are good but not identical to the tools §8.3 names (DEV-006) — don't let docs or UI overclaim.
