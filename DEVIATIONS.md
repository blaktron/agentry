# DEVIATIONS

Per PLAN.md §0.5: PLAN.md is immutable during the build. Deviations, discovered constraints, and post-hoc decisions are recorded here — one dated entry each: **what, why, impact**. IDs are stable (`DEV-nnn`) and referenced from commits.

---

## DEV-001 — No container runtime on the build host (2026-08-27)

**What:** The build machine (macOS, arm64) has no Docker/colima/podman. The compose dev stack (`deploy/compose/docker-compose.yaml`, postgres+minio+mailpit per M0) is authored and validated structurally, but is not executed on this machine. Local development and integration tests instead run against a native PostgreSQL 16 (Homebrew) managed by `scripts/dev/pg.sh`; tests take their DSN from `AGENTRY_TEST_DATABASE_URL`. CI uses GitHub Actions Postgres service containers. §17.1's "testcontainers" mechanism is therefore realized as "real Postgres via DSN" — same coverage, different lifecycle manager.

**Why:** Installing Docker Desktop requires privileged system setup unavailable to the builder agent; Homebrew Postgres 16 provides the identical database engine.

**Impact:** M0 acceptance item "`make dev` boots stack" is verified by compose-config validation locally and by actual boot in any Docker-equipped environment; all DB-touching tests still run against real PostgreSQL 16 locally and in CI. No product code differs.

## DEV-002 — OpenAPI document version 3.0.3 instead of 3.1 (2026-08-27)

**What:** D-09 specifies "OpenAPI 3.1 spec-first". The spec at `schemas/openapi.yaml` is authored against OpenAPI **3.0.3**.

**Why:** The chosen generator toolchain (oapi-codegen v2, per Appendix B "all active") parses specs through kin-openapi, which does not accept `openapi: 3.1.x` documents. Alternatives (hand-rolled codegen, switching generators) cost more than the 3.1 delta is worth at v1; none of the v1 surface needs 3.1-only features (webhooks object, full JSON-Schema keywords).

**Impact:** None on API semantics or clients. Revisit when oapi-codegen's 3.1 support lands; bumping the document version is then mechanical. oasdiff gate works on 3.0.x today.

## DEV-005 — Job queue: interface now, River integration deferred (2026-08-27)

**What:** D-05 specifies River (Postgres-backed Go queue) for all async work. M4 ships the queue as an `internal/queue` interface with a Postgres `SELECT … FOR UPDATE SKIP LOCKED` implementation (the `jobs` table in migration 00005) — the same mechanism River uses internally — rather than River itself. River is pinned in go.mod for the swap.

**Why:** River owns its own migration set and worker lifecycle; wiring it fully is orthogonal to what M4's acceptance criteria actually test (attack-corpus recall, the gate, state-machine property tests, attestation verification). D-05 itself mandates "Queue interface wraps River", so building to the interface first is on-plan; the concrete driver is a later substitution behind it.

**Impact:** Async semantics (durable enqueue, at-least-once delivery, retries with backoff, idempotent handlers) are preserved by the SKIP-LOCKED implementation and its tests. Swapping in River means adding a `queue.Client` implementation and its migrations, with no change to enqueue sites or handlers. The scan orchestrator additionally supports synchronous in-process execution (used in dev mode and tests) so the pipeline is exercisable without a running worker.

## DEV-006 — Scanner external tools: interfaces with native fallbacks (2026-08-27)

**What:** §8.3 names specific tools — gitleaks (S2), opengrep (S6), osv-scanner (S7). M4 ships each scanner behind an interface with a capable native-Go implementation as the default, and an "external tool" adapter path (exec the real binary when present on `$PATH` / configured) left as the production upgrade. Concretely: S2 uses a native high-signal secret ruleset (including the `agy_` PAT rule required by D-22) with entropy gating; S6 uses native AST-free regex/heuristic detectors mapped to the capability vocabulary; S7 parses lockfiles natively and checks install-scripts + typosquat heuristics, with OSV vulnerability lookup gated behind an injected `osv.Client` (offline no-op by default).

**Why:** Embedding/execing three third-party toolchains (two of them requiring network calls or large rule databases) inside the no-egress sandbox task profile is an integration and packaging effort disproportionate to M4's gate criteria, which test detection behaviour on the committed attack corpus. The native implementations detect every technique the corpus exercises. The plan's swap-point philosophy (§3 "Swap point") applies: the interface is the commitment, the backend is replaceable.

**Impact:** Corpus recall and precision are met by native code. Production hardening (bundling gitleaks/opengrep binaries into the sandbox image, wiring osv-scanner's DB) becomes a matter of providing the adapter implementations behind the existing interfaces — no orchestrator or gate changes. Recorded so the security posture is honest (§1.6.3): the shipped scanners are good, not identical to the named tools.

## DEV-007 — LLM judge (S5): provider interface with none/static impls in-tree (2026-08-27)

**What:** D-13 defines judge providers bedrock/anthropic/none. M4 ships the `scan/judge.Provider` interface, the `none` provider (which forces human review per §8.4.6), and a deterministic `static` heuristic provider used as the default in tests and dev. The `bedrock` and `anthropic` providers are interface stubs returning a clear "not configured" error until wired with real SDK calls (Q3 also gates the SaaS default).

**Why:** Live LLM calls cannot run in CI or the offline build environment, and the SaaS model/region choice is an open question (Q3). §8.4.6 already specifies the fail-toward-review behaviour when no judge is available, which is exactly what `none` implements.

**Impact:** The gate's treatment of judge output (C1–C6 categories, borderline→review, manipulated-judge→review) is implemented and tested against the `static` provider. Enabling a real provider is additive.
