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
