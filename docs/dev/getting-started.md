# Developing Agentry

## Prerequisites

- Go 1.24+ (`brew install go`)
- Node 20+ for the web layer (`brew install node`)
- Docker (preferred) **or** PostgreSQL 16 locally (`brew install postgresql@16`); see DEV-001 in the agentry-notes deviations register
- `sqlc` for query codegen (`brew install sqlc` or `go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest`)

## Quick start

```bash
make db-up          # local Postgres 16 on :5477 (or: docker compose -f deploy/compose/docker-compose.yaml up -d)
make dev            # migrations + agentryd all on :8080
curl localhost:8080/api/v1/meta
```

## Everyday commands

| Command | What |
|---|---|
| `make check` | the CI gate: generated-code drift, lint, tests, build |
| `make generate` | regenerate OpenAPI server/client, sqlc, TS types after editing `schemas/` or `internal/store/queries/` |
| `make test` | Go tests; DB tests need `AGENTRY_TEST_DATABASE_URL` (`./scripts/dev/pg.sh test-url`) |
| `./scripts/acceptance/m0.sh` | milestone acceptance scripts (one per milestone) |

## Layout

See PLAN §18.1 ([agentry-notes](https://github.com/blaktron/agentry-notes)). The layout is normative. Spec-first: edit `schemas/openapi.yaml`, regenerate, then implement the new interface method on `internal/api.Server`.

## Configuration

`agentry.yaml` (copy from `agentry.yaml.example`) + `AGENTRY_*` env overrides. Env always wins. `internal/config/config.go` is the authoritative mapping.
