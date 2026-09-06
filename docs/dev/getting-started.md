# Developing Agentry

## Prerequisites

- Go 1.27+ (`brew install go`)
- Node 22.15+ for the web layer (`brew install node`) — the Builder's
  archive packer uses `node:zlib`'s zstd, which arrived in 22.15
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

## The other repositories

The registry is one of several repositories that move together:
[agentry-cli](https://github.com/blaktron/agentry-cli) (the CLI and the
runner, Go), [agentry-desktop](https://github.com/blaktron/agentry-desktop)
(Wails: Go plus a React frontend; on Linux it needs the GTK 3 and WebKit2GTK
4.1 development headers to build), [agentry-docs](https://github.com/blaktron/agentry-docs)
(the MkDocs and Redoc machinery that builds this site and the developers
site from this repository's `docs/` and `schemas/openapi.yaml`),
[agentry-mcp](https://github.com/blaktron/agentry-mcp) (an MCP server that
lets an agent host use the registry's API; regenerated from the spec), and
[agentry-examples](https://github.com/blaktron/agentry-examples). Each has
a `make check` that is its CI gate. A change to the API contract is made
in `schemas/openapi.yaml` first, then regenerated into the server, the CLI
client, the web types and agentry-mcp.

## Configuration

`agentry.yaml` (copy from `agentry.yaml.example`) + `AGENTRY_*` env overrides. Env always wins. `internal/config/config.go` is the authoritative mapping.
