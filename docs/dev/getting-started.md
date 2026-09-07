# Developing Agentry

## Prerequisites

- Go 1.27+ (`brew install go`). There is no JavaScript build: the server's
  own pages are Go templates.
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
| `make generate` | regenerate the OpenAPI server and Go client, and sqlc, after editing `schemas/` or `internal/store/queries/` |
| `make test` | Go tests; DB tests need `AGENTRY_TEST_DATABASE_URL` (`./scripts/dev/pg.sh test-url`) |
| `./scripts/acceptance/m0.sh` | milestone acceptance scripts (one per milestone) |
| `./scripts/acceptance/ui.sh` | the server's own `/ui/` pages: sign-in, account, a token, a device authorize and its exchange, sign-out — with curl, no browser |

## The server's own pages

`internal/ui` serves `/ui/…` from Go `html/template` files
(`internal/ui/templates/`, one stylesheet in `internal/ui/static/`): the
device authorize page the CLI and the desktop app open, sign-in and sign-out,
the account pages (profile, tokens, SSH keys, sessions), the review queue, the
staff console and organization administration. Every page calls the API
in-process with the browser's own session, so it can do nothing the API
refuses; there is no client-side JavaScript to build. `ui.mode` (`full`,
`authorize`, `off`) selects how much of it a deployment serves; `web.url`
names a site in front, and `brand.*` is what the pages call the deployment.

## Layout

See PLAN §18.1 ([agentry-notes](https://github.com/blaktron/agentry-notes)). The layout is normative. Spec-first: edit `schemas/openapi.yaml`, regenerate, then implement the new interface method on `internal/api.Server`.

## The other repositories

The registry is one of several repositories that move together:
[agentry-cli](https://github.com/blaktron/agentry-cli) (the CLI and the
runner, Go), [agentry-desktop](https://github.com/blaktron/agentry-desktop)
(Wails: Go plus a React frontend; on Linux it needs the GTK 3 and WebKit2GTK
4.1 development headers to build), [agentry-docs](https://github.com/blaktron/agentry-docs)
(the MkDocs and Redoc machinery that builds the docs site from this
repository's `docs/` and the site's pages, and the developers site from
`schemas/openapi.yaml`), [agentry-mcp](https://github.com/blaktron/agentry-mcp)
(an MCP server that lets an agent host use the registry's API; regenerated
from the spec), and [agentry-examples](https://github.com/blaktron/agentry-examples).
Two more are closed: `agentry-web` (the hosted site, a Next.js front end
that runs in front of this server) and `agentry-enterprise` (a Go module
that builds the hosted server on `pkg/extension`). Each has a `make check`
that is its CI gate. A change to the API contract is made in
`schemas/openapi.yaml` first, then regenerated into the server and the Go
client here, and from the published spec into the CLI, agentry-mcp and the
site's own types.

## Configuration

`agentry.yaml` (copy from `agentry.yaml.example`) + `AGENTRY_*` env overrides. Env always wins. `internal/config/config.go` is the authoritative mapping.
