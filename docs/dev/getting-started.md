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
| `make check` | the CI gate: generated-code drift, the embedded rule bundle in sync, lint, tests, build |
| `make generate` | regenerate the OpenAPI server and Go client, and sqlc, after editing `schemas/` or `internal/store/queries/` |
| `make test` | Go tests; DB tests need `AGENTRY_TEST_DATABASE_URL` (`./scripts/dev/pg.sh test-url`), whose role may create databases: `internal/scan`, whose sweeps act on every row, runs in its own `<db>_scan` beside it |
| `./scripts/acceptance/m0.sh` | milestone acceptance scripts (`m0`–`m4`, `m6`, `m7`) |
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
(an MCP server that drives the installed `agentry` CLI so Claude Code,
Codex or any MCP host can search, install, run and hold a session with
QuickAgents; the earlier registry-API server is parked inside it as
`secureagentry-mcp/`), and [agentry-examples](https://github.com/blaktron/agentry-examples).
Two more are closed: `agentry-web` (the hosted site, a Next.js front end
that runs in front of this server) and `agentry-enterprise` (a Go module
that builds the hosted server on `pkg/extension`). Each has a `make check`
that is its CI gate. A change to the API contract is made in
`schemas/openapi.yaml` first, then regenerated into the server and the Go
client here (`pkg/apiclient`, which the CLI imports), and from the
published spec into the site's own types.

## Until the repositories are public

The open-core repositories are private until the operator flips them
(agentry-notes `PUBLIC-FLIP.md`; the date is not scheduled). Until then the
Go modules cannot be fetched anonymously, and three workarounds apply — each
disappears at the flip:

- **Locally**, a `go.work` at the workspace root resolves `agentry`,
  `agentry-cli` and `agentry-desktop` against sibling checkouts, so no
  download happens. Without it, `GOPRIVATE=github.com/blaktron` and
  `GONOSUMDB=github.com/blaktron` plus a git credential helper that answers
  with a read token let `go get` fetch the private module.
- **In CI** (self-hosted runners), `AGENTRY_BUILD_TOKEN` is a read token
  stored as a repository secret; the workflows write it into a git
  `insteadOf` rule for `https://github.com/` before `go mod download`. A
  repository without the secret fails at the module fetch and says so.
- **The docs and site images** clone the private repositories with the same
  kind of token as a BuildKit secret (`gh_token`).

Never put a token in a workflow file, a Dockerfile or a commit; the secret's
name is the only thing that belongs in the tree.

## Configuration

`agentry.yaml` (copy from `agentry.yaml.example`) + `AGENTRY_*` env overrides. Env always wins. `internal/config/config.go` is the authoritative mapping.
