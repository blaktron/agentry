# Developing Agentry

## Prerequisites

- Go at `go.mod`'s `go` line, 1.27.2 today (`brew install go`; an older `go`
  fetches that toolchain itself). There is no JavaScript build: the server's
  own pages are Go templates.
- Docker (preferred) **or** PostgreSQL 16 locally (`brew install postgresql@16`);
  `scripts/dev/pg.sh` runs a private cluster under `.devdata/pg` for machines
  without Docker
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
| `./scripts/acceptance/smoke.sh` | boots the stack against a database and reaches the API through the generated Go client (`make e2e` runs it) |
| `./scripts/acceptance/auth.sh` | the authorization matrix, the personal-access-token lifecycle and an audit row for every mutating call |
| `./scripts/acceptance/git.sh` | the git conformance matrix; oversize pushes, wrong credentials and tag-permission cases are refused |
| `./scripts/acceptance/publish-install.sh` | publish and install round trips for every agent kind and source, byte-reproducible archives, yank semantics, and the state-machine property that no path to `published` skips the gate |
| `./scripts/acceptance/cli.sh` | the `agentry` CLI against a booted `agentryd`: login, init, validate, publish, install, verify, yank |
| `./scripts/acceptance/gate.sh` | the attack-corpus gate (full recall, no benign regressions), offline attestation verification, tighten-only policy and an extractor that survives fuzzing |
| `./scripts/acceptance/enterprise-sso.sh` | SAML and OIDC sign-in, enforced SSO with organization-bound tokens, SCIM provisioning, domain verification, webhooks with the SSRF guard, and audit export |
| `./scripts/acceptance/helm.sh` | the Helm chart lints and renders, and its production shape holds (skipped without `helm`) |
| `./scripts/acceptance/invariant-test-names.sh` | every test named as evidence for a core security invariant still exists under that name |
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

The repository layout is in the [README](https://github.com/blaktron/agentry#layout). The API is
spec-first: edit `schemas/openapi.yaml`, regenerate with `make generate`, then
implement the new interface method on `internal/api.Server`. All SQL lives in
`internal/store/queries/` and goes through sqlc.

## The other repositories

The registry is one of several repositories that move together:
[agentry-cli](https://github.com/blaktron/agentry-cli) (the CLI and the
runner, Go), [agentry-desktop](https://github.com/blaktron/agentry-desktop)
(Wails: Go plus a React frontend; on Linux it needs the GTK 3 and WebKit2GTK
4.1 development headers to build) and [agentry-mcp](https://github.com/blaktron/agentry-mcp)
(an MCP server that drives the installed `agentry` CLI so Claude Code,
Codex or any MCP host can search, install, run and hold a session with
QuickAgents).
Others are closed, among them the hosted site (a Next.js front end that runs in
front of this server) and the enterprise build (a Go module that builds the
hosted server on `pkg/extension`). Each public repository has a `make check`
that is its CI gate. A change to the API contract is made in
`schemas/openapi.yaml` first, then regenerated into the server and the Go
client here (`pkg/apiclient`, which the CLI imports), and from the
published spec into the site's own types.

## Building with the CLI or the desktop app

A change that spans the core and the CLI (or the desktop app) builds against
both checkouts through a `go.work` that lists them:

```bash
# in a directory that holds both checkouts
go work init ./agentry ./agentry-cli
cd agentry-cli && go build ./...
```

With `GOWORK=off`, each module resolves the others from the versions its
`go.mod` names.

## Configuration

`agentry.yaml` (copy from `agentry.yaml.example`) + `AGENTRY_*` env overrides. Env always wins. `internal/config/config.go` is the authoritative mapping.
