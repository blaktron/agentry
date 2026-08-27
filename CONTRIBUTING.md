# Contributing to Agentry

Agentry is a security product, so the bar for changes is a little higher than
usual in two specific places: the scanners and the authorization layer. Almost
everything else is ordinary Go and TypeScript work.

## Before you start

- **Security issues do not go in pull requests.** See [SECURITY.md](SECURITY.md).
- Large changes: open an issue first. Protocol and manifest changes go through
  an RFC in `docs/rfcs/` (copy the template, open a PR with just the RFC).
- The build plan lives in `PLAN.md` and is immutable during the v1 build.
  Deviations get an entry in `DEVIATIONS.md` — dated, with what/why/impact —
  rather than an edit to the plan.

## Development setup

```bash
brew install go postgresql@16 sqlc golangci-lint   # or your platform's equivalent
make db-up                                          # local Postgres on :5477
make dev                                            # migrations + agentryd all on :8080
```

Everyday commands:

| Command | What |
|---|---|
| `make check` | the full gate: generated-code drift, lint, tests, build |
| `make generate` | regenerate OpenAPI server/client, sqlc, TS types |
| `make test` | Go tests (DB tests need `AGENTRY_TEST_DATABASE_URL`) |
| `./scripts/acceptance/mN.sh` | the acceptance script for milestone N |

Docker is optional; `scripts/dev/pg.sh` manages a private Postgres cluster if
you would rather not run a container.

## The rules that matter

**Spec-first for the API.** Edit `schemas/openapi.yaml`, run `make generate`,
then implement the generated interface method. CI fails on generated-code drift
and on breaking changes within `/api/v1`.

**Every route declares its authorization.** Add an entry to `routeAuthz` in
`internal/api/authz_routes.go`. A route with no declaration fails CI — that
table is the tenant-isolation control, and the matrix test enumerates it
against every role. If a handler needs authorization the chokepoint cannot
express (platform staff, org reviewer, "not the author"), mark it
`SelfAuthorized: true` and write a dedicated test for it.

**All SQL lives in `internal/store/queries/` and goes through sqlc.** No
string-built SQL anywhere else.

**Every scanner rule ships with fixtures.** A rule in `rules/` needs at least
two matching and two non-matching cases, and the non-matching cases must
include a plausible benign lookalike. The loader refuses rules without them.
A new detection technique also needs a fixture pair in
`testdata/attack-corpus/`. Recall regressions and precision regressions both
fail the build; precision matters as much as recall, because an agent *about*
prompt-injection defense has to remain publishable.

**Never write "safe".** Product copy says "scanned", "N findings", "signed".
Static analysis cannot prove an agent safe and we do not imply otherwise. This
is a review point, not a style preference.

**Do not log secrets.** No tokens, PAT values, session ids, or judge inputs in
logs. Audit `detail` fields are for structured facts, not payloads.

## Code style

Match the file you are editing. Beyond that:

- wrap errors with context (`fmt.Errorf("registry: resolve %s: %w", ref, err)`);
- `context.Context` first parameter, threaded through;
- no package-level mutable state;
- document every exported symbol in `pkg/`;
- comments explain constraints and *why*, not what the next line does;
- conventional commits (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`).

## Tests

New code needs tests at the level where the behaviour lives: table tests for
pure logic, real-Postgres integration tests for stores and handlers, and an
acceptance-script assertion for anything a milestone promises. Fixtures for
hostile content are text-only, defanged, and use `*.invalid.example` hosts —
never functional malware, never real endpoints, never real secrets.

## Certificate of origin

We use the [Developer Certificate of Origin](https://developercertificate.org/)
instead of a CLA. Sign off your commits:

```bash
git commit -s -m "fix: reject symlinks in the include set"
```

By signing off you state that you wrote the contribution or have the right to
submit it under the project's license.

## Licensing

The project license is being finalized (PLAN §20 Q2); the planning default is
Apache-2.0. Do not add dependencies under AGPL, and do not import rule content
whose license restricts competing use — both would contaminate the
distribution (PLAN §14.4, threat T-13). New dependencies need a line in the PR
description explaining why an existing one will not do.
