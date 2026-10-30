# Agentry

The Agentry registry server: a registry and git host for single-purpose AI
agents, with a mandatory pre-publication security pipeline and signed
provenance.

This repository is the open core. It holds `agentryd` (the server, in api,
git and worker roles), the ten-stage security pipeline, the account and
authorization system, the git host, the server's own pages at `/ui/`, and a
headless deployment (Docker Compose and a Helm chart). It runs on its own.
The Go module path, the `agentryd` and `agentry` binaries and the `AGENTRY_`
environment prefix keep the `agentry` name.

Every published version is scanned on the exact bytes that will ship, and
nothing becomes installable until the gate decides. A scanner that errors or
times out, or content it could not read, fails **toward** review — never
through. Static analysis cannot prove an agent safe, and the product never
claims it does. See [the trust model](https://docs.secureagentry.net/trust/)
for what the pipeline checks, what a signature proves and what none of it
guarantees.

## Prerequisites

- Go at the version on the `go` line of `go.mod` (an older `go` fetches that
  toolchain itself). There is no JavaScript build: the server's pages are Go
  templates.
- Docker with Compose, or PostgreSQL 18 locally (`scripts/dev/pg.sh` runs a
  private cluster).
- `sqlc` for query code generation (`make generate`).
- `golangci-lint` for `make lint` (the target skips it when it is absent).

## Build, test and lint

```bash
make build      # compile ./... and write bin/agentryd
make test       # all Go tests; database tests read AGENTRY_TEST_DATABASE_URL
make lint       # gofmt, go vet, golangci-lint
make generate   # regenerate the OpenAPI server, the Go client and sqlc output
make check      # the CI gate: generated-code drift, ruleset sync, compose image pins, third-party notices, lint, tests, build
make workflows-check  # no fork-reachable workflow job on a self-hosted runner (python3 with PyYAML)
```

`./scripts/dev/pg.sh test-url` prints a database URL for the tests. The
acceptance scripts in `scripts/acceptance/` drive a booted server end to end
(`make e2e` runs `smoke.sh`). The API is spec-first: edit `schemas/openapi.yaml`,
run `make generate`, then implement the new method on `internal/api.Server`.
[Developing Agentry](docs/dev/getting-started.md) has the details.

## Run it locally

```bash
make db-up      # local Postgres 18 on :5477
make dev        # migrations, then agentryd (all roles) on :8080
curl localhost:8080/api/v1/meta
```

People sign in through an OpenID provider you configure (`auth.oidc`); the
server keeps no passwords. http://localhost:8080/ui/ hands sign-in to that
provider, and `/ui/authorize` is the page the CLI and the desktop app open.
Configuration is
`agentry.yaml` (copy `agentry.yaml.example`) with `AGENTRY_*` environment
overrides; the environment wins. `deploy/compose` runs the whole registry
with no site in front: Postgres, object storage, mail, `agentryd` and an
nginx edge. For a real deployment, see
[self-hosting](https://docs.secureagentry.net/self-hosting/).

## Layout

| Path | What |
|---|---|
| `cmd/agentryd` | the server: `agentryd api\|git\|worker\|all` |
| `internal/scan` | the security pipeline: orchestrator, stages S1–S10, gate, judge, signing |
| `internal/registry` | agents, versions, the publication state machine, deterministic archives |
| `internal/gitsrv` | git smart-HTTP, repository storage, policy hooks |
| `internal/api` `internal/auth` `internal/store` | HTTP layer, identity and authorization, Postgres |
| `internal/render` | the only path by which author markdown reaches a browser |
| `internal/ui` | the server's own pages at `/ui/` (Go templates): device authorize, the sign-in hand-off, sign-out, address confirmation |
| `pkg/extension` | the seam an outside Go module extends the server through: routes, migrations, entitlements, hooks, jobs |
| `pkg/judge` `pkg/websearch` | the AI Review client and its question sets, and the web search clients |
| `pkg/` | the public surface the CLI and third parties build on: manifest spec and refs, rules engine, embedded ruleset, deterministic archives and extractor, attestation verification, the generated API client |
| `rules/` | the versioned S3/S4 rule bundle |
| `testdata/attack-corpus/` | the golden corpus: attack fixtures and their benign twins |
| `examples/` | small example QuickAgent packages that publish through the pipeline |
| `deploy/` | the headless Compose stack and the Helm chart |
| `schemas/` | the OpenAPI spec and the code generator configuration |
| `tools/oapi-codegen` | the OpenAPI generator's own Go module, so its dependencies stay out of the server's `go.mod` |
| `docs/` | the pages published at docs.secureagentry.net |

The CLI is [agentry-cli](https://github.com/blaktron/agentry-cli); it depends
on this module's `pkg/`.

## Documentation

- [Self-hosting](https://docs.secureagentry.net/self-hosting/)
- [Running QuickAgents](https://docs.secureagentry.net/quickagents/)
- [Trust and security model](https://docs.secureagentry.net/trust/)
- [The runner](https://docs.secureagentry.net/runner/)
- [API reference](https://developers.secureagentry.net/)
- [Developing Agentry](docs/dev/getting-started.md)

## Contributing

Contributions are welcome under the Developer Certificate of Origin (every
commit is signed off) and no CLA. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

Report vulnerabilities as described in [SECURITY.md](SECURITY.md), never in a
public issue.

## License

MIT (see [LICENSE](LICENSE)).
