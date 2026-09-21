# Contributing to Agentry

Agentry is a security product, so the bar for changes is a little higher than
usual in two specific places: the scanners and the authorization layer. Almost
everything else is ordinary Go work.

## Before you start

- **Security issues do not go in pull requests.** See [SECURITY.md](SECURITY.md).
- Large changes: open an issue first. Protocol and manifest changes go through
  an RFC in `docs/rfcs/` (copy the template, open a PR with the RFC alone).
- The build plan lives in [agentry-notes](https://github.com/blaktron/agentry-notes) and is immutable during the v1 build.
  Deviations get an entry in the deviations register there — dated, with what/why/impact —
  rather than an edit to the plan.

## Which repository

This repository is the open core: the server, the pipeline, auth, the git
host, the headless deployment and the server's own `/ui/` pages. The hosted
service's site (`blaktron/agentry-web`) and enterprise build
(`blaktron/agentry-enterprise`) are closed repositories; a bug in the hosted
site's pages, brand or deployment goes to the service's support address, not
to an issue here. The CLI, the desktop app, the MCP server, the docs machinery
and the examples each have their own public repository (see
[docs/dev/getting-started.md](docs/dev/getting-started.md)).

## Contributing from outside

Fork, branch from `main`, open a pull request. CI runs on the maintainers'
own runners once a maintainer approves the run for a first-time contributor.
Sign off every commit (the DCO, below); keep a change to one concern; say in
the PR what you verified and how. A change that departs from the recorded
design gets a dated entry in the deviations register in
[agentry-notes](https://github.com/blaktron/agentry-notes) — the maintainers
will write it with you.

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
| `make generate` | regenerate the OpenAPI server and Go client, and sqlc |
| `make test` | Go tests (DB tests need `AGENTRY_TEST_DATABASE_URL`) |
| `./scripts/acceptance/mN.sh` | the acceptance script for milestone N |
| `./scripts/acceptance/ui.sh` | the server's own `/ui/` pages, driven with curl and a cookie jar |
| `./scripts/acceptance/directory-signout.py` | sign-out against a live directory (needs its URL and the bootstrap token; a throwaway user it deletes) |

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

**The core UI can do nothing the API refuses.** A page under `internal/ui`
calls the API in-process with the browser's own session and CSRF token; it
never reaches into the store or around `routeAuthz`. A new page gets a test in
`internal/ui/ui_test.go`, and a new flow gets a step in
`scripts/acceptance/ui.sh`.

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
- conventional commits (`feat:`, `fix:`, `perf:`, `security:`, `deps:`, `docs:`,
  `refactor:`, `test:`, `ci:`, `chore:`) — release-please turns these into the
  CHANGELOG, so the prefix is what appears (or is hidden) in release notes. A
  `feat!:` or a `BREAKING CHANGE:` footer bumps the major version.

## Tests

New code needs tests at the level where the behaviour lives: table tests for
pure logic, real-Postgres integration tests for stores and handlers, and an
acceptance-script assertion for anything a milestone promises. Fixtures for
hostile content are text-only, defanged, and use `*.invalid.example` hosts —
never functional malware, never real endpoints, never real secrets.

## Writing

### The register

The docs, the READMEs and this file speak in one register, crisp: you for the
reader and no narrator. A file with no "we" in it does not get one. A claim
about protection names its mechanism in the same sentence or the next one. Not
"strict controls at every layer" but "the gateway serves only the tools the
manifest declared, and traffic leaves through the egress proxy".

Say it, then name it: "the manifest, the file that says what the agent may
touch" on first use, plain "manifest" after. Sentences run 10 to 25 words and
paragraphs 2 to 4 sentences. A sentence passes 30 words only when it is listing
mechanisms.

Hedge where the hedge is the fact: "cannot prove", "reduces" and "today" are
content, not softening. End a section on a next step or a stated limit rather
than a recap. Section numbers and register ids stay out of product copy, but
the docs keep their citations — §-numbers, DEV-nnn, RFC ids — because there
they are the audit trail.

The words this prose does not use live in `scripts/prose/never.txt`, and the
check reads them from there. They are reproduced here as data, not as prose:

```
safe                 trusted            leverage
secure               protected          leveraging
secure by default    ensures            trust infrastructure
guarantee            eliminates         enterprise-grade
guaranteed           prevents           peace of mind
Here's the thing     It's worth noting
```

Also out: superlatives about protection, tools written as guardians, landscape
openers, rhetorical questions, adjective triads, bold-colon listicles, closing
kickers, exclamation marks, emoji, `just` and `simply` as minimisers, and the
passive voice where the actor is known. `does not guarantee` is the one form of
those words the register keeps. No word disappears by deleting the sentence
that disclaims it.

### The copy loop

Rewriting a file follows one loop. Copy it to a before file, then audit the
whole file as a reader and with the four unslop scanners. A scanner hit is a
candidate, and a quiet scanner is not a pass.

Pull the constraints out with `extract_constraints.py`, add the sentences the
file carries that may not move, and draft in place with the smallest repair
that fixes what the audit confirmed. Then gate it with
`validate_preservation.py --strict`, `diff_check.py`, the four scanners again
on the result, and `scripts/prose/structure-diff.py` proving every fence,
table, heading, link and inline code span survived byte for byte.

Every script in that loop except `scripts/prose/structure-diff.py` is unslop's,
not this repository's — from the checkout `UNSLOP_DIR=<clone>` names below.
Pass `--strict` first or it does nothing. As a fourth argument it is dropped,
and a run with warnings still exits 0. In the constraints file's place it is
read as a path, and the script dies with a traceback.

§4 and §6 of `plans/front-end-voice-and-warmth.md` in
[agentry-notes](https://github.com/blaktron/agentry-notes) carry the full rule.
They say what counts as a finding, which sentences may not move, and when a
diff over 40 % or a preservation warning needs a named sign-off in the pull
request.

### The prose check

`scripts/prose/check.sh` runs over the working tree, and `make prose-check`
wraps it. Its blocking half reads three lists. Every sentence in
`scripts/prose/protected.txt` must appear in each file named beside it, with
whitespace collapsed so a line wrap is not a change. Every word in
`scripts/prose/never.txt` is refused unless it sits inside a span allowlisted
in `scripts/prose/allow.txt`, one `<reason> :: <span>` per line.

Fenced blocks, inline code spans and quoted terms are masked before that
search, so a command, a policy key and a quoted term keep their words. The
advisory half runs the unslop battery over the markdown, the server's HTML
templates and the notifier's strings, and never fails a build.
`UNSLOP_DIR=<clone>` points it at a local clone instead of fetching, and
`UNSLOP_SKIP=1` skips that half.

`scripts/prose/check.sh --self-test` proves the check still fails on a softened
posture sentence and on a seeded never-word. The CI job is `prose-check` in
`.github/workflows/ci.yaml`, and it runs both of those with `UNSLOP_SKIP=1`.

A red check is one of two things. A sentence that may not move was softened or
dropped: put it back, or edit `scripts/prose/protected.txt` in the same pull
request if the claim itself changed. Or a never-word reached the prose: reword
it so the mechanism carries the sentence. Where the word belongs, add the span
to `scripts/prose/allow.txt` with its reason, and argue that line in the pull
request.

## Certificate of origin

We use the [Developer Certificate of Origin](https://developercertificate.org/)
instead of a CLA. Sign off your commits:

```bash
git commit -s -m "fix: reject symlinks in the include set"
```

By signing off you state that you wrote the contribution or have the right to
submit it under the project's license.

## Licensing

The project license is MIT ([LICENSE](LICENSE)). Do not add dependencies
under AGPL, and do not import rule content
whose license restricts competing use — both would contaminate the
distribution (PLAN §14.4, threat T-13). New dependencies need a line in the PR
description explaining why an existing one will not do.

## Releasing

Releases are automated with [release-please](https://github.com/googleapis/release-please)
(`.github/workflows/release-please.yaml`, `release-please-config.json`):

1. Merges to `main` update a standing **release PR** that bumps the version
   (per the conventional-commit types since the last release) and rewrites
   `CHANGELOG.md`. Nothing is released while that PR sits open.
2. Merging the release PR creates the `vX.Y.Z` tag and a GitHub release whose
   body is the changelog.
3. The tag triggers `release.yaml`, which runs the full check + attack-corpus
   gate, then builds reproducible cross-platform binaries, an SPDX SBOM, and
   keyless cosign signatures, and attaches them to the release. It **refuses
   to release if the attack corpus gate is red** — the same bar publishers face.

One operational prerequisite: the tag must be pushed with a token that can
trigger workflows, or `release.yaml` will not fire. Store a fine-grained PAT
or GitHub App token as the `RELEASE_PLEASE_TOKEN` secret (see the note atop
`release-please.yaml`). Without it, the PR and changelog still work; push the
tag manually to cut assets.
