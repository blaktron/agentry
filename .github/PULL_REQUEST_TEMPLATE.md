<!-- One concern per pull request. Conventional-commit subject. -->

## What and why

Closes #

## Verification

<!-- The tests, scripts or live checks you ran, and what you did NOT verify.
"Not verified" beats a claim that turns out to be wrong. -->

## Checklist

- [ ] every commit is signed off (DCO, CONTRIBUTING.md)
- [ ] the spec (`schemas/openapi.yaml`) was edited first and `make generate` run, if the API changed
- [ ] every new route has a `RouteDecl` in `internal/api/authz_routes.go`
- [ ] new scanner rules ship match and benign fixtures
- [ ] product copy never says "safe"
- [ ] a change to documented behaviour updates its page in `docs/`
