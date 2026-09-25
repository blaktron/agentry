# Agentry build entrypoints (M0). `make check` is the CI gate; `make dev`
# boots the local stack. Individual targets below are composable.

SHELL := /bin/bash
export PATH := /opt/homebrew/bin:$(PATH)

GO      ?= go
BIN_DIR := bin
LDFLAGS := -X github.com/blaktron/agentry/internal/version.Version=$(shell git describe --tags --always --dirty 2>/dev/null || echo 0.0.0-dev)

.PHONY: all build test lint vuln generate generate-check check prose-check dev db-up db-down clean e2e sync-rules sync-rules-check fuzz deps-audit attest-interop

all: build

## build: compile all packages and agentryd into ./bin (the CLI lives in
## github.com/blaktron/agentry-cli; scripts/dev/cli-bin.sh resolves/builds it)
build:
	$(GO) build ./...
	$(GO) build -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/agentryd ./cmd/agentryd

## test: run all Go tests (DB tests honor AGENTRY_TEST_DATABASE_URL), through
## scripts/ci/go-test.sh, which names a package killed by the timeout and says
## whether any test failed (agentry#452).
##
## TEST_TIMEOUT is measured, not guessed (agentry#452, 2026-09-25). The runs
## API gave 124 `check` jobs from 2026-09-22 to 09-25, and internal/api
## dominates every run:
##   - first runner host (core-1/2, 4 vCPU): 17 green runs, 420 s to 976 s
##     (median 648 s). No run was killed by the timeout.
##   - second host (r2-core-*, 12 vCPU): 98 green runs, 72 s to 424 s
##     (median 131 s).
## 25m = 1500 s is the worst green run (976 s) with about 50% headroom; the
## first host has swung more than twofold between quiet and loaded. A genuine
## hang still fails, at 25 minutes. The check job's timeout-minutes in
## .github/workflows/ci.yaml (35) is sized from this value: change both or
## neither.
TEST_TIMEOUT ?= 25m
test:
	GO=$(GO) ./scripts/ci/go-test.sh -timeout $(TEST_TIMEOUT) ./...

## lint: gofmt + go vet + golangci-lint (if installed)
# No `| grep -q` in the scripts or the workflows (agentry#548, after
# agentry-desktop#236): grep -q exits at its first match, the writer still
# writing gets EPIPE, and pipefail reports that as the pipeline's failure,
# so a found match reads as "not found". Comment lines are skipped.
lint:
	@hits=$$(grep -rnE '\|[[:space:]]*grep[[:space:]]+(-[A-Za-z]*q|--quiet)' scripts/ .github/workflows/ | grep -vE '^[^:]+:[0-9]+:[[:space:]]*#' || true); \
	if [ -n "$$hits" ]; then echo "$$hits"; echo "a piped grep -q under pipefail can fail on the writer's EPIPE: use grep -q ... <<<\"\$$x\" or grep ... >/dev/null (agentry#548)"; exit 1; fi
	@fmt_out=$$(gofmt -l . || true); \
	if [ -n "$$fmt_out" ]; then echo "gofmt needed on:"; echo "$$fmt_out"; exit 1; fi
	$(GO) vet ./...
	@if command -v golangci-lint >/dev/null 2>&1; then golangci-lint run ./...; \
	else echo "golangci-lint not installed; skipped (CI runs it)"; fi

## vuln: govulncheck over the module
vuln:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...

## generate: regenerate the OpenAPI server and Go client, and sqlc queries
generate:
	$(GO) tool oapi-codegen -config schemas/codegen-server.yaml schemas/openapi.yaml
	$(GO) tool oapi-codegen -config schemas/codegen-goclient.yaml schemas/openapi.yaml
	@if command -v sqlc >/dev/null 2>&1; then sqlc generate; else echo "sqlc not installed; skipped"; fi

## generate-check: fail if generated code drifted from the spec/queries
generate-check: generate
	@if ! git diff --quiet -- internal/api/openapi_gen.go pkg/apiclient/client_gen.go internal/store/gen; then \
	  echo "generated code is stale — run 'make generate' and commit"; git --no-pager diff --stat; exit 1; fi

## sync-rules: copy the canonical /rules bundle into the embeddable copy
# go:embed cannot reach outside a package directory, so the bundle exists
# twice. CONTINUE.md and DEV-011 both name this target; it did not exist
# until now, which meant the drift check nothing ran was also unrunnable.
sync-rules:
	./scripts/dev/sync-rules.sh

## sync-rules-check: fail if the embedded ruleset copy has drifted
sync-rules-check:
	./scripts/dev/sync-rules.sh --check

## fuzz: run each §17.5 fuzz target briefly (the committed corpora always run
## as ordinary tests; this exercises the mutator)
fuzz:
	$(GO) test -timeout 20m ./pkg/archive     -run FuzzExtract  -fuzz FuzzExtract  -fuzztime $(FUZZTIME)
	$(GO) test -timeout 20m ./pkg/manifest    -run FuzzParse    -fuzz FuzzParse    -fuzztime $(FUZZTIME)
	$(GO) test -timeout 20m ./internal/render -run FuzzSanitize -fuzz FuzzSanitize -fuzztime $(FUZZTIME)
FUZZTIME ?= 30s

## deps-audit: our own dependency hygiene (§17.5, T-13)
deps-audit:
	$(GO) run github.com/google/osv-scanner/v2/cmd/osv-scanner@latest scan source -r .
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...

## check: the full local/CI gate
check: generate-check sync-rules-check lint test build

## prose-check: the §4.6 posture sentences and the §4.4 never list over the
## markdown, then the advisory unslop battery (UNSLOP_SKIP=1 skips it,
## UNSLOP_DIR=<clone> skips the fetch). Deliberately not part of `check`:
## it needs python3 rather than Go, and CI runs it as its own job.
prose-check:
	./scripts/prose/check.sh

## dev: boot the dev stack (compose when docker exists, else local pg) and run agentryd all
dev:
	@if command -v docker >/dev/null 2>&1; then docker compose -f deploy/compose/docker-compose.yaml up -d; \
	else ./scripts/dev/pg.sh up; fi
	AGENTRY_DEV_MODE=$${AGENTRY_DEV_MODE:-true} \
	AGENTRY_DATABASE_URL=$$(./scripts/dev/pg.sh url 2>/dev/null || echo "postgres://agentry:agentry@localhost:5432/agentry_dev?sslmode=disable") \
	  $(GO) run ./cmd/agentryd all

db-up:
	./scripts/dev/pg.sh up

db-down:
	./scripts/dev/pg.sh down

## e2e: acceptance scripts (per-milestone)
e2e:
	./scripts/acceptance/m0.sh

clean:
	rm -rf $(BIN_DIR)

# Third-party verification of our DSSE/in-toto envelopes with cosign
# (agentry#26). Needs cosign on PATH.
attest-interop:
	./scripts/dev/attest-interop.sh
