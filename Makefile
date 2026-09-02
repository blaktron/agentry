# Agentry build entrypoints (M0). `make check` is the CI gate; `make dev`
# boots the local stack. Individual targets below are composable.

SHELL := /bin/bash
export PATH := /opt/homebrew/bin:$(PATH)

GO      ?= go
BIN_DIR := bin
LDFLAGS := -X github.com/blaktron/agentry/internal/version.Version=$(shell git describe --tags --always --dirty 2>/dev/null || echo 0.0.0-dev)

.PHONY: all build test lint vuln generate generate-check check dev db-up db-down clean web-install web-check e2e sync-rules sync-rules-check fuzz deps-audit attest-interop

all: build

## build: compile all packages and agentryd into ./bin (the CLI lives in
## github.com/blaktron/agentry-cli; scripts/dev/cli-bin.sh resolves/builds it)
build:
	$(GO) build ./...
	$(GO) build -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/agentryd ./cmd/agentryd

## test: run all Go tests (DB tests honor AGENTRY_TEST_DATABASE_URL)
test:
	$(GO) test ./...

## lint: gofmt + go vet + golangci-lint (if installed)
lint:
	@fmt_out=$$(gofmt -l . | grep -v '^web/' || true); \
	if [ -n "$$fmt_out" ]; then echo "gofmt needed on:"; echo "$$fmt_out"; exit 1; fi
	$(GO) vet ./...
	@if command -v golangci-lint >/dev/null 2>&1; then golangci-lint run ./...; \
	else echo "golangci-lint not installed; skipped (CI runs it)"; fi

## vuln: govulncheck over the module
vuln:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...

## generate: regenerate OpenAPI server/client, sqlc queries, TS types
generate:
	$(GO) tool oapi-codegen -config schemas/codegen-server.yaml schemas/openapi.yaml
	$(GO) tool oapi-codegen -config schemas/codegen-goclient.yaml schemas/openapi.yaml
	@if command -v sqlc >/dev/null 2>&1; then sqlc generate; else echo "sqlc not installed; skipped"; fi
	@if [ -d web/node_modules ]; then cd web && npm run --silent gen; else echo "web deps not installed; TS gen skipped"; fi

## generate-check: fail if generated code drifted from the spec/queries
generate-check: generate
	@if ! git diff --quiet -- internal/api/openapi_gen.go pkg/apiclient/client_gen.go internal/store/gen web/lib/api; then \
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
	$(GO) test ./internal/scan   -run FuzzExtract  -fuzz FuzzExtract  -fuzztime $(FUZZTIME)
	$(GO) test ./pkg/manifest    -run FuzzParse    -fuzz FuzzParse    -fuzztime $(FUZZTIME)
	$(GO) test ./internal/render -run FuzzSanitize -fuzz FuzzSanitize -fuzztime $(FUZZTIME)
FUZZTIME ?= 30s

## deps-audit: our own dependency hygiene (§17.5, T-13)
deps-audit:
	$(GO) run github.com/google/osv-scanner/v2/cmd/osv-scanner@latest scan source -r .
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...

## check: the full local/CI gate
check: generate-check sync-rules-check lint test build

## dev: boot the dev stack (compose when docker exists, else local pg) and run agentryd all
dev:
	@if command -v docker >/dev/null 2>&1; then docker compose -f deploy/compose/docker-compose.yaml up -d; \
	else ./scripts/dev/pg.sh up; fi
	AGENTRY_DATABASE_URL=$$(./scripts/dev/pg.sh url 2>/dev/null || echo "postgres://agentry:agentry@localhost:5432/agentry_dev?sslmode=disable") \
	  $(GO) run ./cmd/agentryd all

db-up:
	./scripts/dev/pg.sh up

db-down:
	./scripts/dev/pg.sh down

web-install:
	cd web && npm install

web-check:
	cd web && npm run check

## e2e: acceptance scripts (per-milestone)
e2e:
	./scripts/acceptance/m0.sh

clean:
	rm -rf $(BIN_DIR)

# Third-party verification of our DSSE/in-toto envelopes with cosign
# (agentry#26). Needs cosign on PATH.
attest-interop:
	./scripts/dev/attest-interop.sh
