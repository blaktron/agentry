#!/usr/bin/env bash
# Git protocol conformance matrix. The matrix itself lives in
# internal/gitsrv/conformance_test.go (one implementation, real git CLI);
# this wrapper is the CI entrypoint.
set -euo pipefail
cd "$(cd "$(dirname "$0")/../.." && pwd)"
export PATH=/opt/homebrew/bin:$PATH

if [ -z "${AGENTRY_TEST_DATABASE_URL:-}" ]; then
  ./scripts/dev/pg.sh up
  AGENTRY_TEST_DATABASE_URL="$(./scripts/dev/pg.sh test-url)"
  export AGENTRY_TEST_DATABASE_URL
fi

go test -timeout 20m ./internal/gitsrv -run TestGitConformance -count=1 -v 2>&1 \
  | grep -E "^(=== RUN|    --- (PASS|FAIL)|--- (PASS|FAIL)|ok|FAIL)" || true
go test -timeout 20m ./internal/gitsrv -run TestGitConformance -count=1 >/dev/null
echo "git conformance matrix: PASSED"
