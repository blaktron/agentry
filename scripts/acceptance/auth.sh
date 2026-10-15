#!/usr/bin/env bash
# Auth acceptance: the authorization matrix passes, the PAT lifecycle works
# end to end, and every mutating call leaves an audit row — all executed
# against a real Postgres.
set -euo pipefail
cd "$(cd "$(dirname "$0")/../.." && pwd)"
. scripts/acceptance/lib.sh
export PATH=/opt/homebrew/bin:$PATH

if [ -z "${AGENTRY_TEST_DATABASE_URL:-}" ]; then
  ./scripts/dev/pg.sh up
  AGENTRY_TEST_DATABASE_URL="$(./scripts/dev/pg.sh test-url)"
  export AGENTRY_TEST_DATABASE_URL
fi

echo "== auth acceptance =="
gotest "auth primitives" -timeout 20m ./internal/auth -count=1
gotest "route declarations complete" -timeout 20m ./internal/api -run TestRouteDeclarationsComplete -count=1
gotest "authz matrix" -timeout 20m ./internal/api -run TestAuthzMatrix -count=1
gotest "PAT lifecycle e2e" -timeout 20m ./internal/api -run TestPATLifecycle -count=1
gotest "audit coverage + append-only" -timeout 20m ./internal/api -run TestAuditCoverage -count=1
gotest "auth flows (login/TOTP/CSRF)" -timeout 20m ./internal/api -run 'TestAuthLifecycle|TestTOTPFlow' -count=1
echo "== auth acceptance PASSED =="
