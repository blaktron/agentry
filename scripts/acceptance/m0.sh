#!/usr/bin/env bash
# M0 acceptance (PLAN §18.2): stack boots, `make check` is green (run
# separately in CI), and a smoke test hits the API through the generated
# Go client (in `make test`); the TS client smoke lives with the site now.
set -euo pipefail
cd "$(cd "$(dirname "$0")/../.." && pwd)"

PORT="${AGENTRY_ACCEPT_PORT:-$(python3 -c "import socket; s=socket.socket(); s.bind(('127.0.0.1',0)); print(s.getsockname()[1]); s.close()")}"  # free unless pinned (agentry#133)
export PATH=/opt/homebrew/bin:$PATH

echo "== M0 acceptance =="

# 1. Database: CI provides AGENTRY_TEST_DATABASE_URL; locally use pg.sh.
if [ -z "${AGENTRY_TEST_DATABASE_URL:-}" ]; then
  ./scripts/dev/pg.sh up
  AGENTRY_TEST_DATABASE_URL="$(./scripts/dev/pg.sh test-url)"
  export AGENTRY_TEST_DATABASE_URL
fi
echo "db: $AGENTRY_TEST_DATABASE_URL"

# 2. Build binaries.
make build >/dev/null
./bin/agentryd --version
# The CLI moved to github.com/blaktron/agentry-cli (built via scripts/dev/cli-bin.sh).

# 3. Migrations against a clean-ish DB.
AGENTRY_DATABASE_URL="$AGENTRY_TEST_DATABASE_URL" ./bin/agentryd migrate
echo "migrations: OK"

# 4. Boot the api role and wait for readiness.
AGENTRY_DATABASE_URL="$AGENTRY_TEST_DATABASE_URL" \
AGENTRY_HTTP_ADDR=":$PORT" \
  ./bin/agentryd api &
SRV_PID=$!
trap 'kill $SRV_PID 2>/dev/null || true' EXIT

for i in $(seq 1 50); do
  if curl -fsS "http://localhost:$PORT/healthz" >/dev/null 2>&1; then break; fi
  sleep 0.2
  [ "$i" = 50 ] && { echo "server did not become healthy"; exit 1; }
done
curl -fsS "http://localhost:$PORT/healthz" >/dev/null && echo "healthz: OK"
curl -fsS "http://localhost:$PORT/readyz"  >/dev/null && echo "readyz: OK (db reachable)"
curl -fsS "http://localhost:$PORT/.well-known/agentry/registry.json" >/dev/null && echo "well-known: OK"

# 5. Go client smoke (same code path as make test, run explicitly).
go test ./internal/api -run 'TestM0Smoke' -count=1 >/dev/null && echo "go client smoke: OK"

# 6. The server's own surface answers (the full check is scripts/acceptance/ui.sh).
curl -fsS -o /dev/null -w '%{http_code}' "http://localhost:$PORT/ui/login" | grep -q 200 && echo "core UI: OK"

echo "== M0 acceptance PASSED =="
