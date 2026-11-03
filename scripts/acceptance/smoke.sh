#!/usr/bin/env bash
# Smoke acceptance: the compiled binary boots (migrations, the api role,
# health and readiness endpoints, the well-known document, the API's own
# metadata and the login page), every request reaching that process. The
# generated Go client's smoke, TestSmoke, runs once, in the Go suite
# (`make test`), against its own in-process server.
set -euo pipefail
cd "$(cd "$(dirname "$0")/../.." && pwd)"
. scripts/acceptance/lib.sh

PORT="${AGENTRY_ACCEPT_PORT:-$(python3 -c "import socket; s=socket.socket(); s.bind(('127.0.0.1',0)); print(s.getsockname()[1]); s.close()")}"  # free unless pinned
export PATH=/opt/homebrew/bin:$PATH

echo "== smoke acceptance =="

# 1. Database: CI provides AGENTRY_TEST_DATABASE_URL; locally use pg.sh.
if [ -z "${AGENTRY_TEST_DATABASE_URL:-}" ]; then
  ./scripts/dev/pg.sh up
  AGENTRY_TEST_DATABASE_URL="$(./scripts/dev/pg.sh test-url)"
  export AGENTRY_TEST_DATABASE_URL
fi
echo "db: $AGENTRY_TEST_DATABASE_URL"

# 2. Build binaries.
make build >/dev/null
BIN_VERSION="$(./bin/agentryd --version)"
echo "$BIN_VERSION"
BIN_VERSION="${BIN_VERSION#agentryd version }"
# The CLI lives in github.com/blaktron/agentry-cli (built via scripts/dev/cli-bin.sh).

# A throwaway server: dev mode, opted in — the default is off and would
# ask for a sealing key and a signing key.
export AGENTRY_DEV_MODE=true

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

# 5. The API answers from this process: its metadata names the version the
# binary was built with, so the request reached the server started above
# and not another one.
META_VERSION="$(curl -fsS "http://localhost:$PORT/api/v1/meta" | python3 -c 'import json,sys; print(json.load(sys.stdin)["version"])')"
if [ "$META_VERSION" != "$BIN_VERSION" ]; then
  echo "api meta: version $META_VERSION, want the binary's $BIN_VERSION"; exit 1
fi
echo "api meta: OK ($META_VERSION)"

# 6. The server's own surface answers (the full check is scripts/acceptance/ui.sh).
curl -fsS -o /dev/null -w '%{http_code}' "http://localhost:$PORT/ui/login" | grep 200 >/dev/null && echo "core UI: OK"

echo "== smoke acceptance PASSED =="
