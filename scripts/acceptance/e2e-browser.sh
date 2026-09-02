#!/usr/bin/env bash
# Browser smoke (DEV-031): boot the API + web exactly like m5.sh, seed a
# verified user, and drive real Chromium over the load-bearing pages and a
# same-origin form post (web/e2e/). Requires `npx playwright install
# chromium` to have run (CI does; locally: cd web && npx playwright install chromium).
set -euo pipefail
cd "$(cd "$(dirname "$0")/../.." && pwd)"
export PATH=/opt/homebrew/bin:$PATH

if [ -z "${AGENTRY_TEST_DATABASE_URL:-}" ]; then
  ./scripts/dev/pg.sh up
  AGENTRY_TEST_DATABASE_URL="$(./scripts/dev/pg.sh test-url)"
  export AGENTRY_TEST_DATABASE_URL
fi
DB="$AGENTRY_TEST_DATABASE_URL"

PSQL="${PGBIN:-}/psql"
[ -x "$PSQL" ] || PSQL="$(command -v psql || true)"
[ -n "$PSQL" ] || { echo "psql not found — set PGBIN"; exit 1; }

PORT=8199
WEBPORT=3099
WORK=$(mktemp -d)
make build >/dev/null
if [ ! -d web/node_modules ]; then (cd web && npm ci --silent); fi
# ALWAYS build: a stale .next serves yesterday's compiled server code, and
# this suite exists precisely to catch what yesterday's code got wrong (its
# first local run failed on a .next predating the sameOrigin fix — the
# stale build 403'd the browser exactly like the original outage).
(cd web && npm run build >"$WORK/webbuild.log" 2>&1) || { tail -20 "$WORK/webbuild.log"; exit 1; }

AGENTRY_LIMITS_AUTHED_BURST_PER_MIN="100000" \
AGENTRY_LIMITS_AUTHED_PER_HOUR="1000000" \
AGENTRY_LIMITS_ANONYMOUS_PER_MIN="100000" \
AGENTRY_LIMITS_LOGIN_PER_MIN="1000" \
AGENTRY_DATABASE_URL="$DB" AGENTRY_HTTP_ADDR=":$PORT" \
  AGENTRY_STORAGE_LOCAL_DIR="$WORK/storage" AGENTRY_GIT_DATA_DIR="$WORK/git" \
  AGENTRY_BASE_URL="http://localhost:$PORT" ./bin/agentryd all >"$WORK/api.log" 2>&1 &
API_PID=$!
AGENTRY_API_BASE="http://localhost:$PORT" ./web/node_modules/.bin/next start web -p $WEBPORT >"$WORK/web.log" 2>&1 &
WEB_PID=$!
trap 'kill $API_PID $WEB_PID 2>/dev/null || true' EXIT

for i in $(seq 1 60); do curl -fsS "http://localhost:$PORT/healthz" >/dev/null 2>&1 && break; sleep 0.5; done
curl -fsS "http://localhost:$PORT/healthz" >/dev/null || { echo "api failed to start:"; tail -20 "$WORK/api.log"; exit 1; }
for i in $(seq 1 100); do curl -fsS "http://localhost:$WEBPORT/" >/dev/null 2>&1 && break; sleep 0.5; done
curl -fsS "http://localhost:$WEBPORT/" >/dev/null || { echo "web failed to start:"; tail -20 "$WORK/web.log"; exit 1; }

SFX=$(date +%s | tail -c 6)
H="e2e$SFX"
PW="hunter2hunter2"
curl -fsS -X POST "http://localhost:$PORT/api/v1/auth/register" -H 'Content-Type: application/json' \
  -d "{\"handle\":\"$H\",\"email\":\"$H@example.test\",\"password\":\"$PW\"}" >/dev/null
"$PSQL" "$DB" -qAt -c "UPDATE users SET email_verified_at=now() WHERE email='$H@example.test'" >/dev/null

echo "== browser smoke (chromium) =="
(cd web && E2E_BASE_URL="http://localhost:$WEBPORT" E2E_API_URL="http://localhost:$PORT" \
  E2E_USER="$H" E2E_PASS="$PW" npx playwright test)
echo "== lighthouse a11y ≥ 90 on public pages (agentry#42) =="
./scripts/acceptance/lighthouse-a11y.sh "http://localhost:$WEBPORT"
echo "BROWSER SMOKE PASSED"
