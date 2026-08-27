#!/usr/bin/env bash
# M5 acceptance (PLAN §18.2): the web app builds and server-renders the five
# §2.3 public flows against a live API, the XSS corpus renders safe (§10.3),
# and search/report/README endpoints back the pages.
set -euo pipefail
cd "$(cd "$(dirname "$0")/../.." && pwd)"
export PATH=/opt/homebrew/bin:$PATH

if [ -z "${AGENTRY_TEST_DATABASE_URL:-}" ]; then
  ./scripts/dev/pg.sh up
  AGENTRY_TEST_DATABASE_URL="$(./scripts/dev/pg.sh test-url)"
  export AGENTRY_TEST_DATABASE_URL
fi

echo "== M5 acceptance =="

# 1. Sanitizer / XSS corpus + invisible-character reveal (§10.3).
go test ./internal/render -count=1 >/dev/null && echo "XSS corpus + invisible-char reveal (§10.3): OK"

# 2. Search + README render endpoints (§10.4, §10.3).
go test ./internal/api -run 'TestAuthzMatrix|TestRouteDeclarationsComplete' -count=1 >/dev/null \
  && echo "route declarations + authz matrix (incl. search/readme): OK"

# 3. Web app typecheck + production build.
if [ ! -d web/node_modules ]; then (cd web && npm install --silent); fi
(cd web && npx tsc --noEmit) && echo "web typecheck: OK"
(cd web && npm run build >/tmp/agentry-m5-build.log 2>&1) \
  && echo "web production build: OK" \
  || { echo "web build FAILED"; tail -20 /tmp/agentry-m5-build.log; exit 1; }

# 4. Live SSR smoke: boot the API + web, publish an agent, assert the agent
#    page server-renders its capability contract and report card.
PORT=8199
WEBPORT=3099
WORK=$(mktemp -d)
DB="$(./scripts/dev/pg.sh url)"
make build >/dev/null
AGENTRY_DATABASE_URL="$DB" AGENTRY_HTTP_ADDR=":$PORT" \
  AGENTRY_STORAGE_LOCAL_DIR="$WORK/storage" AGENTRY_GIT_DATA_DIR="$WORK/git" \
  AGENTRY_BASE_URL="http://localhost:$PORT" ./bin/agentryd all >"$WORK/api.log" 2>&1 &
API_PID=$!
AGENTRY_API_BASE="http://localhost:$PORT" ./web/node_modules/.bin/next start web -p $WEBPORT >"$WORK/web.log" 2>&1 &
WEB_PID=$!
trap 'kill $API_PID $WEB_PID 2>/dev/null || true' EXIT

for i in $(seq 1 60); do curl -fsS "http://localhost:$PORT/healthz" >/dev/null 2>&1 && break; sleep 0.3; done
for i in $(seq 1 100); do curl -fsS "http://localhost:$WEBPORT/" >/dev/null 2>&1 && break; sleep 0.3; done
if ! curl -fsS "http://localhost:$WEBPORT/" >/dev/null 2>&1; then
  echo "web server failed to start:"; tail -20 "$WORK/web.log"; exit 1
fi

SFX=$(date +%s | tail -c 6)
H="m5demo$SFX"
curl -fsS -X POST "http://localhost:$PORT/api/v1/auth/register" -H 'Content-Type: application/json' \
  -d "{\"handle\":\"$H\",\"email\":\"$H@example.test\",\"password\":\"hunter2hunter2\"}" >/dev/null
"${PGBIN:-/opt/homebrew/opt/postgresql@16/bin}/psql" "$DB" -qAt \
  -c "UPDATE users SET email_verified_at=now(), created_at=now()-interval '60 days' WHERE email='$H@example.test'" >/dev/null
CJ=$(mktemp)
CSRF=$(curl -fsS -c "$CJ" -X POST "http://localhost:$PORT/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"login\":\"$H\",\"password\":\"hunter2hunter2\"}" | python3 -c 'import json,sys;print(json.load(sys.stdin)["csrfToken"])')
PAT=$(curl -fsS -b "$CJ" -H "X-Agentry-CSRF: $CSRF" -X POST "http://localhost:$PORT/api/v1/user/tokens" \
  -H 'Content-Type: application/json' -d '{"name":"m5","scopes":["agent:publish","agent:read"]}' \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["token"])')
curl -fsS -b "$CJ" -H "X-Agentry-CSRF: $CSRF" -X POST "http://localhost:$PORT/api/v1/agents" \
  -H 'Content-Type: application/json' \
  -d "{\"namespace\":\"$H\",\"name\":\"demo-skill\",\"kind\":\"skill\",\"visibility\":\"public\",\"summary\":\"M5 acceptance demo agent\"}" >/dev/null

AG=$(mktemp -d)
cat > "$AG/agent.yaml" <<YAML
schemaVersion: "1"
name: demo-skill
namespace: $H
kind: skill
version: 1.0.0
summary: "M5 acceptance demo agent"
license: Apache-2.0
entrypoints:
  skill: SKILL.md
capabilities:
  network:
    egress: [api.example.com]
  secrets: [DEMO_TOKEN]
publish:
  include: [agent.yaml, README.md, SKILL.md, LICENSE]
YAML
printf '# demo-skill\n\nA **well-behaved** demo agent for the M5 acceptance check.\n' > "$AG/README.md"
printf 'Summarize the input politely and cite sources.\n' > "$AG/SKILL.md"
echo "Apache-2.0" > "$AG/LICENSE"
AGENTRY_TOKEN="$PAT" ./bin/agentry --registry "http://localhost:$PORT" publish "$AG" >/dev/null 2>&1

check() { # url, needle, label
  if curl -fsS "$1" | grep -q "$2"; then echo "  $3: OK"; else echo "  $3: FAILED (missing '$2')"; exit 1; fi
}
echo "live SSR flows:"
check "http://localhost:$WEBPORT/"                          "scanning step built in" "home page"
check "http://localhost:$WEBPORT/search?q=demo"             "demo-skill"             "search results"
check "http://localhost:$WEBPORT/$H/demo-skill"             "Declared capabilities"  "agent page (capability contract)"
check "http://localhost:$WEBPORT/$H/demo-skill"             "Security report"        "agent page (report card)"
check "http://localhost:$WEBPORT/$H/demo-skill"             "api.example.com"        "agent page (egress host)"
check "http://localhost:$WEBPORT/$H/demo-skill/versions/1.0.0" "Provenance"          "version page (provenance)"
check "http://localhost:$WEBPORT/$H"                        "demo-skill"             "namespace page"
check "http://localhost:$WEBPORT/trust"                     "does not guarantee"     "trust page"
check "http://localhost:$WEBPORT/docs"                      "publish.include"        "docs page"

echo "== M5 acceptance PASSED =="
