#!/usr/bin/env bash
# Core UI acceptance: boot the API the way smoke.sh does and drive the
# server's own browser surface with curl and a cookie jar: the sign-in
# hand-off with no provider configured, a signed-in landing, authorize a
# device and exchange its code from "the app", sign out. The account and its
# session are seeded (lib.sh seed_session); the sign-in round trip through an
# OpenID provider is the Go suite's (internal/api). No browser, no Node: this
# is the headless registry's own check.
set -euo pipefail
cd "$(cd "$(dirname "$0")/../.." && pwd)"
. scripts/acceptance/lib.sh
PORT="${AGENTRY_ACCEPT_PORT:-$(python3 -c "import socket; s=socket.socket(); s.bind(('127.0.0.1',0)); print(s.getsockname()[1]); s.close()")}"
echo "== core UI acceptance =="
if [ -z "${AGENTRY_TEST_DATABASE_URL:-}" ]; then
  ./scripts/dev/pg.sh up
  AGENTRY_TEST_DATABASE_URL="$(./scripts/dev/pg.sh test-url)"
  export AGENTRY_TEST_DATABASE_URL
fi
make build >/dev/null
# A throwaway server: dev mode, opted in.
export AGENTRY_DEV_MODE=true
AGENTRY_DATABASE_URL="$AGENTRY_TEST_DATABASE_URL" ./bin/agentryd migrate
BASE="http://localhost:$PORT"
AGENTRY_DATABASE_URL="$AGENTRY_TEST_DATABASE_URL" AGENTRY_HTTP_ADDR=":$PORT" AGENTRY_BASE_URL="$BASE" \
  AGENTRY_LIMITS_LOGIN_PER_MIN=1000 ./bin/agentryd api &
SRV_PID=$!
JAR="$(mktemp)"
trap 'kill $SRV_PID 2>/dev/null || true; rm -f "$JAR"' EXIT
for i in $(seq 1 50); do
  curl -fsS "$BASE/healthz" >/dev/null 2>&1 && break
  sleep 0.2
  [ "$i" = 50 ] && { echo "server did not become healthy"; exit 1; }
done
SFX="$(python3 -c "import secrets; print(secrets.token_hex(3))")"
HANDLE="uiacc$SFX"
# Signed out: the hand-off page, which has no form, and says plainly that
# there is no provider to hand off to.
page=$(curl -fsS "$BASE/ui/login")
grep 'has not configured one' <<<"$page" >/dev/null || { echo "sign-in page: $page"; exit 1; }
if grep -q '<form' <<<"$page"; then echo "sign-in page carries a form"; exit 1; fi
code=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$BASE/ui/login" --data-urlencode "login=$HANDLE" --data-urlencode "password=x")
[ "$code" = "405" ] || { echo "POST /ui/login: $code"; exit 1; }
echo "sign-in hand-off: OK"
for path in /ui/account /ui/account/tokens /ui/review /ui/staff /ui/orgs; do
  code=$(curl -sS -o /dev/null -w '%{http_code}' "$BASE$path")
  [ "$code" = "404" ] || { echo "$path: $code, want 404"; exit 1; }
done
echo "only the sign-in and authorize pages are served: OK"
seed_session "$HANDLE"
printf 'localhost\tFALSE\t/\tFALSE\t0\tagentry_session\t%s\nlocalhost\tFALSE\t/\tFALSE\t0\tagentry_csrf\t%s\n' "$SESSION" "$CSRF" >"$JAR"
csrf() { awk '$6=="agentry_csrf"{print $7}' "$JAR" | tail -1; }
curl -fsS -b "$JAR" "$BASE/ui/" | grep "signed in as $HANDLE" >/dev/null && echo "landing names the account: OK"
STATE="state_$SFX$SFX"
curl -fsS -b "$JAR" "$BASE/ui/authorize?port=40123&state=$STATE" | grep "127.0.0.1:40123" >/dev/null && echo "authorize page: OK"
cb=$(curl -sS -o /dev/null -w '%{redirect_url}' -b "$JAR" -H 'Sec-Fetch-Site: same-origin' --data-urlencode "_csrf=$(csrf)" \
  --data-urlencode "port=40123" --data-urlencode "state=$STATE" "$BASE/ui/authorize")
case "$cb" in http://127.0.0.1:40123/callback\?*) ;; *) echo "approve: redirect $cb"; exit 1;; esac
CODE=$(python3 -c "import sys,urllib.parse as u; print(u.parse_qs(u.urlparse(sys.argv[1]).query)['code'][0])" "$cb")
TOKEN=$(curl -fsS -X POST "$BASE/api/v1/auth/desktop/exchange" -H 'Content-Type: application/json' \
  -d "{\"code\":\"$CODE\",\"state\":\"$STATE\"}" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
curl -fsS -o /dev/null -H "Authorization: Bearer $TOKEN" "$BASE/api/v1/user" && echo "device authorize + exchange: OK"
loc=$(curl -sS -o /dev/null -w '%{http_code}' -b "$JAR" -c "$JAR" -H 'Sec-Fetch-Site: same-origin' --data-urlencode "_csrf=$(csrf)" "$BASE/ui/logout")
[ "$loc" = "303" ] || { echo "sign-out: $loc"; exit 1; }
code=$(curl -sS -o /dev/null -w '%{http_code}' -b "agentry_session=$SESSION" "$BASE/api/v1/user")
[ "$code" = "401" ] && echo "sign-out revokes the session: OK"
echo "== core UI acceptance PASSED =="
