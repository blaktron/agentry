#!/usr/bin/env bash
# Core UI acceptance (DEV-091, plan core-web-split §3.2): boot the API the
# way m0.sh does and drive the server's own browser surface with curl and a
# cookie jar — sign in through the form, read the account, mint a token,
# authorize a device and exchange its code from "the app", sign out. No
# browser, no Node: this is the headless registry's own check.
set -euo pipefail
cd "$(cd "$(dirname "$0")/../.." && pwd)"
PORT="${AGENTRY_ACCEPT_PORT:-$(python3 -c "import socket; s=socket.socket(); s.bind(('127.0.0.1',0)); print(s.getsockname()[1]); s.close()")}"
echo "== core UI acceptance =="
if [ -z "${AGENTRY_TEST_DATABASE_URL:-}" ]; then
  ./scripts/dev/pg.sh up
  AGENTRY_TEST_DATABASE_URL="$(./scripts/dev/pg.sh test-url)"
  export AGENTRY_TEST_DATABASE_URL
fi
make build >/dev/null
# A throwaway server: dev mode, opted in (DEV-116).
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
HANDLE="uiacc$SFX"; PASS="hunter2hunter2"
curl -fsS -o /dev/null -X POST "$BASE/api/v1/auth/register" -H 'Content-Type: application/json' \
  -d "{\"handle\":\"$HANDLE\",\"email\":\"$HANDLE@example.test\",\"password\":\"$PASS\"}"
echo "register: OK ($HANDLE)"
csrf() { awk '$6=="agentry_csrf"{print $7}' "$JAR" | tail -1; }
loc=$(curl -sS -o /dev/null -w '%{redirect_url}' -c "$JAR" -b "$JAR" -H 'Sec-Fetch-Site: same-origin' \
  --data-urlencode "login=$HANDLE" --data-urlencode "password=$PASS" --data-urlencode "next=/ui/account" "$BASE/ui/login")
[ "$loc" = "$BASE/ui/account" ] || { echo "sign-in: redirect $loc"; exit 1; }
[ -n "$(csrf)" ] || { echo "sign-in: no csrf cookie"; exit 1; }
echo "sign-in form: OK"
curl -fsS -b "$JAR" "$BASE/ui/account" | grep "$HANDLE" >/dev/null && echo "account page: OK"
# Organizations (agentry#363): the create form, then the decommission form.
# Creating one needs a verified address, and the verification token never
# leaves the server, so the address is marked verified directly, as
# m3-cli.sh does — through the Go toolchain rather than psql.
go run ./scripts/dev/dbexec "UPDATE users SET email_verified_at = now() WHERE id = (SELECT id FROM handles WHERE handle = '$HANDLE')" >/dev/null
ORG="uiorg$SFX"
loc=$(curl -sS -o /dev/null -w '%{redirect_url}' -b "$JAR" -c "$JAR" -H 'Sec-Fetch-Site: same-origin' --data-urlencode "_csrf=$(csrf)" \
  --data-urlencode "handle=$ORG" --data-urlencode "displayName=Acceptance Org" "$BASE/ui/orgs")
[ "$loc" = "$BASE/ui/orgs/$ORG" ] || { echo "create org form: redirect $loc"; exit 1; }
curl -fsS -b "$JAR" -c "$JAR" "$BASE/ui/orgs/$ORG" | grep "Acceptance Org" >/dev/null && echo "org created from the form: OK"
loc=$(curl -sS -o /dev/null -w '%{redirect_url}' -b "$JAR" -c "$JAR" -H 'Sec-Fetch-Site: same-origin' --data-urlencode "_csrf=$(csrf)" \
  --data-urlencode "section=decommission" --data-urlencode "confirm=$ORG" "$BASE/ui/orgs/$ORG")
[ "$loc" = "$BASE/ui/orgs/$ORG" ] || { echo "decommission form: redirect $loc"; exit 1; }
curl -fsS -b "$JAR" -c "$JAR" "$BASE/ui/orgs/$ORG" | grep "being decommissioned" >/dev/null && echo "org decommissioned from the form: OK"
curl -fsS -b "$JAR" -H 'Sec-Fetch-Site: same-origin' --data-urlencode "_csrf=$(csrf)" --data-urlencode "action=create" \
  --data-urlencode "name=acceptance" --data-urlencode "scopes=agent:read" "$BASE/ui/account/tokens" | grep "agy_" >/dev/null && echo "token shown once: OK"
curl -fsS -b "$JAR" "$BASE/ui/account/tokens" | grep "acceptance" >/dev/null && echo "token listed: OK"
# The hosted-run scopes are on the form and travel to the token (agentry#348).
curl -fsS -b "$JAR" "$BASE/ui/account/tokens" | grep 'value="run:write"' >/dev/null && echo "run scopes offered: OK"
curl -fsS -b "$JAR" -H 'Sec-Fetch-Site: same-origin' --data-urlencode "_csrf=$(csrf)" --data-urlencode "action=create" \
  --data-urlencode "name=acceptance-run" --data-urlencode "scopes=run:read" --data-urlencode "scopes=run:write" "$BASE/ui/account/tokens" | grep "agy_" >/dev/null && echo "run-scoped token shown once: OK"
curl -fsS -b "$JAR" "$BASE/ui/account/tokens" | grep "run:read run:write" >/dev/null && echo "run-scoped token listed with its scopes: OK"
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
code=$(curl -sS -o /dev/null -w '%{http_code}' -b "$JAR" "$BASE/ui/account")
[ "$code" = "303" ] && echo "sign-out: OK"
echo "== core UI acceptance PASSED =="
