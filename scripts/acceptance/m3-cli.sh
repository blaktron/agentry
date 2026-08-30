#!/usr/bin/env bash
# M3 CLI acceptance (WG-F, PLAN §11/§18.2): boots a real agentryd against
# local Postgres, then drives the agentry CLI end to end:
#   login (PAT via stdin) → init → validate → publish (cli-upload source) →
#   install --target=claude-skill → verify → yank → yanked-range exclusion.
set -euo pipefail
cd "$(cd "$(dirname "$0")/../.." && pwd)"
export PATH=/opt/homebrew/bin:$PATH
ROOT="$(pwd)"

./scripts/dev/pg.sh up
DB_URL="$(./scripts/dev/pg.sh url)"

# psql, for the documented email-verification shortcut (same binary discovery
# as scripts/dev/pg.sh).
PGBIN="${PGBIN:-}"
if [ -z "$PGBIN" ]; then
  for cand in /opt/homebrew/opt/postgresql@16/bin /usr/local/opt/postgresql@16/bin; do
    [ -x "$cand/psql" ] && PGBIN="$cand" && break
  done
fi
[ -n "$PGBIN" ] || { echo "psql not found; install postgresql@16 or set PGBIN" >&2; exit 1; }

TMP="$(mktemp -d)"
SERVER_PID=""
cleanup() {
  if [ -n "$SERVER_PID" ]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT

PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
BASE="http://127.0.0.1:$PORT"
API="$BASE/api/v1"

echo "== build agentryd + agentry =="
go build -o "$TMP/agentryd" ./cmd/agentryd
cp "$(./scripts/dev/cli-bin.sh)" "$TMP/agentry"
AGENTRY="$TMP/agentry"

echo "== boot agentryd all on $BASE =="
mkdir -p "$TMP/storage" "$TMP/git"
# Acceptance traffic is a tight scripted loop from one IP; the real §19
# limits are exercised by m1.sh, not here.
AGENTRY_LIMITS_AUTHED_BURST_PER_MIN="100000" \
AGENTRY_LIMITS_AUTHED_PER_HOUR="1000000" \
AGENTRY_LIMITS_ANONYMOUS_PER_MIN="100000" \
AGENTRY_LIMITS_LOGIN_PER_MIN="1000" \
AGENTRY_HTTP_ADDR="127.0.0.1:$PORT" \
AGENTRY_DATABASE_URL="$DB_URL" \
AGENTRY_STORAGE_LOCAL_DIR="$TMP/storage" \
AGENTRY_GIT_DATA_DIR="$TMP/git" \
AGENTRY_BASE_URL="$BASE" \
AGENTRY_LOG_LEVEL=warn \
"$TMP/agentryd" all >"$TMP/server.log" 2>&1 &
SERVER_PID=$!

healthy=""
for _ in $(seq 1 120); do
  if curl -fsS "$BASE/healthz" >/dev/null 2>&1; then healthy=1; break; fi
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "server exited early:"; tail -50 "$TMP/server.log"; exit 1
  fi
  sleep 0.5
done
[ -n "$healthy" ] || { echo "server never became healthy:"; tail -50 "$TMP/server.log"; exit 1; }

SFX="$(python3 -c 'import secrets; print(secrets.token_hex(3))')"
HANDLE="m3cli$SFX"
EMAIL="$HANDLE@example.test"
PASSWORD="m3cli-pass-123456"
NAME="hello-skill"

jsonfield() { python3 -c 'import sys,json; print(json.load(sys.stdin)[sys.argv[1]])' "$1"; }

echo "== register user $HANDLE =="
curl -fsS -X POST "$API/auth/register" -H 'Content-Type: application/json' \
  -d "{\"handle\":\"$HANDLE\",\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" >/dev/null

# Documented shortcut: the verification token only leaves the server through
# the (dev no-op) email notifier, so mark the address verified directly —
# exactly what the server's own test suite does. Publishing requires it.
"$PGBIN/psql" "$DB_URL" -qAt -v ON_ERROR_STOP=1 \
  -c "UPDATE users SET email_verified_at = now() WHERE id = (SELECT id FROM handles WHERE handle = '$HANDLE')" >/dev/null

echo "== login (session) + mint PAT =="
CSRF="$(curl -fsS -c "$TMP/cookies" -X POST "$API/auth/login" -H 'Content-Type: application/json' \
  -d "{\"login\":\"$HANDLE\",\"password\":\"$PASSWORD\"}" | jsonfield csrfToken)"
PAT="$(curl -fsS -b "$TMP/cookies" -X POST "$API/user/tokens" \
  -H 'Content-Type: application/json' -H "X-Agentry-CSRF: $CSRF" \
  -d '{"name":"m3-cli","scopes":["agent:publish","agent:read","repo:read","repo:write","user:profile"]}' \
  | jsonfield token)"

# CLI credential/config isolation: config under $TMP, OS keychain untouched.
export AGENTRY_CONFIG_DIR="$TMP/config"
export AGENTRY_NO_KEYRING=1

echo "== agentry login (PAT fed via stdin; config-file fallback) =="
# grep -q on a live pipe would close it early and SIGPIPE the CLI under
# pipefail, so every assertion greps a captured file instead.
printf '%s\n' "$PAT" | "$AGENTRY" login --registry "$BASE" >"$TMP/login.out" 2>&1
grep -q "logged in to $BASE as $HANDLE" "$TMP/login.out" || { echo "login did not confirm the handle"; cat "$TMP/login.out"; exit 1; }

# The rest also exercises the AGENTRY_TOKEN env override (CI credential path).
export AGENTRY_TOKEN="$PAT"

echo "== agentry init =="
"$AGENTRY" init --kind=skill --namespace "$HANDLE" --name "$NAME" "$TMP/$NAME"

echo "== agentry validate (offline D-12 parity, embedded-rules dir) =="
AGENTRY_RULES_DIR="$ROOT/rules" "$AGENTRY" validate "$TMP/$NAME"

echo "== create agent via API =="
curl -fsS -X POST "$API/agents" -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $PAT" \
  -d "{\"namespace\":\"$HANDLE\",\"name\":\"$NAME\",\"kind\":\"skill\",\"visibility\":\"public\"}" >/dev/null

echo "== agentry publish (cli-upload source) =="
"$AGENTRY" publish --registry "$BASE" "$TMP/$NAME" | tee "$TMP/publish.out"
grep -q "published $HANDLE/$NAME@0.1.0" "$TMP/publish.out" || { echo "publish did not reach published"; exit 1; }

echo "== agentry install --target=claude-skill =="
"$AGENTRY" install --registry "$BASE" "$HANDLE/$NAME" --target=claude-skill --dir "$TMP/skills" --yes
test -f "$TMP/skills/$NAME/SKILL.md"  || { echo "SKILL.md missing after install"; exit 1; }
test -f "$TMP/skills/$NAME/agent.yaml" || { echo "agent.yaml missing after install"; exit 1; }
head -1 "$TMP/skills/$NAME/SKILL.md" | grep -q '^---$' || { echo "installed SKILL.md lacks YAML frontmatter"; exit 1; }

echo "== agentry info + search =="
"$AGENTRY" info --registry "$BASE" "$HANDLE/$NAME" >"$TMP/info.out"
cat "$TMP/info.out"
grep -q "latest:  0.1.0" "$TMP/info.out" || { echo "info missing latest version"; exit 1; }
"$AGENTRY" search --registry "$BASE" "$HANDLE" >"$TMP/search.out"
grep -q "$HANDLE/$NAME" "$TMP/search.out" || { echo "search missing the agent"; exit 1; }

echo "== agentry verify (digest, exit code for CI) =="
"$AGENTRY" verify --registry "$BASE" "$HANDLE/$NAME@0.1.0" | tee "$TMP/verify.out"
grep -q "digest: PASS" "$TMP/verify.out" || { echo "verify did not PASS"; exit 1; }

echo "== agentry yank =="
"$AGENTRY" yank --registry "$BASE" "$HANDLE/$NAME@0.1.0" --reason "m3-cli acceptance cleanup"

# §5.5: yanked versions leave range resolution — a rangeless install must fail.
if "$AGENTRY" install --registry "$BASE" "$HANDLE/$NAME" --target=claude-skill --dir "$TMP/skills2" --yes >/dev/null 2>&1; then
  echo "install of a fully-yanked agent unexpectedly succeeded"; exit 1
fi
echo "yanked version excluded from range resolution: OK"

echo "== M3 CLI acceptance PASSED =="
