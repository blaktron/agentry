#!/usr/bin/env bash
# End-to-end smoke for the containerized dev stack: an account and its
# session → activation by email (REAL email, read back from mailpit) → PAT →
# create agent → git push + tag → publish through the real pipeline →
# resolve → download (S3/minio path). The server keeps no password, and the
# stack has no OpenID provider to sign in at, so the account and its session
# are written into the stack's database as the sign-in callback writes them.
set -euo pipefail
API=http://localhost:8080/api/v1
GITBASE=http://localhost:8080
MAILPIT=http://localhost:8025
SFX=$(date +%s | tail -c 6)
H="smoke$SFX"; E="$H@dev.local"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
jf() { python3 -c "import sys,json;print(json.load(sys.stdin)$1)"; }

COMPOSE="${COMPOSE:-docker compose --project-directory $(cd "$(dirname "$0")/../../deploy/compose" && pwd)}"
SESSION="agys_$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
CSRF="csrf_$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
echo "== account $H, unconfirmed, signed in =="
$COMPOSE exec -T postgres psql -U agentry -d agentry_dev -qAt -v ON_ERROR_STOP=1 >/dev/null <<SQL
INSERT INTO handles (id, handle, kind) VALUES (gen_random_uuid(), '$H', 'user');
INSERT INTO users (id, email, display_name) SELECT id, '$E', '$H' FROM handles WHERE handle = '$H';
INSERT INTO sessions (id, user_id, token_sha256, csrf_token, expires_at)
  SELECT gen_random_uuid(), id, sha256(convert_to('$SESSION', 'UTF8')), '$CSRF', now() + interval '1 hour' FROM handles WHERE handle = '$H';
SQL
curl -fsS -b "agentry_session=$SESSION" -H "X-Agentry-CSRF: $CSRF" -X POST "$API/user/email-verification" -o /dev/null -w 'activation link: %{http_code}\n'

echo "== pull the verification token out of the real email (mailpit) =="
TOKEN=""
for i in $(seq 1 20); do
  sleep 1
  MID=$(curl -fsS "$MAILPIT/api/v1/search?query=to:$E" | python3 -c "
import sys,json
m=json.load(sys.stdin).get('messages') or []
print(m[0]['ID'] if m else '')")
  [ -n "$MID" ] || continue
  TOKEN=$(curl -fsS "$MAILPIT/api/v1/message/$MID" | python3 -c "
import sys,json,re
d=json.load(sys.stdin); body=(d.get('Text') or '')+' '+(d.get('HTML') or '')
m=re.search(r'token=([A-Za-z0-9._~-]{16,})', body) or re.search(r'\b([A-Za-z0-9_-]{24,})\b', body)
print(m.group(1) if m else '')")
  [ -n "$TOKEN" ] && break
done
[ -n "$TOKEN" ] || { echo "FAIL: no verification email/token in mailpit"; exit 1; }
curl -fsS -X POST "$API/auth/verify-email" -H 'Content-Type: application/json' \
  -d "{\"token\":\"$TOKEN\"}" -o /dev/null -w 'verify-email: %{http_code}\n'

echo "== mint PAT =="
PAT=$(curl -fsS -b "agentry_session=$SESSION" -H "X-Agentry-CSRF: $CSRF" -X POST "$API/user/tokens" \
  -H 'Content-Type: application/json' \
  -d '{"name":"stack-smoke","scopes":["agent:publish","agent:read","repo:read","repo:write","user:profile"]}' \
  | jf "['token']")

echo "== create private agent + push content + tag =="
curl -fsS -H "Authorization: Bearer $PAT" -X POST "$API/agents" -H 'Content-Type: application/json' \
  -d "{\"namespace\":\"$H\",\"name\":\"hello-dev\",\"modes\":[\"autonomous\"],\"visibility\":\"private\",\"summary\":\"container stack smoke\"}" >/dev/null
git init -q "$TMP/w" && cd "$TMP/w"
git -c init.defaultBranch=main checkout -qb main 2>/dev/null || true
cat > agent.yaml <<YAML
schemaVersion: "2"
name: hello-dev
namespace: $H
modes: [autonomous]
version: 0.1.0
summary: "container stack smoke"
entrypoints:
  instruction: SKILL.md
capabilities: {}
publish:
  include: [agent.yaml, SKILL.md]
YAML
printf '# hello-dev\n\nSay hello politely in dev-stack smoke tests.\n' > SKILL.md
git add . && git -c user.email=smoke@dev.local -c user.name=smoke commit -qm 'v0.1.0'
git tag v0.1.0
git push -q "http://pat:$PAT@localhost:8080/$H/hello-dev.git" main v0.1.0

echo "== submit + poll the real pipeline =="
SUB=$(curl -sS -w '\n%{http_code}' -H "Authorization: Bearer $PAT" -X POST "$API/agents/$H/hello-dev/versions" \
  -H 'Content-Type: application/json' -d '{"tag":"v0.1.0"}')
CODE=$(echo "$SUB" | tail -1)
# The v* tag push auto-submits (agents.auto_publish_tags); an explicit POST
# after it is then a duplicate that V3 immutability rightly refuses.
if grep -q "already exists" <<<"$SUB"; then echo "  (tag push already auto-submitted — immutability refusal is correct)";
elif ! grep -q '^2' <<<"$CODE"; then echo "FAIL: submit returned $CODE:"; echo "$SUB" | sed '$d' | head -c 600; exit 1; fi
STATUS=""
for i in $(seq 1 30); do
  sleep 2
  STATUS=$(curl -fsS -H "Authorization: Bearer $PAT" "$API/agents/$H/hello-dev/versions/0.1.0" | jf "['status']")
  echo "  status: $STATUS"
  case "$STATUS" in published|rejected|needs_review) break;; esac
done
[ "$STATUS" = published ] || { echo "FAIL: version ended as $STATUS"; \
  curl -fsS -H "Authorization: Bearer $PAT" "$API/agents/$H/hello-dev/versions/0.1.0/report" | head -c 800; exit 1; }

echo "== resolve + download (exercises the minio-backed S3 store) =="
RES=$(curl -fsS -H "Authorization: Bearer $PAT" "$API/resolve?ref=$H/hello-dev@0.1.0")
echo "$RES" | jf "['digest']"
curl -fsS -H "Authorization: Bearer $PAT" -o "$TMP/a.tar.zst" "$API/agents/$H/hello-dev/versions/0.1.0/download"
D=$(sha256sum "$TMP/a.tar.zst" | cut -d' ' -f1)
grep -q "$D" <<<"$RES" && echo "download digest matches resolve: OK" || { echo "FAIL: digest mismatch"; exit 1; }
echo "== report card =="
curl -fsS -H "Authorization: Bearer $PAT" "$API/agents/$H/hello-dev/versions/0.1.0/report" | python3 -c "
import sys,json; r=json.load(sys.stdin)
print('scan status:', r.get('scanStatus'), '| findings:', r.get('findingCounts'), '| ruleset:', r.get('rulesetVersion'))"
echo "SMOKE PASSED"
