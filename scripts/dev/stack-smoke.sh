#!/usr/bin/env bash
# End-to-end smoke for the containerized dev stack: register → email verify
# (REAL email, read back from mailpit) → PAT → create agent → git push + tag
# → publish through the real pipeline → resolve → download (S3/minio path).
set -euo pipefail
API=http://localhost:8080/api/v1
GITBASE=http://localhost:8080
MAILPIT=http://localhost:8025
SFX=$(date +%s | tail -c 6)
H="smoke$SFX"; E="$H@dev.local"; PW="devsmoke-pass-$SFX"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
jf() { python3 -c "import sys,json;print(json.load(sys.stdin)$1)"; }

echo "== register $H =="
curl -fsS -X POST "$API/auth/register" -H 'Content-Type: application/json' \
  -d "{\"handle\":\"$H\",\"email\":\"$E\",\"password\":\"$PW\"}" >/dev/null

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

echo "== login + mint PAT =="
CSRF=$(curl -fsS -c "$TMP/jar" -X POST "$API/auth/login" -H 'Content-Type: application/json' \
  -d "{\"login\":\"$H\",\"password\":\"$PW\"}" | jf "['csrfToken']")
PAT=$(curl -fsS -b "$TMP/jar" -H "X-Agentry-CSRF: $CSRF" -X POST "$API/user/tokens" \
  -H 'Content-Type: application/json' \
  -d '{"name":"stack-smoke","scopes":["agent:publish","agent:read","repo:read","repo:write","user:profile"]}' \
  | jf "['token']")

echo "== create private agent + push content + tag =="
curl -fsS -H "Authorization: Bearer $PAT" -X POST "$API/agents" -H 'Content-Type: application/json' \
  -d "{\"namespace\":\"$H\",\"name\":\"hello-dev\",\"kind\":\"skill\",\"visibility\":\"private\",\"summary\":\"container stack smoke\"}" >/dev/null
git init -q "$TMP/w" && cd "$TMP/w"
git -c init.defaultBranch=main checkout -qb main 2>/dev/null || true
cat > agent.yaml <<YAML
schemaVersion: "1"
name: hello-dev
namespace: $H
kind: skill
version: 0.1.0
summary: "container stack smoke"
entrypoints:
  skill: SKILL.md
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
if echo "$SUB" | grep -q "already exists"; then echo "  (tag push already auto-submitted — immutability refusal is correct)";
elif ! echo "$CODE" | grep -q '^2'; then echo "FAIL: submit returned $CODE:"; echo "$SUB" | sed '$d' | head -c 600; exit 1; fi
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
echo "$RES" | grep -q "$D" && echo "download digest matches resolve: OK" || { echo "FAIL: digest mismatch"; exit 1; }
echo "== report card =="
curl -fsS -H "Authorization: Bearer $PAT" "$API/agents/$H/hello-dev/versions/0.1.0/report" | python3 -c "
import sys,json; r=json.load(sys.stdin)
print('scan status:', r.get('scanStatus'), '| findings:', r.get('findingCounts'), '| ruleset:', r.get('rulesetVersion'))"
echo "SMOKE PASSED"
