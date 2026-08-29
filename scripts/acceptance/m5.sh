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

# 3. Web app typecheck, unit tests, and production build.
if [ ! -d web/node_modules ]; then (cd web && npm install --silent); fi
(cd web && npx tsc --noEmit) && echo "web typecheck: OK"
(cd web && npx vitest run >/tmp/agentry-m5-vitest.log 2>&1) \
  && echo "web unit tests (safeNext, invisible-char list, capability diff): OK" \
  || { echo "web unit tests FAILED"; tail -30 /tmp/agentry-m5-vitest.log; exit 1; }
(cd web && npm run build >/tmp/agentry-m5-build.log 2>&1) \
  && echo "web production build: OK" \
  || { echo "web build FAILED"; tail -20 /tmp/agentry-m5-build.log; exit 1; }

# 3b. Both theme palettes survive the Tailwind build (B-17). @theme is a
#     build-time token table, so a dark block nested inside a media query
#     overwrites the light values instead of overriding them — the symptom is
#     exactly one :root and a dark page for light-mode users.
CSS=$(ls web/.next/static/chunks/*.css 2>/dev/null | head -1)
[ -n "$CSS" ] || { echo "no compiled CSS found"; exit 1; }
python3 - "$CSS" <<'PY'
import re, sys
css = open(sys.argv[1]).read()
values = re.findall(r"--color-bg:\s*([^;}]+)", css)
if len(values) < 2:
    print(f"  theme palettes: FAILED — --color-bg defined {len(values)} time(s): {values}")
    sys.exit(1)
if "prefers-color-scheme" not in css:
    print("  theme palettes: FAILED — no prefers-color-scheme block")
    sys.exit(1)
missing = [t for t in ("--color-sev-critical", "--color-sev-low", "--color-sev-info")
           if f"{t}:" not in css]
if missing:
    print(f"  severity tokens: FAILED — tree-shaken out of the build: {missing}")
    sys.exit(1)
print(f"  light + dark palettes both present ({', '.join(v.strip() for v in values)}): OK")
print("  per-severity tokens survive tree-shaking: OK")
PY

# 4. Live SSR smoke: boot the API + web, publish an agent, assert the agent
#    page server-renders its capability contract and report card.
PORT=8199
WEBPORT=3099
WORK=$(mktemp -d)
DB="$(./scripts/dev/pg.sh url)"
make build >/dev/null
# Acceptance traffic is a tight scripted loop from one IP; the real §19
# limits are exercised by m1.sh, not here.
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
tags: [acceptance, summarize]
entrypoints:
  skill: SKILL.md
capabilities:
  network:
    egress: [api.example.com]
  secrets: [DEMO_TOKEN]
dependencies:
  agents:
    - ref: acme/formatter
      version: "^1.2"
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
# The trending list itself is asserted through /search?sort=installs below:
# the home page's own fetch is cached for five minutes and this script polls
# "/" before publishing anything, so the section heading is what is stable
# here, not its contents.
check "http://localhost:$WEBPORT/"                          "Most installed this month" "home page (featured/trending section)"
check "http://localhost:$WEBPORT/search?q=demo"             "demo-skill"             "search results"
check "http://localhost:$WEBPORT/$H/demo-skill"             "Declared capabilities"  "agent page (capability contract)"
check "http://localhost:$WEBPORT/$H/demo-skill"             "Security report"        "agent page (report card)"
check "http://localhost:$WEBPORT/$H/demo-skill"             "api.example.com"        "agent page (egress host)"
check "http://localhost:$WEBPORT/$H/demo-skill/versions/1.0.0" "Provenance"          "version page (provenance)"
check "http://localhost:$WEBPORT/$H"                        "demo-skill"             "namespace page"
check "http://localhost:$WEBPORT/trust"                     "does not guarantee"     "trust page"
check "http://localhost:$WEBPORT/docs"                      "publish.include"        "docs page"
check "http://localhost:$WEBPORT/advisories"                "quarantined"            "advisories page"

# §10.2 elements added in wave 2. Each of these was claimed by page copy or
# by the plan before it was rendered; they are asserted individually so a
# regression names the missing element rather than "the agent page changed".
echo "§10.2 agent-page elements:"
check "http://localhost:$WEBPORT/$H/demo-skill"             "Scanned"                "agent page (scan date on report card)"
check "http://localhost:$WEBPORT/$H/demo-skill"             "/tags/acceptance"       "agent page (tag chips link to /tags)"
check "http://localhost:$WEBPORT/$H/demo-skill"             "acme/formatter"         "agent page (dependency list)"
check "http://localhost:$WEBPORT/$H/demo-skill"             "target=mcp"             "agent page (install target selector)"
check "http://localhost:$WEBPORT/$H/demo-skill"             "Star this agent"        "agent page (star control)"
check "http://localhost:$WEBPORT/$H/demo-skill"             "Installs"               "agent page (stats panel)"
check "http://localhost:$WEBPORT/$H/demo-skill?target=mcp"  "target=mcp"             "agent page (target=mcp renders)"
check "http://localhost:$WEBPORT/$H/demo-skill/versions/1.0.0" "Signing key"         "version page (provenance key id)"
check "http://localhost:$WEBPORT/$H/demo-skill/versions/1.0.0" "Dependencies"        "version page (dependency list)"
check "http://localhost:$WEBPORT/tags/acceptance"           "demo-skill"             "tag page lists the agent"
check "http://localhost:$WEBPORT/search"                    "verified organizations" "search (verified facet control)"
check "http://localhost:$WEBPORT/search"                    "Capability"             "search (capability facet control)"
check "http://localhost:$WEBPORT/search"                    "Apache-2.0"             "search (license facet counts)"
check "http://localhost:$WEBPORT/search?sort=installs"      "demo-skill"             "search (sort=installs)"
check "http://localhost:$WEBPORT/login"                     "company account"        "login (org SSO entry point)"

# CSP + hydration (B-01). `script-src 'self'` with no nonce blocks Next's own
# inline bootstrap: the flight payload never executes, every route throws
# React #412, and no client component ever mounts. The policy must therefore
# carry a per-request nonce AND every script tag must be stamped with it.
echo "CSP nonce + hydration (§10.3, B-01):"
curl -fsSI "http://localhost:$WEBPORT/" | grep -i '^content-security-policy:' \
  | grep -q "script-src 'self' 'nonce-" \
  && echo "  CSP carries a per-request script nonce: OK" \
  || { echo "  CSP nonce: FAILED (header has no nonce)"; exit 1; }
curl -fsS -D "$WORK/head.txt" -o "$WORK/home.html" "http://localhost:$WEBPORT/"
python3 - "$WORK/head.txt" "$WORK/home.html" <<'PY'
import re, sys
head = open(sys.argv[1]).read()
html = open(sys.argv[2]).read()
m = re.search(r"'nonce-([^']+)'", head)
if not m:
    print("  hydration: FAILED — no nonce in the CSP header"); sys.exit(1)
nonce = m.group(1)
tags = re.findall(r"<script\b[^>]*>", html)
if not tags:
    print("  hydration: FAILED — no script tags served at all"); sys.exit(1)
missing = [t for t in tags if f'nonce="{nonce}"' not in t]
if missing:
    print(f"  hydration: FAILED — {len(missing)}/{len(tags)} script tags lack the nonce: {missing[:2]}")
    sys.exit(1)
if "self.__next_f.push" not in html:
    print("  hydration: FAILED — no flight payload in the document"); sys.exit(1)
print(f"  every script tag ({len(tags)}) carries the CSP nonce: OK")
print("  flight payload present (React can hydrate): OK")
PY

# Two more CSP invariants the nonce move must not have loosened.
curl -fsSI "http://localhost:$WEBPORT/" | grep -i '^content-security-policy:' \
  | grep -q "frame-ancestors 'none'" \
  && echo "  other CSP directives preserved: OK" \
  || { echo "  CSP directives: FAILED (frame-ancestors lost)"; exit 1; }
curl -fsSI "http://localhost:$WEBPORT/" | grep -qi '^x-content-type-options: nosniff' \
  && echo "  static security headers still applied: OK" \
  || { echo "  static headers: FAILED"; exit 1; }

# Open redirect (B-16): the sign-in form must not bounce to another origin.
LOC=$(curl -fsS -o /dev/null -w '%{redirect_url}' -X POST "http://localhost:$WEBPORT/login/submit" \
  --data-urlencode "login=nobody" --data-urlencode "password=wrongwrongwrong" \
  --data-urlencode "next=//evil.example")
echo "$LOC" | grep -q "evil.example" \
  && { echo "  open redirect: FAILED — //evil.example survived into $LOC"; exit 1; } \
  || echo "  scheme-relative ?next rejected (B-16): OK"

# 5. Structural accessibility on the public pages. Not a full Lighthouse run,
#    but it gates the regressions that actually happen: a lost landmark, a
#    second h1, an unlabelled search input, a nameless link.
echo "accessibility (landmarks, heading order, labels, link names):"
python3 ./scripts/dev/a11y-check.py \
  "http://localhost:$WEBPORT/" \
  "http://localhost:$WEBPORT/search" \
  "http://localhost:$WEBPORT/trust" \
  "http://localhost:$WEBPORT/docs" \
  "http://localhost:$WEBPORT/advisories" \
  "http://localhost:$WEBPORT/login" \
  "http://localhost:$WEBPORT/login/challenge" \
  "http://localhost:$WEBPORT/tags/acceptance" \
  "http://localhost:$WEBPORT/$H/demo-skill" \
  "http://localhost:$WEBPORT/$H/demo-skill?target=mcp" \
  "http://localhost:$WEBPORT/$H/demo-skill/versions/1.0.0"

echo "== M5 acceptance PASSED =="
