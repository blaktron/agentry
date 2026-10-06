#!/usr/bin/env bash
# Terms of Service step acceptance, the directory's half (agentry#788).
#
# The sign-up's terms step and its optional display name are configuration
# the directory applies: a prompt stage after the form, shown only where the
# server's AGENTRY_DIRECTORY_TERMS_FILE names an HTML fragment; a validation
# policy that refuses a submission without the agreement, or without terms it
# could read; and a policy on the enrolment write that records the version
# and the time, and gives a blank display name the username. This proves it
# against the image the compose file pins, on a throwaway directory:
#
#   1. On (a fixture terms file named): the display name is optional; the
#      terms step follows the form with the file's text; an unticked
#      agreement is refused; a ticked one reaches the authenticator setup
#      with no mail step (agentry#861); the
#      accounts record agreement, version and time, a blank name became the
#      username as typed while the username was written lower-cased
#      (agentry#856), a typed name and a promo code were kept, and the text
#      shown was not stored.
#   2. Unreadable (the file not UTF-8, then removed): the step says the
#      terms could not be loaded and refuses the sign-up. Not UTF-8 is the
#      case that once fell through: the expression raised, authentik showed
#      its source, and the source matched a loose version pattern.
#   3. Off (the server and the worker recreated without either variable:
#      no terms, and registry activation off): the form leads straight to
#      the directory's confirmation mail and the account is written
#      inactive, as before agentry#861 (DEV-197). That is production's path
#      until its chart turns registry activation on (agentry-web#972).
#   4. The email claim (agentry#861): the agentry-verified-email mapping
#      says email_verified false for a fresh sign-up, true once the
#      registry confirms its subject and address, and true for an account
#      from before (no attribute). Refused/unreachable checks fail closed.
#
# The scroll gate is page script and is checked in a browser, not here.
# Needs docker, the pinned images and outbound HTTPS from the directory (the
# CAPTCHA's siteverify with Cloudflare's test keys), nothing else. Files go
# in with docker cp, not bind mounts, as in directory-promo.sh.
set -euo pipefail
cd "$(cd "$(dirname "$0")/../.." && pwd)"
echo "== directory terms of service acceptance =="
source scripts/acceptance/directory-resources.sh

COMPOSE=deploy/compose/docker-compose.yaml
IMAGE="${AUTHENTIK_IMAGE:-$(awk '/image: ghcr.io\/goauthentik\/server:/{print $2; exit}' "$COMPOSE")}"
PG_IMAGE=$(awk '/image: postgres:/{print $2; exit}' "$COMPOSE")
REDIS_IMAGE=$(awk '/image: redis:/{print $2; exit}' "$COMPOSE")
PY_IMAGE="${PY_IMAGE:-python:3.12-slim}"
[ -n "$IMAGE" ] || { echo "FAIL: no authentik image is pinned in $COMPOSE"; exit 1; }

P="dt-$(openssl rand -hex 4)"
NET="$P-net"
AK="$P-ak-server"
WORKER="$P-ak-worker"
DRIVER="$P-driver"
FIXTURE=$(mktemp)
cleanup() {
  docker rm -fv "$P-pg" "$P-redis" "$AK" "$WORKER" "$DRIVER" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -f "$FIXTURE"
}
trap cleanup EXIT

# A terms file long enough to scroll, in the shape a deployment mounts: an
# HTML fragment whose root names its version.
VERSION="2026-09-30-fixture-$(openssl rand -hex 2)"
{
  echo "<article data-terms-version=\"$VERSION\"><h1>Fixture terms</h1>"
  for i in $(seq 1 40); do echo "<h2 id=\"c$i\">Fixture clause $i</h2><p>The fixture's clause $i says one thing.</p>"; done
  echo "</article>"
} >"$FIXTURE"
# mktemp makes it 0600, docker cp keeps the mode and the owner, and the
# directory runs as uid 1000: a fixture only its writer can read would fail
# closed for the wrong reason (it did, on a runner whose user is root).
chmod 0644 "$FIXTURE"
TERMS_PATH=/templates/agentry-terms-fixture.html

PG_PW=$(openssl rand -hex 16)
docker network create "${DIRECTORY_DOCKER_LABELS[@]}" "$NET" >/dev/null
docker run -d "${DIRECTORY_DOCKER_LABELS[@]}" --name "$P-pg" --network "$NET" --network-alias dt-pg \
  -e POSTGRES_PASSWORD="$PG_PW" -e POSTGRES_USER=authentik -e POSTGRES_DB=authentik "$PG_IMAGE" >/dev/null
docker run -d "${DIRECTORY_DOCKER_LABELS[@]}" --name "$P-redis" --network "$NET" --network-alias dt-redis "$REDIS_IMAGE" >/dev/null
AK_ENV=(
  -e AUTHENTIK_SECRET_KEY="$(openssl rand -hex 32)"
  -e AUTHENTIK_POSTGRESQL__HOST=dt-pg -e AUTHENTIK_POSTGRESQL__USER=authentik
  -e AUTHENTIK_POSTGRESQL__NAME=authentik -e AUTHENTIK_POSTGRESQL__PASSWORD="$PG_PW"
  -e AUTHENTIK_REDIS__HOST=dt-redis -e AUTHENTIK_ERROR_REPORTING__ENABLED=false
  -e AUTHENTIK_LOG_LEVEL=warning
  -e AGENTRY_ACCOUNT_URL=http://registry.test/settings -e AGENTRY_PUBLIC_WEB_URL=http://registry.test
  -e AGENTRY_IDP_TRUST_CHECK_TOKEN="$(openssl rand -hex 32)" -e AGENTRY_REGISTRY_INTERNAL_URL=http://dt-driver:8080
  # The promo field on, so a code typed on the form can be shown to survive
  # the terms step's merge into the same prompt data.
  -e AGENTRY_DIRECTORY_PROMO_FIELD=true
)
# Registry activation (agentry#861): on for every phase but the last, on the
# server (the write's policy reads it) and the worker (the blueprint's
# conditions read it).
ACT=(-e AGENTRY_DIRECTORY_REGISTRY_ACTIVATION=true)
# server <on|off>: the terms setting is read by the server that runs the
# flow, so it changes by recreating the server.
server() {
  local flag=() act=("${ACT[@]}")
  [ "$1" = on ] && flag=(-e AGENTRY_DIRECTORY_TERMS_FILE="$TERMS_PATH")
  [ "$1" = off ] && act=()
  docker rm -fv "$AK" >/dev/null 2>&1 || true
  docker create "${DIRECTORY_DOCKER_LABELS[@]}" --name "$AK" --network "$NET" --network-alias dt-ak-server "${AK_ENV[@]}" "${flag[@]}" "${act[@]}" "$IMAGE" server >/dev/null
  docker cp deploy/compose/authentik/templates/. "$AK:/templates" >/dev/null
  docker cp deploy/compose/authentik/blueprints/. "$AK:/blueprints/custom" >/dev/null
  [ "$1" = on ] && docker cp "$FIXTURE" "$AK:$TERMS_PATH" >/dev/null
  docker start "$AK" >/dev/null
}
server on
# worker <on|off>: the blueprint's activation conditions are read by the
# worker that applies it, so the setting changes by recreating the worker.
worker() {
  local act=("${ACT[@]}")
  [ "$1" = off ] && act=()
  docker rm -fv "$WORKER" >/dev/null 2>&1 || true
  docker create "${DIRECTORY_DOCKER_LABELS[@]}" --name "$WORKER" --network "$NET" "${AK_ENV[@]}" "${act[@]}" "$IMAGE" worker >/dev/null
  docker cp deploy/compose/authentik/templates/. "$WORKER:/templates" >/dev/null
  docker cp deploy/compose/authentik/blueprints/. "$WORKER:/blueprints/custom" >/dev/null
  docker start "$WORKER" >/dev/null
}
worker on

docker create "${DIRECTORY_DOCKER_LABELS[@]}" --name "$DRIVER" --network "$NET" --network-alias dt-driver \
  -e AK=http://dt-ak-server:9000 -e TERMS_VERSION="$VERSION" "$PY_IMAGE" sleep 3600 >/dev/null
docker cp scripts/acceptance/directory-terms.py "$DRIVER:/driver.py" >/dev/null
docker start "$DRIVER" >/dev/null

akshell() { docker exec -i "$@" "$AK" ak shell 2>&1 | grep -vE '^(###|[0-9]+ objects imported|\{")'; }

# applied waits until the terms stage is bound into the enrolment flow, for
# up to $1 seconds.
applied() {
  local deadline=$(( $(date +%s) + $1 )) got=""
  while [ "$(date +%s)" -lt "$deadline" ]; do
    got=$(akshell <<'PY' || true
from authentik.flows.models import FlowStageBinding
print("BOUND", FlowStageBinding.objects.filter(target__slug="agentry-enrollment", stage__name="agentry-enrollment-terms", order=15).exists())
PY
)
    case "$got" in *"BOUND True"*) return 0 ;; esac
    sleep 10
  done
  echo "FAIL: the terms step was not bound: ${got:-no answer}"
  docker logs --tail 20 "$WORKER" 2>&1 | tail -10
  return 1
}
# up waits until the server answers the flow executor, for up to $1 seconds.
up() {
  local deadline=$(( $(date +%s) + $1 ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    docker exec "$DRIVER" python -c "import urllib.request,sys; urllib.request.urlopen('http://dt-ak-server:9000/-/health/ready/', timeout=5)" >/dev/null 2>&1 && return 0
    sleep 5
  done
  echo "FAIL: the server did not come back"; docker logs --tail 20 "$AK" 2>&1 | tail -10; return 1
}

echo "waiting for the directory to boot and apply the blueprints (a few minutes)"
applied 600
up 120
echo "ok   the blueprint applied: the terms step is bound at order 15"

out=$(docker exec "$DRIVER" python /driver.py on) || { echo "$out"; exit 1; }
echo "$out" | grep -v '^ACCOUNTS '
accounts=$(echo "$out" | sed -n 's/^ACCOUNTS //p')

check=$(akshell -e ACCOUNTS="$accounts" -e VERSION="$VERSION" <<'PY' || true
import json, os
from datetime import datetime, timedelta, timezone
from authentik.core.models import User
from authentik.stages.authenticator import devices_for_user
a = json.loads(os.environ["ACCOUNTS"])
for label in ("blank", "named"):
    u = User.objects.get(username=a[label])
    at = u.attributes.get("agentry_terms_accepted_at") or ""
    fresh = bool(at) and datetime.now(timezone.utc) - datetime.fromisoformat(at) < timedelta(minutes=30)
    print("TERMS", label, u.attributes.get("agentry_terms_accepted"), u.attributes.get("agentry_terms_version") == os.environ["VERSION"], fresh)
    print("NAME", label, u.name == a.get(label + "Typed", u.username), repr(u.name))
    print("KEYS", label, sorted(u.attributes))
    print("ACTIVE", label, u.is_active, u.attributes.get("agentry_email_verified"))
    print("DEVICES", label, len(list(devices_for_user(u))))
PY
)
for label in blank named; do
  case "$check" in *"TERMS $label True True True"*) ;; *) echo "FAIL: the $label account's terms record: $check"; exit 1 ;; esac
done
echo "ok   each account records the agreement, the version of the file it was shown, and when"
case "$check" in *"NAME blank True"*) echo "ok   the mixed-case username was written lower-cased, and a blank display name kept the case it was typed in" ;;
  *) echo "FAIL: the blank-name account: $check"; exit 1 ;; esac
case "$check" in *"NAME named False 'Ada Lovelace'"*) echo "ok   a typed display name is kept" ;;
  *) echo "FAIL: the named account: $check"; exit 1 ;; esac
case "$check" in *"KEYS named ['agentry_email_verified', 'agentry_has_password', 'agentry_promo_code', 'agentry_terms_accepted', 'agentry_terms_accepted_at', 'agentry_terms_version']"*)
    echo "ok   the promo code survives beside the terms record, and the text shown is not stored" ;;
  *) echo "FAIL: the named account's attributes: $check"; exit 1 ;; esac

case "$check" in *"ACTIVE blank True False"*"ACTIVE named True False"*) echo "ok   both accounts are written active and unactivated (agentry_email_verified false)" ;;
  *) echo "FAIL: an account is not written active and unactivated: $check"; exit 1 ;; esac
# The named sign-up chose "later" (agentry#894): it is signed in with no
# authenticator, and nothing of the choice is stored (KEYS above).
case "$check" in *"DEVICES named 0"*) echo "ok   the account that skipped the authenticator setup has no authenticator" ;;
  *) echo "FAIL: the account that skipped the setup: $check"; exit 1 ;; esac

# The claim the registry reads (agentry#869): the directory asks the registry.
docker exec -i "$AK" ak shell -c \
  'exec(compile(__import__("sys").stdin.read(), "verification-acceptance", "exec"))' \
  < scripts/acceptance/directory-verification.py

printf '\xff\xfe<article data-terms-version="not-utf8">' | docker exec -i -u 0 "$AK" sh -c "cat > $TERMS_PATH"
out=$(docker exec "$DRIVER" python /driver.py missing) || { echo "FAIL (a terms file that is not UTF-8)"; echo "$out"; exit 1; }
echo "$out (a file that is not UTF-8)"
docker exec -u 0 "$AK" rm -f "$TERMS_PATH"
out=$(docker exec "$DRIVER" python /driver.py missing) || { echo "FAIL (no terms file)"; echo "$out"; exit 1; }
echo "$out (no file at all)"

echo "recreating the server and the worker without the terms setting and with registry activation off"
server off
worker off
up 300
# Discovery applies an unchanged file on its own time; applying it now, in
# the new worker with its own environment, makes the wait below short (as
# directory-promo.sh does). Its failure shows in the wait.
docker exec "$WORKER" ak apply_blueprint custom/agentry-account-flows.yaml >/dev/null 2>&1 || true
# Wait for the mail's binding to come back at 30.
deadline=$(( $(date +%s) + 600 )); bound=""
while [ "$(date +%s)" -lt "$deadline" ]; do
  bound=$(akshell <<'PY' || true
from authentik.flows.models import FlowStageBinding
print("MAIL", FlowStageBinding.objects.filter(target__slug="agentry-enrollment", stage__name="agentry-enrollment-email-confirmation", order=30).exists())
PY
)
  case "$bound" in *"MAIL True"*) break ;; esac
  sleep 10
done
case "$bound" in *"MAIL True"*) echo "ok   with registry activation off the confirmation mail is bound again at 30" ;;
  *) echo "FAIL: the mail's binding did not come back: $bound"; exit 1 ;; esac
out=$(docker exec "$DRIVER" python /driver.py off) || { echo "$out"; exit 1; }
echo "$out" | grep -v '^ACCOUNTS '
off_user=$(echo "$out" | sed -n 's/^ACCOUNTS //p')
offcheck=$(akshell -e OFF_USER="$off_user" <<'PY' || true
import os
from authentik.core.models import User
u = User.objects.get(username=os.environ["OFF_USER"])
print("OFF", u.is_active, u.attributes.get("agentry_email_verified", "absent"))
PY
)
case "$offcheck" in *"OFF False absent"*) echo "ok   with registry activation off the account is written inactive, with no attribute, for the mail to activate" ;;
  *) echo "FAIL: with registry activation off: $offcheck"; exit 1 ;; esac

echo "PASS: directory terms of service acceptance"
