#!/usr/bin/env bash
# Promo code acceptance, the directory's half.
#
# The sign-up form's optional promo code field is configuration the directory
# applies: one prompt field whose type, prefill and initial value turn on
# AGENTRY_DIRECTORY_PROMO_FIELD, a grammar policy on the prompt stage, and the
# `agentry` scope mapping's agentry_promo_code claim. This proves it against
# the image the compose file pins, on a throwaway directory:
#
#   1. On (the variable set on the worker that applies the blueprint): the
#      field is an optional text field; a promo link (?promo=) fills it in; a
#      code outside the grammar is refused on the form; a code is written to
#      the account's attributes as typed, and an empty field leaves nothing;
#      the agentry scope sends agentry_promo_code for the account with a code
#      and no such claim for the other.
#   2. Off (the worker recreated without it, the blueprint applied again): the
#      field is served hidden, a promo link fills nothing in, and a code posted
#      into the hidden field anyway is stored empty.
#
# What the registry does with the claim is internal/api's tests
# (TestPromoClaimOnlyFromDirectoryOnCreate). Needs docker, the pinned images
# and outbound HTTPS from the directory (the CAPTCHA's siteverify with
# Cloudflare's test keys), nothing else. Files go in with docker cp, not bind
# mounts, as in directory-remember.sh.
set -euo pipefail
cd "$(cd "$(dirname "$0")/../.." && pwd)"
echo "== directory promo code acceptance =="
source scripts/acceptance/directory-resources.sh

COMPOSE=deploy/compose/docker-compose.yaml
IMAGE="${AUTHENTIK_IMAGE:-$(awk '/image: ghcr.io\/goauthentik\/server:/{print $2; exit}' "$COMPOSE")}"
PG_IMAGE=$(awk '/image: postgres:/{print $2; exit}' "$COMPOSE")
REDIS_IMAGE=$(awk '/image: redis:/{print $2; exit}' "$COMPOSE")
PY_IMAGE="${PY_IMAGE:-python:3.12-slim}"
[ -n "$IMAGE" ] || { echo "FAIL: no authentik image is pinned in $COMPOSE"; exit 1; }

# A random prefix, so two runs on one daemon never meet (directory-remember.sh).
P="dp-$(openssl rand -hex 4)"
NET="$P-net"
AK="$P-ak-server"
WORKER="$P-ak-worker"
DRIVER="$P-driver"
cleanup() {
  docker rm -fv "$P-pg" "$P-redis" "$AK" "$WORKER" "$DRIVER" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

PG_PW=$(openssl rand -hex 16)
docker network create "${DIRECTORY_DOCKER_LABELS[@]}" "$NET" >/dev/null
docker run -d "${DIRECTORY_DOCKER_LABELS[@]}" --name "$P-pg" --network "$NET" --network-alias dp-pg \
  -e POSTGRES_PASSWORD="$PG_PW" -e POSTGRES_USER=authentik -e POSTGRES_DB=authentik "$PG_IMAGE" >/dev/null
docker run -d "${DIRECTORY_DOCKER_LABELS[@]}" --name "$P-redis" --network "$NET" --network-alias dp-redis "$REDIS_IMAGE" >/dev/null
AK_ENV=(
  -e AUTHENTIK_SECRET_KEY="$(openssl rand -hex 32)"
  -e AUTHENTIK_POSTGRESQL__HOST=dp-pg -e AUTHENTIK_POSTGRESQL__USER=authentik
  -e AUTHENTIK_POSTGRESQL__NAME=authentik -e AUTHENTIK_POSTGRESQL__PASSWORD="$PG_PW"
  -e AUTHENTIK_REDIS__HOST=dp-redis -e AUTHENTIK_ERROR_REPORTING__ENABLED=false
  -e AUTHENTIK_LOG_LEVEL=warning
  -e AGENTRY_ACCOUNT_URL=http://registry.test/settings -e AGENTRY_PUBLIC_WEB_URL=http://registry.test
  -e AGENTRY_IDP_TRUST_CHECK_TOKEN="$(openssl rand -hex 32)" -e AGENTRY_REGISTRY_INTERNAL_URL=http://dp-driver:8080
  # Registry activation on, as compose sets it: sign-up ends
  # at the authenticator setup, the account active and unactivated.
  -e AGENTRY_DIRECTORY_REGISTRY_ACTIVATION=true
)
# worker <on|off>: the blueprint is applied by the worker, with the worker's
# environment; its watcher re-applies it with that environment too, so the
# flag is changed by recreating the worker, never by one apply.
worker() {
  local flag=()
  [ "$1" = on ] && flag=(-e AGENTRY_DIRECTORY_PROMO_FIELD=true)
  docker rm -fv "$WORKER" >/dev/null 2>&1 || true
  docker create "${DIRECTORY_DOCKER_LABELS[@]}" --name "$WORKER" --network "$NET" "${AK_ENV[@]}" "${flag[@]}" "$IMAGE" worker >/dev/null
  docker cp deploy/compose/authentik/templates/. "$WORKER:/templates" >/dev/null
  docker cp deploy/compose/authentik/blueprints/. "$WORKER:/blueprints/custom" >/dev/null
  docker start "$WORKER" >/dev/null
}
# The server serves what the database holds and applies no blueprint, so
# the flag is the worker's alone here; compose gives both the same value.
docker create "${DIRECTORY_DOCKER_LABELS[@]}" --name "$AK" --network "$NET" --network-alias dp-ak-server "${AK_ENV[@]}" "$IMAGE" server >/dev/null
docker cp deploy/compose/authentik/templates/. "$AK:/templates" >/dev/null
docker cp deploy/compose/authentik/blueprints/. "$AK:/blueprints/custom" >/dev/null
docker start "$AK" >/dev/null
worker on

docker create "${DIRECTORY_DOCKER_LABELS[@]}" --name "$DRIVER" --network "$NET" --network-alias dp-driver -e AK=http://dp-ak-server:9000 "$PY_IMAGE" sleep 3600 >/dev/null
docker cp scripts/acceptance/directory-promo.py "$DRIVER:/driver.py" >/dev/null
docker start "$DRIVER" >/dev/null

akshell() { docker exec -i "$@" "$AK" ak shell 2>&1 | grep -vE '^(###|[0-9]+ objects imported|\{")'; }

# field_type waits until the promo field's type is $1 (the blueprint applied
# by a worker with that flag), for up to $2 seconds.
field_type() {
  local want=$1 deadline=$(( $(date +%s) + $2 )) got=""
  while [ "$(date +%s)" -lt "$deadline" ]; do
    got=$(akshell <<'PY' || true
from authentik.stages.prompt.models import Prompt
p = Prompt.objects.filter(name="agentry-enrollment-promo-code").first()
print("TYPE", p.type if p else "absent")
PY
)
    case "$got" in *"TYPE $want"*) return 0 ;; esac
    sleep 10
  done
  echo "FAIL: the promo field did not become $want: ${got:-no answer}"
  docker logs --tail 20 "$WORKER" 2>&1 | tail -10
  return 1
}

echo "waiting for the directory to boot and apply the blueprints (a few minutes)"
field_type text 600
echo "ok   the blueprint applied with the field on"

out=$(docker exec "$DRIVER" python /driver.py on) || { echo "$out"; exit 1; }
echo "$out" | grep -v '^ACCOUNTS '
accounts=$(echo "$out" | sed -n 's/^ACCOUNTS //p')

check=$(akshell -e ACCOUNTS="$accounts" <<'PY' || true
import json, os
from authentik.core.models import User
from authentik.policies.types import PolicyRequest
from authentik.providers.oauth2.models import ScopeMapping
a = json.loads(os.environ["ACCOUNTS"])
m = ScopeMapping.objects.get(name="agentry-remember-device")
coded, empty = User.objects.get(username=a["coded"]), User.objects.get(username=a["empty"])
print("ATTR coded", repr(coded.attributes.get("agentry_promo_code")), "empty", repr(empty.attributes.get("agentry_promo_code")))
# The field is the first to put a nested attributes value in the prompt data,
# beside the has-password policy's flat attributes.agentry_has_password: the
# two must merge, and nothing else may be written.
print("KEYS coded", sorted(coded.attributes), coded.attributes.get("agentry_has_password"))
print("CLAIM coded", m.evaluate(user=coded, request=PolicyRequest(coded), token=None).get("agentry_promo_code"))
print("CLAIM empty", "agentry_promo_code" in m.evaluate(user=empty, request=PolicyRequest(empty), token=None))
PY
)
case "$check" in *"ATTR coded 'launch-2026' empty ''"*) echo "ok   the code is written to the account's attributes as typed; an empty field leaves it empty" ;;
  *) echo "FAIL: the accounts' attributes: $check"; exit 1 ;; esac
case "$check" in *"KEYS coded ['agentry_email_verified', 'agentry_has_password', 'agentry_promo_code'] True"*) echo "ok   the code merges beside agentry_has_password and agentry_email_verified, and nothing else is written" ;;
  *) echo "FAIL: the coded account's attributes: $check"; exit 1 ;; esac
case "$check" in *"CLAIM coded launch-2026"*) echo "ok   the agentry scope sends agentry_promo_code for the account with a code" ;;
  *) echo "FAIL: the claim for the account with a code: $check"; exit 1 ;; esac
case "$check" in *"CLAIM empty False"*) echo "ok   and no such claim for the account without one" ;;
  *) echo "FAIL: the claim for the account without a code: $check"; exit 1 ;; esac

echo "recreating the worker without the flag"
worker off
# Discovery applies the blueprint when the worker boots, on its own time;
# applying it now makes the wait below short. Its failure shows there.
docker exec "$WORKER" ak apply_blueprint custom/agentry-account-flows.yaml >/dev/null 2>&1 || true
field_type hidden 300
echo "ok   the blueprint applied again with the field off"

out=$(docker exec "$DRIVER" python /driver.py off) || { echo "$out"; exit 1; }
echo "$out" | grep -v '^ACCOUNTS '
accounts=$(echo "$out" | sed -n 's/^ACCOUNTS //p')
check=$(akshell -e ACCOUNTS="$accounts" <<'PY' || true
import json, os
from authentik.core.models import User
u = User.objects.get(username=json.loads(os.environ["ACCOUNTS"])["smuggled"])
print("ATTR smuggled", repr(u.attributes.get("agentry_promo_code")))
PY
)
case "$check" in *"ATTR smuggled ''"*) echo "ok   a code posted into the hidden field is stored empty" ;;
  *) echo "FAIL: a code posted into the hidden field: $check"; exit 1 ;; esac

echo "PASS: directory promo code acceptance"
