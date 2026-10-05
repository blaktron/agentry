#!/usr/bin/env bash
# The per-IP sign-up budget's acceptance (agentry#830, DEV-063).
#
# agentry-account-flow-rate-limit caps how much one address can make the
# directory do in an hour: accounts created plus mails sent. On authentik
# 2026.8 neither was recorded the way it counted them (a flow-made account
# is `user_write` with `created`, not `model_created`; the worker sends the
# mail, so `email_sent` carries no address), and it counted nothing. This
# proves the budget against the image the compose file pins, on a throwaway
# directory with the budget at 4 and registry activation off (so the
# sign-up sends its own confirmation mail):
#
#   1. One password sign-up to its confirmation mail, the mail page opened
#      a second time, one resend from it, then a password reset of that
#      account to its mail.
#      authentik records what the budget counts, with the client's address:
#      one `user_write` created event (the password sign-up's, the case the
#      issue left unverified) and a `custom_agentry_account_mail` per mail
#      (three: the sign-up's, its resend and the reset's; the second
#      opening was not counted again). The mail events name their flow and
#      carry no prompt data.
#   2. With 4 spent, a new sign-up and a new reset are refused at the
#      start, in the policy's words, and nothing more is recorded.
#
# Needs docker, the pinned images and outbound HTTPS from the directory (the
# CAPTCHA's siteverify with Cloudflare's test keys), nothing else. Files go
# in with docker cp, not bind mounts, as in directory-terms.sh.
set -euo pipefail
cd "$(cd "$(dirname "$0")/../.." && pwd)"
echo "== directory sign-up budget acceptance =="

COMPOSE=deploy/compose/docker-compose.yaml
IMAGE="${AUTHENTIK_IMAGE:-$(awk '/image: ghcr.io\/goauthentik\/server:/{print $2; exit}' "$COMPOSE")}"
PG_IMAGE=$(awk '/image: postgres:/{print $2; exit}' "$COMPOSE")
REDIS_IMAGE=$(awk '/image: redis:/{print $2; exit}' "$COMPOSE")
PY_IMAGE="${PY_IMAGE:-python:3.12-slim}"
[ -n "$IMAGE" ] || { echo "FAIL: no authentik image is pinned in $COMPOSE"; exit 1; }

P="dl-$(openssl rand -hex 4)"
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
docker network create "$NET" >/dev/null
docker run -d --name "$P-pg" --network "$NET" --network-alias dl-pg \
  -e POSTGRES_PASSWORD="$PG_PW" -e POSTGRES_USER=authentik -e POSTGRES_DB=authentik "$PG_IMAGE" >/dev/null
docker run -d --name "$P-redis" --network "$NET" --network-alias dl-redis "$REDIS_IMAGE" >/dev/null
# The budget is read when the worker applies the blueprint (it is formatted
# into the expression), so the worker carries it; the server too, as the
# compose file sets it on both. Registry activation is off (unset), so the
# sign-up's confirmation mail is the directory's own.
AK_ENV=(
  -e AUTHENTIK_SECRET_KEY="$(openssl rand -hex 32)"
  -e AUTHENTIK_POSTGRESQL__HOST=dl-pg -e AUTHENTIK_POSTGRESQL__USER=authentik
  -e AUTHENTIK_POSTGRESQL__NAME=authentik -e AUTHENTIK_POSTGRESQL__PASSWORD="$PG_PW"
  -e AUTHENTIK_REDIS__HOST=dl-redis -e AUTHENTIK_ERROR_REPORTING__ENABLED=false
  -e AUTHENTIK_LOG_LEVEL=warning
  -e AGENTRY_ACCOUNT_URL=http://registry.test/settings -e AGENTRY_PUBLIC_WEB_URL=http://registry.test
  -e AUTHENTIK_ACCOUNT_FLOW_MAX_PER_HOUR=4
)
for role in server worker; do
  name=$AK alias=(--network-alias dl-ak-server)
  [ "$role" = worker ] && name=$WORKER alias=()
  docker create --name "$name" --network "$NET" "${alias[@]}" "${AK_ENV[@]}" "$IMAGE" "$role" >/dev/null
  docker cp deploy/compose/authentik/templates/. "$name:/templates" >/dev/null
  docker cp deploy/compose/authentik/blueprints/. "$name:/blueprints/custom" >/dev/null
  docker start "$name" >/dev/null
done

docker create --name "$DRIVER" --network "$NET" --network-alias dl-driver \
  -e AK=http://dl-ak-server:9000 "$PY_IMAGE" sleep 3600 >/dev/null
docker cp scripts/acceptance/directory-budget.py "$DRIVER:/driver.py" >/dev/null
docker start "$DRIVER" >/dev/null

akshell() { docker exec -i "$@" "$AK" ak shell 2>&1 | grep -vE '^(###|[0-9]+ objects imported|\{")'; }

# bound says whether the mail-count policy is bound to both mail stages.
bound() { case "$1" in *"COUNTED agentry-enrollment True"*"COUNTED agentry-recovery True"*) return 0 ;; esac; return 1; }

echo "waiting for the directory to boot and apply the blueprints (a few minutes)"
deadline=$(( $(date +%s) + 600 )); got=""
while [ "$(date +%s)" -lt "$deadline" ]; do
  got=$(akshell <<'PY' || true
from authentik.policies.models import PolicyBinding
for flow in ("agentry-enrollment", "agentry-recovery"):
    print("COUNTED", flow, PolicyBinding.objects.filter(
        policy__name="agentry-account-flow-mail-count",
        target__flowstagebinding__target__slug=flow).exists())
PY
)
  bound "$got" && break
  sleep 10
done
bound "$got" || {
  echo "FAIL: the mail-count policy is not bound to both mail stages: ${got:-no answer}"
  docker logs --tail 20 "$WORKER" 2>&1 | tail -10
  exit 1
}
deadline=$(( $(date +%s) + 120 ))
until docker exec "$DRIVER" python -c "import urllib.request; urllib.request.urlopen('http://dl-ak-server:9000/-/health/ready/', timeout=5)" >/dev/null 2>&1; do
  [ "$(date +%s)" -lt "$deadline" ] || { echo "FAIL: the server is not ready"; docker logs --tail 20 "$AK" 2>&1 | tail -10; exit 1; }
  sleep 5
done
echo "ok   the blueprint applied: the mail-count policy is bound to the sign-up's and the reset's mail stages"

# events prints what the budget counts from the address the driver's
# requests came from (the address of the account's own creation event).
events() {
  akshell -e ACCOUNT="$1" <<'PY' || true
import os
from datetime import timedelta
from django.utils.timezone import now
from authentik.core.models import User
from authentik.events.models import Event, EventAction
made = Event.objects.filter(action=EventAction.USER_WRITE, context__created=True,
                            user__username=os.environ["ACCOUNT"]).order_by("created").first()
ip = made.client_ip if made else None
recent = Event.objects.filter(client_ip=ip, created__gte=now() - timedelta(hours=1)) if ip else Event.objects.none()
mails = recent.filter(action=EventAction.CUSTOM_PREFIX + "agentry_account_mail")
print("IP", ip)
print("CREATED", recent.filter(action=EventAction.USER_WRITE, context__created=True).count())
print("MAILS", mails.count())
# The mails' flows: the sign-up's (its mail and its resend) and the
# reset's, each named.
print("FLOWS", len({e.context.get("flow") for e in mails if e.context.get("flow")}))
# What a mail event may carry: the flow it counts, the request's path and
# method (from_http), and the enrichment authentik adds where GeoIP or ASN
# databases are configured. Anything else is the form leaking in.
print("EXTRA", sorted({k for e in mails for k in e.context} - {"flow", "http_request", "geo", "asn"}))
print("USERS", User.objects.filter(username__startswith="dl-").count())
PY
}

out=$(docker exec "$DRIVER" python /driver.py spend) || { echo "$out"; exit 1; }
echo "$out" | grep -v '^ACCOUNT '
account=$(echo "$out" | sed -n 's/^ACCOUNT //p')
[ -n "$account" ] || { echo "FAIL: the driver named no account"; exit 1; }
spent=$(events "$account")
case "$spent" in *"IP None"*|"") echo "FAIL: no creation event recorded the sign-up's address: $spent"; exit 1 ;; esac
echo "     $(grep '^IP ' <<<"$spent") (the address the flows came from)"
case "$spent" in *"CREATED 1"*) echo "ok   the password sign-up is recorded as a user_write created event with the client's address" ;;
  *) echo "FAIL: the sign-up's creation event: $spent"; exit 1 ;; esac
case "$spent" in *"MAILS 3"*"FLOWS 2"*) echo "ok   the sign-up's mail, its resend and the reset's mail are each recorded, with the address and the flow (the mail page opened twice counted once)" ;;
  *) echo "FAIL: the mail events: $spent"; exit 1 ;; esac
case "$spent" in *"EXTRA []"*) echo "ok   a mail event carries the flow and the request's path, nothing of the form" ;;
  *) echo "FAIL: a mail event's context: $spent"; exit 1 ;; esac
users_before=$(sed -n 's/^USERS //p' <<<"$spent")

out=$(docker exec "$DRIVER" python /driver.py refuse) || { echo "$out"; exit 1; }
echo "$out"
after=$(events "$account")
case "$after" in *"CREATED 1"*"MAILS 3"*) echo "ok   the refused attempts recorded nothing more" ;;
  *) echo "FAIL: the refused attempts were recorded: $after"; exit 1 ;; esac
[ "$(sed -n 's/^USERS //p' <<<"$after")" = "$users_before" ] || { echo "FAIL: a refused sign-up made an account: $after"; exit 1; }
echo "ok   no account was made with the budget spent"

echo "PASS: directory sign-up budget acceptance"
