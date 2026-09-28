#!/usr/bin/env bash
# Remembered-browser acceptance, the directory's half (agentry#671, DEV-163).
#
# "Remember this device for 30 days" lives on the directory's code page, and
# the directory decides whether to show that page by asking the registry. All
# of it is configuration the directory applies: the account-flows blueprint
# (two policies, the `agentry` scope mapping, two restated sign-in bindings)
# and the flow page's template override. This proves that configuration
# against the image the compose file pins:
#
#   1. The template is authentik's own flows/templates/if/flow.html, byte for
#      byte, plus one marked block; and the web component and form the block
#      writes into still exist in the image's bundle. An authentik upgrade
#      that moves either fails here, not silently on the sign-in page.
#   2. A throwaway directory, on a private network, with the blueprints and
#      templates copied in, signs two users in through the real flow executor
#      (scripts/acceptance/directory-remember.py plays the browser and a
#      stand-in registry): the code is asked unless the registry says this
#      browser is remembered for this user; a ticked box reaches the ID token
#      only beside a validated factor; a remembered sign-in cannot mint again;
#      and a registry that errors, hangs or answers garbage, a revoked record,
#      and a skip policy that raises all mean the code is asked. And no
#      sign-in writes authentik's own 30-day `authentik_device` cookie, which
#      the blueprint turns off on every login stage (agentry#460).
#
# Needs docker and the pinned images, nothing else. Files go in with docker
# cp, not bind mounts: a CI job drives the host's daemon from inside a runner
# container, where the checkout's path means nothing to the daemon.
set -euo pipefail
cd "$(cd "$(dirname "$0")/../.." && pwd)"
echo "== directory remembered-browser acceptance =="

COMPOSE=deploy/compose/docker-compose.yaml
IMAGE="${AUTHENTIK_IMAGE:-$(awk '/image: ghcr.io\/goauthentik\/server:/{print $2; exit}' "$COMPOSE")}"
PG_IMAGE=$(awk '/image: postgres:/{print $2; exit}' "$COMPOSE")
REDIS_IMAGE=$(awk '/image: redis:/{print $2; exit}' "$COMPOSE")
PY_IMAGE="${PY_IMAGE:-python:3.12-slim}"
TEMPLATE=deploy/compose/authentik/templates/if/flow.html
[ -n "$IMAGE" ] && [ -n "$PG_IMAGE" ] && [ -n "$REDIS_IMAGE" ] || { echo "FAIL: an image is not pinned in $COMPOSE"; exit 1; }

# A random prefix: $$ is a PID, and runner containers each have their own PID
# namespace on the one daemon, so two runs could share it and one run's
# cleanup would remove the other's containers.
P="dr-$(openssl rand -hex 4)"
NET="$P-net"
TMP=$(mktemp -d)
AK="$P-ak-server"
DRIVER="$P-driver"
cleanup() {
  docker rm -f "$P-pg" "$P-redis" "$AK" "$P-ak-worker" "$DRIVER" "$P-probe" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$TMP"
}
trap cleanup EXIT
# The driver's redirect URI and the directory's registry URL name the hosts
# dr-ak-server and dr-driver: network aliases, which live only on this run's
# private network, so runs on one daemon never meet.

# ---------------------------------------------------------------- 1. the template
probe=$(docker create --name "$P-probe" "$IMAGE")
docker cp "$probe:/authentik/flows/templates/if/flow.html" "$TMP/flow.orig.html"
docker cp "$probe:/web/dist" "$TMP/dist" >/dev/null
docker rm -f "$probe" >/dev/null
sed '/^{# agentry:begin remembered-browser/,$d' "$TEMPLATE" > "$TMP/flow.ours.html"
if cmp -s "$TMP/flow.orig.html" "$TMP/flow.ours.html"; then
  echo "ok   the template is the pinned image's flow.html plus one marked block"
else
  echo "FAIL: $TEMPLATE no longer starts with the pinned image's flow.html; re-copy it and keep the block:"
  diff "$TMP/flow.orig.html" "$TMP/flow.ours.html" | head -20
  exit 1
fi
[ "$(grep -c '^{# agentry:begin remembered-browser' "$TEMPLATE")" -eq 1 ] && [ "$(grep -c '^{# agentry:end remembered-browser' "$TEMPLATE")" -eq 1 ] \
  || { echo "FAIL: the template's block is not marked exactly once"; exit 1; }
chunk=$(grep -rl 'ak-stage-authenticator-validate-code' "$TMP/dist" --include='*.js' | head -1)
[ -n "$chunk" ] || { echo "FAIL: the image's bundle has no ak-stage-authenticator-validate-code"; exit 1; }
for needle in 'name="code"' 'pf-m-action' 'ak-stage-authenticator-validate-code'; do
  grep -q -- "$needle" "$chunk" || { echo "FAIL: the code stage's bundle no longer contains $needle, which the template's script relies on"; exit 1; }
done
echo "ok   the code stage's component, its code field and its action fieldset are in the pinned bundle"

# ---------------------------------------------------------------- 2. a directory
PG_PW=$(openssl rand -hex 16)
CHECK_TOKEN=$(openssl rand -hex 32)
CLIENT_SECRET=$(openssl rand -hex 24)
USER_PASSWORD="pw-$(openssl rand -hex 12)"
docker network create "$NET" >/dev/null
docker run -d --name "$P-pg" --network "$NET" --network-alias dr-pg \
  -e POSTGRES_PASSWORD="$PG_PW" -e POSTGRES_USER=authentik -e POSTGRES_DB=authentik "$PG_IMAGE" >/dev/null
docker run -d --name "$P-redis" --network "$NET" --network-alias dr-redis "$REDIS_IMAGE" >/dev/null
AK_ENV=(
  -e AUTHENTIK_SECRET_KEY="$(openssl rand -hex 32)"
  -e AUTHENTIK_POSTGRESQL__HOST=dr-pg -e AUTHENTIK_POSTGRESQL__USER=authentik
  -e AUTHENTIK_POSTGRESQL__NAME=authentik -e AUTHENTIK_POSTGRESQL__PASSWORD="$PG_PW"
  -e AUTHENTIK_REDIS__HOST=dr-redis -e AUTHENTIK_ERROR_REPORTING__ENABLED=false
  -e AUTHENTIK_LOG_LEVEL=warning
  -e AGENTRY_ACCOUNT_URL=http://registry.test/settings -e AGENTRY_PUBLIC_WEB_URL=http://registry.test
  -e AGENTRY_IDP_TRUST_CHECK_TOKEN="$CHECK_TOKEN" -e AGENTRY_REGISTRY_INTERNAL_URL=http://dr-driver:8080
)
docker create --name "$AK" --network "$NET" --network-alias dr-ak-server "${AK_ENV[@]}" "$IMAGE" server >/dev/null
docker create --name "$P-ak-worker" --network "$NET" "${AK_ENV[@]}" "$IMAGE" worker >/dev/null
for c in "$AK" "$P-ak-worker"; do
  docker cp deploy/compose/authentik/templates/. "$c:/templates" >/dev/null
  docker cp deploy/compose/authentik/blueprints/. "$c:/blueprints/custom" >/dev/null
done
docker start "$AK" "$P-ak-worker" >/dev/null

# The stand-in registry must answer before the first sign-in.
docker create --name "$DRIVER" --network "$NET" --network-alias dr-driver \
  -e AK=http://dr-ak-server:9000 -e CHECK_TOKEN="$CHECK_TOKEN" \
  -e CLIENT_SECRET="$CLIENT_SECRET" -e USER_PASSWORD="$USER_PASSWORD" \
  "$PY_IMAGE" python /driver.py serve >/dev/null
docker cp scripts/acceptance/directory-remember.py "$DRIVER:/driver.py" >/dev/null
docker start "$DRIVER" >/dev/null

# ak shell prints a banner and JSON log lines around what the script prints.
akshell() { docker exec -i "$@" "$AK" ak shell 2>&1 | grep -vE '^(###|[0-9]+ objects imported|\{")'; }

# Ready means the account-flows blueprint has applied, including the binding
# it restates in mode all (the default sign-in flow has to exist first).
echo "waiting for the directory to boot and apply the blueprints (a few minutes)"
ready=""
deadline=$(( $(date +%s) + 600 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  ready=$(akshell <<'PY' || true
from authentik.flows.models import FlowStageBinding
from authentik.providers.oauth2.models import ScopeMapping
ok = ScopeMapping.objects.filter(name="agentry-remember-device").exists()
b = FlowStageBinding.objects.filter(target__slug="default-authentication-flow", order=30).first()
print("READY" if ok and b is not None and b.policy_engine_mode == "all" else "WAIT")
PY
)
  case "$ready" in *READY*) break ;; esac
  sleep 10
done
case "$ready" in *READY*) echo "ok   the blueprint applied: the agentry scope mapping exists and the MFA binding is in mode all" ;;
  *) echo "FAIL: the account-flows blueprint did not apply within ten minutes"; docker logs --tail 40 "$P-ak-worker" 2>&1 | tail -20; exit 1 ;; esac

setup=$(akshell -e CLIENT_SECRET="$CLIENT_SECRET" -e USER_PASSWORD="$USER_PASSWORD" <<'PY' || true
import os
from authentik.core.models import Application, User
from authentik.crypto.models import CertificateKeyPair
from authentik.flows.models import Flow
from authentik.providers.oauth2.models import OAuth2Provider, RedirectURI, RedirectURIMatchingMode, ScopeMapping
from authentik.stages.authenticator_totp.models import TOTPDevice
for name in ("dr-one", "dr-two"):
    u, _ = User.objects.get_or_create(username=name, defaults={"email": name + "@example.test", "name": name})
    u.set_password(os.environ["USER_PASSWORD"]); u.is_active = True; u.save()
    TOTPDevice.objects.filter(user=u).delete()
    TOTPDevice.objects.create(user=u, name=name, key="3132333435363738393031323334353637383930", confirmed=True, digits=6)
managed = ["goauthentik.io/providers/oauth2/scope-" + s for s in ("openid", "email", "profile")]
maps = list(ScopeMapping.objects.filter(managed__in=managed)) + [ScopeMapping.objects.get(name="agentry-remember-device")]
p, _ = OAuth2Provider.objects.update_or_create(name="dr", defaults={
    "client_id": "dr", "client_secret": os.environ["CLIENT_SECRET"], "client_type": "confidential",
    "authorization_flow": Flow.objects.get(slug="default-provider-authorization-implicit-consent"),
    "invalidation_flow": Flow.objects.get(slug="default-provider-invalidation-flow"),
    "sub_mode": "hashed_user_id", "include_claims_in_id_token": True, "grant_types": ["authorization_code"],
    "signing_key": CertificateKeyPair.objects.exclude(key_data="").first()})
p.redirect_uris = [RedirectURI(RedirectURIMatchingMode.STRICT, "http://dr-driver:8080/callback")]
p.save(); p.property_mappings.set(maps)
Application.objects.update_or_create(slug="dr", defaults={"name": "dr", "provider": p})
print("SETUP-DONE two users and the client")
PY
)
case "$setup" in *SETUP-DONE*) echo "ok   set up two users with a TOTP factor, and the client" ;;
  *) echo "FAIL: setting up the users and the client:"; echo "$setup" | tail -20; exit 1 ;; esac

set +e
# Each sign-in waits for a fresh TOTP step, so the scenarios take minutes.
timeout 900 docker exec "$DRIVER" python /driver.py scenarios
st=$?
if [ "$st" -eq 0 ]; then
  akshell <<'PY'
from authentik.policies.expression.models import ExpressionPolicy as E
p = E.objects.get(name="agentry-remembered-browser-skip")
E.objects.filter(pk=p.pk).update(expression='raise Exception("acceptance: the skip policy raises")\n' + p.expression)
PY
  timeout 300 docker exec "$DRIVER" python /driver.py raise
  st=$?
  akshell <<'PY'
from authentik.policies.expression.models import ExpressionPolicy as E
p = E.objects.get(name="agentry-remembered-browser-skip")
E.objects.filter(pk=p.pk).update(expression=p.expression.replace('raise Exception("acceptance: the skip policy raises")\n', "", 1))
PY
fi
set -e
[ "$st" -eq 0 ] || { echo "FAIL: directory remembered-browser acceptance"; exit 1; }
echo "PASS: directory remembered-browser acceptance"
