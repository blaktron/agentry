#!/usr/bin/env bash
# Bootstrap the directory service (DEV-057): create/refresh the OAuth2
# provider and application that let the registry consume Authentik as its
# `authentik` social provider. Idempotent — safe to re-run.
#
# Required environment:
#   AUTHENTIK_URL                    e.g. https://agentry.tail49832b.ts.net:8443
#   AUTHENTIK_BOOTSTRAP_TOKEN        the API token first boot created
#   AGENTRY_AUTHENTIK_CLIENT_SECRET  OAuth client secret to (re)set
#   AGENTRY_REDIRECT_URI             e.g. https://<host>/api/v1/auth/oidc/authentik/callback
# Optional:
#   AGENTRY_CLIENT_ID   (default agentry-registry)
#   CURL_FLAGS          e.g. -k while the edge still runs a self-signed cert
set -euo pipefail

: "${AUTHENTIK_URL:?}" "${AUTHENTIK_BOOTSTRAP_TOKEN:?}"
: "${AGENTRY_AUTHENTIK_CLIENT_SECRET:?}" "${AGENTRY_REDIRECT_URI:?}"
CLIENT_ID="${AGENTRY_CLIENT_ID:-agentry-registry}"
API="$AUTHENTIK_URL/api/v3"
auth=(-H "Authorization: Bearer $AUTHENTIK_BOOTSTRAP_TOKEN" -H "Content-Type: application/json")
curlx() { curl -fsS ${CURL_FLAGS:-} "${auth[@]}" "$@"; }
jget() { python3 -c "import sys,json;d=json.load(sys.stdin);print(eval(sys.argv[1],{},{'d':d}))" "$1"; }

echo "== wait for authentik =="
for i in $(seq 1 60); do
  curl -fsS ${CURL_FLAGS:-} -o /dev/null "$AUTHENTIK_URL/-/health/ready/" && break
  sleep 2
  [ "$i" = 60 ] && { echo "FAIL: authentik never became ready"; exit 1; }
done
echo "ready"

echo "== resolve flows + signing key =="
AUTHZ_FLOW=$(curlx "$API/flows/instances/?slug=default-provider-authorization-implicit-consent" | jget "d['results'][0]['pk']")
INVAL_FLOW=$(curlx "$API/flows/instances/?slug=default-provider-invalidation-flow" | jget "d['results'][0]['pk']" 2>/dev/null || echo "")
CERT=$(curlx "$API/crypto/certificatekeypairs/?name=authentik+Self-signed+Certificate" | jget "d['results'][0]['pk']")
echo "authorization flow: $AUTHZ_FLOW"; echo "signing key: $CERT"

# The provider payload. redirect_uris changed shape across authentik
# releases (plain text vs a list of {matching_mode, url}); try the
# structured form first and fall back to the legacy string.
mkpayload() {
  python3 - "$1" <<'PY'
import json, os, sys
structured = sys.argv[1] == "structured"
p = {
    "name": "agentry-registry",
    "authorization_flow": os.environ["AUTHZ_FLOW"],
    "client_type": "confidential",
    "client_id": os.environ["CLIENT_ID"],
    "client_secret": os.environ["CLIENT_SECRET"],
    "signing_key": os.environ["CERT"],
    "sub_mode": "hashed_user_id",
    "include_claims_in_id_token": True,
}
if os.environ.get("INVAL_FLOW"):
    p["invalidation_flow"] = os.environ["INVAL_FLOW"]
uri = os.environ["REDIRECT_URI"]
p["redirect_uris"] = [{"matching_mode": "strict", "url": uri}] if structured else uri
print(json.dumps(p))
PY
}
export AUTHZ_FLOW INVAL_FLOW CERT CLIENT_ID CLIENT_SECRET="$AGENTRY_AUTHENTIK_CLIENT_SECRET" REDIRECT_URI="$AGENTRY_REDIRECT_URI"

echo "== provider =="
EXISTING=$(curlx "$API/providers/oauth2/?name=agentry-registry" | jget "d['pagination']['count']")
if [ "$EXISTING" = "0" ]; then
  PK=$(curlx -X POST "$API/providers/oauth2/" -d "$(mkpayload structured)" 2>/dev/null | jget "d['pk']") \
    || PK=$(curlx -X POST "$API/providers/oauth2/" -d "$(mkpayload legacy)" | jget "d['pk']")
  echo "created provider pk=$PK"
else
  PK=$(curlx "$API/providers/oauth2/?name=agentry-registry" | jget "d['results'][0]['pk']")
  curlx -X PATCH "$API/providers/oauth2/$PK/" -d "$(mkpayload structured)" -o /dev/null 2>/dev/null \
    || curlx -X PATCH "$API/providers/oauth2/$PK/" -d "$(mkpayload legacy)" -o /dev/null
  echo "updated provider pk=$PK"
fi

echo "== application =="
APP=$(curlx "$API/core/applications/?slug=agentry" | jget "d['pagination']['count']")
BODY=$(PK="$PK" python3 -c "import json,os;print(json.dumps({'name':'SecureAgentry','slug':'agentry','provider':int(os.environ['PK'])}))")
if [ "$APP" = "0" ]; then
  curlx -X POST "$API/core/applications/" -d "$BODY" -o /dev/null
  echo "created application slug=agentry"
else
  curlx -X PATCH "$API/core/applications/agentry/" -d "$BODY" -o /dev/null
  echo "updated application slug=agentry"
fi

echo "== issuer =="
echo "$AUTHENTIK_URL/application/o/agentry/"
echo "BOOTSTRAP OK"
