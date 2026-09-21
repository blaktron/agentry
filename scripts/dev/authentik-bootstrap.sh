#!/usr/bin/env bash
# Bootstrap the directory service (DEV-057): create/refresh the OAuth2
# provider and application that let the registry consume Authentik as its
# `authentik` social provider. Idempotent — safe to re-run.
#
# Required environment:
#   AUTHENTIK_URL                    e.g. https://auth.example.test:8443
#   AUTHENTIK_BOOTSTRAP_TOKEN        the API token first boot created
#   AGENTRY_AUTHENTIK_CLIENT_SECRET  OAuth client secret to (re)set
#   AGENTRY_REDIRECT_URI             e.g. https://<host>/api/v1/auth/oidc/authentik/callback
#   AGENTRY_PUBLIC_WEB_URL           e.g. https://<host> — where sign-in lands and sign-out returns (agentry#164)
# Optional:
#   AGENTRY_CLIENT_ID   (default agentry-registry)
#   CURL_FLAGS          e.g. -k while the edge still runs a self-signed cert
set -euo pipefail

: "${AUTHENTIK_URL:?}" "${AUTHENTIK_BOOTSTRAP_TOKEN:?}"
: "${AGENTRY_AUTHENTIK_CLIENT_SECRET:?}" "${AGENTRY_REDIRECT_URI:?}" "${AGENTRY_PUBLIC_WEB_URL:?}"
WEB_URL="${AGENTRY_PUBLIC_WEB_URL%/}"
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
# Sign-out returns to the site through the blueprint's agentry-invalidation
# flow (agentry#164); the shipped provider flow is the fallback on a
# directory whose blueprints have not applied yet.
INVAL_FLOW=$(curlx "$API/flows/instances/?slug=agentry-invalidation" | jget "(d['results'][0]['pk'] if d['results'] else '')" 2>/dev/null || echo "")
[ -n "$INVAL_FLOW" ] || INVAL_FLOW=$(curlx "$API/flows/instances/?slug=default-provider-invalidation-flow" | jget "d['results'][0]['pk']" 2>/dev/null || echo "")
CERT=$(curlx "$API/crypto/certificatekeypairs/?name=authentik+Self-signed+Certificate" | jget "d['results'][0]['pk']")
# The scope mappings are what put claims in the ID token: a provider with
# none issues `sub` alone (email/profile scopes are silently ignored) and
# the registry can then only JIT a placeholder account instead of linking
# by verified email. Resolve authentik's managed openid/email/profile
# mappings by their stable `managed` ids, never by display name.
SCOPE_MAPPINGS=$(curlx "$API/propertymappings/provider/scope/?page_size=100" | python3 -c '
import json, sys
want = {"goauthentik.io/providers/oauth2/scope-" + s for s in ("openid", "email", "profile")}
pks = [m["pk"] for m in json.load(sys.stdin)["results"] if m.get("managed") in want]
if len(pks) != 3: sys.exit("expected 3 managed scope mappings, found %d" % len(pks))
print(json.dumps(pks))')
EMAIL_MANAGED_PK=$(curlx "$API/propertymappings/provider/scope/?managed=goauthentik.io/providers/oauth2/scope-email" | jget "d['results'][0]['pk']")
export SCOPE_MAPPINGS EMAIL_MANAGED_PK VERIFIED_NAME VERIFIED_PK
# authentik's managed `email` mapping hard-codes email_verified=False
# (2026.8). This deployment's directory of record IS authentik — accounts
# are operator-created or enrolled through a flow with an email stage — so
# the registry's T-12 auto-link rule (verified IdP email ↔ verified account
# email) needs the assertion to be true. A custom mapping replaces the
# managed one for the `email` scope; idempotent by name.
VERIFIED_NAME="Agentry: OpenID 'email' (directory-verified)"; export VERIFIED_NAME
VERIFIED_PK=$(curlx -G --data-urlencode "name=$VERIFIED_NAME" "$API/propertymappings/provider/scope/" | jget "(d['results'][0]['pk'] if d['results'] else '')")
if [ -z "$VERIFIED_PK" ]; then
  VERIFIED_PK=$(curlx -X POST "$API/propertymappings/provider/scope/" -d "$(python3 -c '
import json, os
print(json.dumps({
  "name": os.environ["VERIFIED_NAME"], "scope_name": "email",
  "description": "Email address (directory-verified)",
  "expression": "# authentik is this deployment\x27s directory of record; the address is\n# asserted verified. The managed mapping hard-codes False (2026.8).\nreturn {\"email\": request.user.email, \"email_verified\": True}",
}))')" | jget "d['pk']")
  echo "created directory-verified email mapping $VERIFIED_PK"
fi
export VERIFIED_PK
SCOPE_MAPPINGS=$(python3 -c '
import json, os, sys
pks = json.loads(os.environ["SCOPE_MAPPINGS"])
pks = [p for p in pks if p != os.environ["EMAIL_MANAGED_PK"]] + [os.environ["VERIFIED_PK"]]
print(json.dumps(pks))')
echo "authorization flow: $AUTHZ_FLOW"; echo "signing key: $CERT"; echo "scope mappings: $SCOPE_MAPPINGS"

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
    "property_mappings": json.loads(os.environ["SCOPE_MAPPINGS"]),
}
if os.environ.get("INVAL_FLOW"):
    p["invalidation_flow"] = os.environ["INVAL_FLOW"]
uri = os.environ["REDIRECT_URI"]
web = os.environ["WEB_URL"]
# The logout-typed entry lets an RP-initiated sign-out name the site as its
# post_logout_redirect_uri (agentry#164).
p["redirect_uris"] = ([{"matching_mode": "strict", "url": uri, "redirect_uri_type": "authorization"},
                       {"matching_mode": "strict", "url": web + "/", "redirect_uri_type": "logout"}]
                      if structured else uri)
print(json.dumps(p))
PY
}
export AUTHZ_FLOW INVAL_FLOW CERT SCOPE_MAPPINGS CLIENT_ID CLIENT_SECRET="$AGENTRY_AUTHENTIK_CLIENT_SECRET" REDIRECT_URI="$AGENTRY_REDIRECT_URI" WEB_URL

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
# The launch URL is the registry's own sign-in start: a directory session
# that ends without a return (enrollment, recovery, a flow opened by hand)
# lands in the app signed in, never in the directory's panel (agentry#164).
BODY=$(PK="$PK" WEB_URL="$WEB_URL" python3 -c "import json,os;print(json.dumps({'name':'Agentry','slug':'agentry','provider':int(os.environ['PK']),'meta_launch_url':os.environ['WEB_URL']+'/api/v1/auth/oidc/authentik/start?next=%2Fdashboard','open_in_new_tab':False}))")
if [ "$APP" = "0" ]; then
  curlx -X POST "$API/core/applications/" -d "$BODY" -o /dev/null
  echo "created application slug=agentry"
else
  curlx -X PATCH "$API/core/applications/agentry/" -d "$BODY" -o /dev/null
  echo "updated application slug=agentry"
fi

echo "== brand: land in Agentry, offer no directory settings =="
APP_PK=$(curlx "$API/core/applications/agentry/" | jget "d['pk']")
BRAND_PK=$(curlx "$API/core/brands/?domain=authentik-default" | jget "d['results'][0]['brand_uuid']")
curlx -X PATCH "$API/core/brands/$BRAND_PK/" -d "$(APP_PK="$APP_PK" python3 -c "import json,os;print(json.dumps({'default_application':os.environ['APP_PK'],'flow_user_settings':None}))")" -o /dev/null
echo "brand $BRAND_PK: default_application=$APP_PK, flow_user_settings=null"

echo "== issuer (AGENTRY_SOCIAL_AUTHENTIK_ISSUER) =="
echo "$AUTHENTIK_URL/application/o/agentry/"
# The cancel view drops a flow plan the session may still hold before the
# provider's end-session runs; without it that plan turns sign-out into an
# empty page (agentry#441).
echo "== sign-out URL (AGENTRY_IDP_LOGOUT_URL) =="
echo "$AUTHENTIK_URL/flows/-/cancel/?next=/application/o/agentry/end-session/"
echo "BOOTSTRAP OK"
