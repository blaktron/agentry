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
# Optional, the log stack's Dashboards (agentry#598; skipped unless the URL is set):
#   AGENTRY_DASHBOARDS_URL             e.g. https://dash.<host> — Dashboards' public URL
#   AGENTRY_IDP_STAFF_MIRROR_GROUP     the group the registry keeps equal to its
#                                      platform staff (default agentry-staff); give the
#                                      server the same value
#   AGENTRY_DASHBOARDS_CLIENT_ID       (default agentry-dashboards)
#   AGENTRY_DASHBOARDS_SECRET_FILE     where the client id and secret are written, 0600
#                                      (default ${XDG_CONFIG_HOME:-~/.config}/agentry/
#                                      dashboards-oidc.env, outside any checkout); an
#                                      existing file's secret is kept, and never printed
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
export SCOPE_MAPPINGS EMAIL_MANAGED_PK
# authentik's managed `email` mapping hard-codes email_verified=False
# (2026.8), which the registry's T-12 auto-link rule (verified IdP email ↔
# verified account email) treats as unlinkable. The account-flows blueprint
# carries the replacement, agentry-verified-email, which asserts what the
# directory recorded: false for a self-enrolled account until the registry's
# activation link confirms it (agentry#861). Until agentry#861 this script
# made its own mapping that said true for everyone; a re-run replaces it on
# the provider (the old mapping is left in place, unused).
VERIFIED_PK=$(curlx -G --data-urlencode "name=agentry-verified-email" "$API/propertymappings/provider/scope/" | jget "(d['results'][0]['pk'] if d['results'] else '')")
[ -n "$VERIFIED_PK" ] || { echo "error: the blueprint's agentry-verified-email scope mapping is not there yet; re-run once authentik has applied agentry-account-flows.yaml" >&2; exit 1; }
export VERIFIED_PK
# The account-flows blueprint's `agentry` scope mapping carries whether the
# sign-in asked to remember the browser (agentry#671, DEV-163). The registry
# asks for the scope; without the mapping on the provider authentik drops
# it, and then no browser is remembered and the code is asked every time.
AGENTRY_SCOPE_PK=$(curlx -G --data-urlencode "name=agentry-remember-device" "$API/propertymappings/provider/scope/" | jget "(d['results'][0]['pk'] if d['results'] else '')")
[ -n "$AGENTRY_SCOPE_PK" ] || echo "warning: the blueprint's agentry-remember-device scope mapping is not there yet; re-run once authentik has applied agentry-account-flows.yaml, or no browser will be remembered" >&2
export AGENTRY_SCOPE_PK
SCOPE_MAPPINGS=$(python3 -c '
import json, os, sys
pks = json.loads(os.environ["SCOPE_MAPPINGS"])
pks = [p for p in pks if p != os.environ["EMAIL_MANAGED_PK"]] + [os.environ["VERIFIED_PK"]]
if os.environ.get("AGENTRY_SCOPE_PK"):
    pks.append(os.environ["AGENTRY_SCOPE_PK"])
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
    # The one grant the registry uses: authorization code + PKCE
    # (internal/auth/oidc; no refresh token is ever requested). authentik
    # 2026.8 made a provider's grants explicit: one created through the API
    # gets none and refuses every authorize request ("Invalid grant_type",
    # reaching the registry as invalid_request), and one migrated from an
    # older release got every grant, password and client_credentials
    # included, which let anything holding the client secret get tokens
    # without the browser flow. Sent on create and on refresh, so a re-run
    # narrows an existing provider (agentry#494).
    "grant_types": ["authorization_code"],
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

if [ -n "${AGENTRY_DASHBOARDS_URL:-}" ]; then
  # The log stack's Dashboards signs in here too (agentry#598). Its tokens
  # carry `roles`: ["agentry-reader"] for a member of the staff mirror group,
  # which the registry keeps equal to its platform staff, and nothing else;
  # the application is bound to the group, so nobody else is even given a
  # token. The group is written by the registry alone (AGENTRY_IDP_STAFF_MIRROR_GROUP
  # on the server); adding someone to it here is undone at its next run.
  DASH_URL="${AGENTRY_DASHBOARDS_URL%/}"
  MIRROR_GROUP="${AGENTRY_IDP_STAFF_MIRROR_GROUP:-agentry-staff}"
  DASH_CLIENT_ID="${AGENTRY_DASHBOARDS_CLIENT_ID:-agentry-dashboards}"
  DASH_SECRET_FILE="${AGENTRY_DASHBOARDS_SECRET_FILE:-${XDG_CONFIG_HOME:-$HOME/.config}/agentry/dashboards-oidc.env}"
  ( umask 077; mkdir -p "$(dirname "$DASH_SECRET_FILE")" )
  export DASH_URL MIRROR_GROUP DASH_CLIENT_ID

  echo "== Dashboards: the staff mirror group =="
  GROUP_PK=$(curlx -G --data-urlencode "name=$MIRROR_GROUP" "$API/core/groups/" | jget "(d['results'][0]['pk'] if d['results'] else '')")
  if [ -z "$GROUP_PK" ]; then
    GROUP_PK=$(curlx -X POST "$API/core/groups/" -d "$(python3 -c 'import json,os;print(json.dumps({"name":os.environ["MIRROR_GROUP"]}))')" | jget "d['pk']")
    echo "created group $MIRROR_GROUP"
  else
    echo "group $MIRROR_GROUP exists"
  fi

  echo "== Dashboards: the roles claim =="
  ROLES_NAME="Agentry: Dashboards roles (staff mirror)"; export ROLES_NAME
  ROLES_BODY=$(python3 -c '
import json, os
g = os.environ["MIRROR_GROUP"]
print(json.dumps({
  "name": os.environ["ROLES_NAME"], "scope_name": "roles",
  "description": "Dashboards reader role for platform staff",
  "expression": "# The registry keeps this group equal to its platform staff (agentry#598).\n"
                "return {\"roles\": [\"agentry-reader\"] if ak_is_group_member(request.user, name=%r) else []}" % g,
}))')
  ROLES_PK=$(curlx -G --data-urlencode "name=$ROLES_NAME" "$API/propertymappings/provider/scope/" | jget "(d['results'][0]['pk'] if d['results'] else '')")
  if [ -z "$ROLES_PK" ]; then
    ROLES_PK=$(curlx -X POST "$API/propertymappings/provider/scope/" -d "$ROLES_BODY" | jget "d['pk']")
    echo "created roles mapping $ROLES_PK"
  else
    curlx -X PATCH "$API/propertymappings/provider/scope/$ROLES_PK/" -d "$ROLES_BODY" -o /dev/null
    echo "updated roles mapping $ROLES_PK"
  fi

  echo "== Dashboards: the client secret =="
  DASH_SECRET=""
  if [ -f "$DASH_SECRET_FILE" ]; then
    DASH_SECRET=$(sed -n 's/^AGENTRY_DASHBOARDS_OIDC_CLIENT_SECRET=//p' "$DASH_SECRET_FILE" | tail -1)
  fi
  if [ -z "$DASH_SECRET" ]; then
    DASH_SECRET=$(python3 -c 'import secrets;print(secrets.token_urlsafe(48))')
    ( umask 077; printf 'AGENTRY_DASHBOARDS_OIDC_CLIENT_ID=%s\nAGENTRY_DASHBOARDS_OIDC_CLIENT_SECRET=%s\n' "$DASH_CLIENT_ID" "$DASH_SECRET" > "$DASH_SECRET_FILE" )
    echo "wrote a new client id and secret to $DASH_SECRET_FILE"
  else
    echo "kept the client secret in $DASH_SECRET_FILE"
  fi
  export DASH_SECRET ROLES_PK

  echo "== Dashboards: the provider =="
  DASH_BODY=$(python3 -c '
import json, os
dash = os.environ["DASH_URL"]
mappings = json.loads(os.environ["SCOPE_MAPPINGS"]) + [os.environ["ROLES_PK"]]
p = {
  "name": "agentry-dashboards", "authorization_flow": os.environ["AUTHZ_FLOW"],
  "client_type": "confidential", "client_id": os.environ["DASH_CLIENT_ID"],
  "client_secret": os.environ["DASH_SECRET"], "signing_key": os.environ["CERT"],
  "sub_mode": "hashed_user_id", "include_claims_in_id_token": True,
  "property_mappings": mappings,
  # Authorization code only, as the registry'"'"'s provider (agentry#494).
  "grant_types": ["authorization_code"],
  # OpenSearch Dashboards returns to <base_redirect_url>/auth/openid/login
  # and, signed out, to its base URL.
  "redirect_uris": [{"matching_mode": "strict", "url": dash + "/auth/openid/login", "redirect_uri_type": "authorization"},
                    {"matching_mode": "strict", "url": dash, "redirect_uri_type": "logout"}],
}
if os.environ.get("INVAL_FLOW"):
    p["invalidation_flow"] = os.environ["INVAL_FLOW"]
print(json.dumps(p))')
  # The body carries the client secret: on stdin, not curl's command line.
  DASH_PK=$(curlx "$API/providers/oauth2/?name=agentry-dashboards" | jget "(d['results'][0]['pk'] if d['results'] else '')")
  if [ -z "$DASH_PK" ]; then
    DASH_PK=$(printf '%s' "$DASH_BODY" | curlx -X POST "$API/providers/oauth2/" --data-binary @- | jget "d['pk']")
    echo "created provider pk=$DASH_PK"
  else
    printf '%s' "$DASH_BODY" | curlx -X PATCH "$API/providers/oauth2/$DASH_PK/" --data-binary @- -o /dev/null
    echo "updated provider pk=$DASH_PK"
  fi
  unset DASH_SECRET DASH_BODY

  echo "== Dashboards: the application, admitting the group alone =="
  # policy_engine_mode all: every bound policy must pass, so a policy bound
  # later cannot let anyone else in by itself.
  DASH_APP_BODY=$(DASH_PK="$DASH_PK" python3 -c "import json,os;print(json.dumps({'name':'Agentry Dashboards','slug':'agentry-dashboards','provider':int(os.environ['DASH_PK']),'meta_launch_url':os.environ['DASH_URL'],'open_in_new_tab':True,'policy_engine_mode':'all'}))")
  if [ "$(curlx "$API/core/applications/?slug=agentry-dashboards" | jget "d['pagination']['count']")" = "0" ]; then
    curlx -X POST "$API/core/applications/" -d "$DASH_APP_BODY" -o /dev/null
    echo "created application slug=agentry-dashboards"
  else
    curlx -X PATCH "$API/core/applications/agentry-dashboards/" -d "$DASH_APP_BODY" -o /dev/null
    echo "updated application slug=agentry-dashboards"
  fi
  DASH_APP_PK=$(curlx "$API/core/applications/agentry-dashboards/" | jget "d['pk']")
  # An expression policy, not a group binding: authentik deletes a group's
  # bindings with the group, which would leave the application open to every
  # directory account; the expression fails closed when the group is gone.
  POLICY_NAME="agentry-dashboards-staff-mirror"; export POLICY_NAME
  POLICY_BODY=$(python3 -c 'import json,os;print(json.dumps({"name":os.environ["POLICY_NAME"],"expression":"# The registry keeps this group equal to its platform staff (agentry#598).\nreturn ak_is_group_member(request.user, name=%r)" % os.environ["MIRROR_GROUP"]}))')
  POLICY_PK=$(curlx -G --data-urlencode "name=$POLICY_NAME" "$API/policies/expression/" | jget "(d['results'][0]['pk'] if d['results'] else '')")
  if [ -z "$POLICY_PK" ]; then
    POLICY_PK=$(curlx -X POST "$API/policies/expression/" -d "$POLICY_BODY" | jget "d['pk']")
    echo "created policy $POLICY_NAME"
  else
    curlx -X PATCH "$API/policies/expression/$POLICY_PK/" -d "$POLICY_BODY" -o /dev/null
    echo "updated policy $POLICY_NAME"
  fi
  if [ "$(curlx "$API/policies/bindings/?target=$DASH_APP_PK&policy=$POLICY_PK" | jget "d['pagination']['count']")" = "0" ]; then
    curlx -X POST "$API/policies/bindings/" -d "$(APP="$DASH_APP_PK" POL="$POLICY_PK" python3 -c "import json,os;print(json.dumps({'target':os.environ['APP'],'policy':os.environ['POL'],'order':0,'enabled':True,'negate':False,'timeout':30}))")" -o /dev/null
    echo "bound application to $POLICY_NAME"
  else
    echo "application already bound to $POLICY_NAME"
  fi
  echo "== Dashboards issuer (the log stack's OpenID connect URL) =="
  echo "$AUTHENTIK_URL/application/o/agentry-dashboards/.well-known/openid-configuration"
  echo "client id and secret: $DASH_SECRET_FILE"
fi

echo "== issuer (AGENTRY_SOCIAL_AUTHENTIK_ISSUER) =="
echo "$AUTHENTIK_URL/application/o/agentry/"
# The cancel view drops a flow plan the session may still hold before the
# provider's end-session runs; without it that plan turns sign-out into an
# empty page (agentry#441).
echo "== sign-out URL (AGENTRY_IDP_LOGOUT_URL) =="
echo "$AUTHENTIK_URL/flows/-/cancel/?next=/application/o/agentry/end-session/"
echo "BOOTSTRAP OK"
