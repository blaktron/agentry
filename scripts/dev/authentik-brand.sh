#!/usr/bin/env bash
# Apply the SecureAgentry brand to the directory service (DEV-057):
# title, wordmark, favicon, flow background, and the custom CSS in
# deploy/compose/authentik/branding.css. Idempotent — PATCHes the default
# brand; safe to re-run after editing the CSS or assets.
#
# Required environment:
#   AUTHENTIK_URL              e.g. https://agentry.tail49832b.ts.net:8443
#   AUTHENTIK_BOOTSTRAP_TOKEN  the API token first boot created
#   ASSET_BASE                 where web/public is served from, e.g.
#                              https://agentry.tail49832b.ts.net
# Optional: CURL_FLAGS (e.g. -k during a self-signed bootstrap).
set -euo pipefail

: "${AUTHENTIK_URL:?}" "${AUTHENTIK_BOOTSTRAP_TOKEN:?}" "${ASSET_BASE:?}"
API="$AUTHENTIK_URL/api/v3"
CSS_FILE="$(dirname "$0")/../../deploy/compose/authentik/branding.css"
[ -f "$CSS_FILE" ] || { echo "FAIL: $CSS_FILE not found"; exit 1; }

auth=(-H "Authorization: Bearer $AUTHENTIK_BOOTSTRAP_TOKEN" -H "Content-Type: application/json")
curlx() { curl -fsS ${CURL_FLAGS:-} "${auth[@]}" "$@"; }

UUID=$(curlx "$API/core/brands/" | python3 -c "
import sys, json
for b in json.load(sys.stdin)['results']:
    if b.get('default'):
        print(b['brand_uuid']); break")
[ -n "$UUID" ] || { echo "FAIL: no default brand"; exit 1; }
echo "default brand: $UUID"

BODY=$(ASSET_BASE="$ASSET_BASE" CSS_FILE="$CSS_FILE" python3 <<'PY'
import json, os
base = os.environ["ASSET_BASE"].rstrip("/")
print(json.dumps({
    "branding_title": "SecureAgentry",
    "branding_logo": f"{base}/brand/wordmark.svg",
    "branding_favicon": f"{base}/brand/mark.svg",
    "branding_default_flow_background": f"{base}/brand/flow-bg.svg",
    "branding_custom_css": open(os.environ["CSS_FILE"]).read(),
}))
PY
)
# The sign-in card's heading is the flow's own title, not brand config.
curlx -X PATCH "$API/flows/instances/default-authentication-flow/" \
  -d '{"title": "Sign in to SecureAgentry"}' -o /dev/null && echo "flow title set"

curlx -X PATCH "$API/core/brands/$UUID/" -d "$BODY" | python3 -c "
import sys, json
b = json.load(sys.stdin)
print('title:   ', b['branding_title'])
print('logo:    ', b['branding_logo'])
print('favicon: ', b['branding_favicon'])
print('flow bg: ', b['branding_default_flow_background'])
print('css:     ', len(b.get('branding_custom_css') or ''), 'bytes')"
echo "BRAND OK"
