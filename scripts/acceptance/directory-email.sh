#!/usr/bin/env bash
# Directory email acceptance (agentry#518): the mails the directory sends a
# person (the sign-up confirmation and the password-reset link) are the
# core's own templates, not authentik's stock ones.
#
# authentik's defaults embed its logo (an inline cid:logo image it attaches
# whenever the body names it), end "Powered by authentik" and call the
# account "your authentik account". This script checks the account-flows
# blueprint names templates the core ships, then renders each one through
# authentik's own TemplateEmailMessage in the pinned image (the class the
# email stage sends with, the context it passes: url, user, expires, token)
# and asserts on what a recipient would get: the link in both parts, the
# deployment's name, and no trace of authentik.
#
# Needs docker and the image the compose file pins; no database, no network
# beyond pulling that image.
set -euo pipefail
cd "$(cd "$(dirname "$0")/../.." && pwd)"
echo "== directory email acceptance =="

BLUEPRINT=deploy/compose/authentik/blueprints/agentry-account-flows.yaml
TEMPLATES=deploy/compose/authentik/templates
IMAGE="${AUTHENTIK_IMAGE:-$(awk '/image: ghcr.io\/goauthentik\/server:/{print $2; exit}' deploy/compose/docker-compose.yaml)}"
[ -n "$IMAGE" ] || { echo "FAIL: no authentik image pinned in the compose file"; exit 1; }

# Every email stage in the blueprint, and the template each one names.
mapfile -t NAMES < <(awk '
  /model: authentik_stages_email.emailstage/ {in_stage=1; next}
  /^  - model:/ {in_stage=0}
  in_stage && $1 == "template:" {print $2}' "$BLUEPRINT")
[ "${#NAMES[@]}" -eq 2 ] || { echo "FAIL: expected 2 email stages in $BLUEPRINT, found ${#NAMES[@]}"; exit 1; }
for name in "${NAMES[@]}"; do
  case "$name" in
    agentry/*.html) ;;
    *) echo "FAIL: an email stage uses $name, not one of the core's agentry/ templates"; exit 1 ;;
  esac
  for f in "$TEMPLATES/$name" "$TEMPLATES/${name%.html}.txt"; do
    [ -f "$f" ] || { echo "FAIL: $name: $f is missing"; exit 1; }
  done
  echo "ok   stage template $name (html and txt)"
done

# The templates go in with docker cp, not a bind mount: a CI job may drive
# the host's daemon from inside a runner container, where the checkout's
# path means nothing to the daemon (and an SELinux host would refuse the
# container a home-directory mount anyway).
cid=$(docker create -i --entrypoint python \
  -e AUTHENTIK_SECRET_KEY=acceptance-only \
  -e AUTHENTIK_LOG_LEVEL=error \
  -e DJANGO_SETTINGS_MODULE=authentik.root.settings \
  "$IMAGE" - "${NAMES[@]}")
trap 'docker rm -f "$cid" >/dev/null 2>&1 || true' EXIT
docker cp "$TEMPLATES" "$cid:/templates" >/dev/null
set +e
docker start -ai "$cid" <<'PY' 2>&1 | grep -v '^{'
import sys
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import django

django.setup()
from authentik.stages.email.utils import TemplateEmailMessage  # noqa: E402

URL = "https://auth.example.test/if/flow/agentry-enrollment/?flow_token=tok-3f9a&x=1"
failures = []


def check(label, cond):
    print(("ok   " if cond else "FAIL ") + label)
    if not cond:
        failures.append(label)


for name in sys.argv[1:]:
    msg = TemplateEmailMessage(
        subject="acceptance",
        to=[("Ada Example", "ada@example.test")],
        template_name=name,
        template_context={
            "url": URL,
            "user": SimpleNamespace(username="ada", name="Ada Example", email="ada@example.test"),
            "expires": datetime.now(timezone.utc) + timedelta(minutes=30),
            "token": "tok-3f9a",
        },
    )
    text = msg.body
    html = msg.alternatives[0][0] if msg.alternatives else ""
    check(f"{name}: renders an HTML part and a text part", bool(html.strip()) and bool(text.strip()))
    # The HTML part escapes & in the link; the text part is autoescape-off.
    check(f"{name}: the link is in both parts", URL.replace("&", "&amp;") in html and URL in text)
    check(f"{name}: names Agentry in both parts", "Agentry" in html and "Agentry" in text)
    for part, body in (("html", html), ("text", text)):
        check(f"{name} ({part}): never mentions authentik", "authentik" not in body.lower())
    # authentik attaches its logo to any mail whose body contains cid:logo.
    check(f"{name}: no inline-image reference (cid:)", "cid:" not in html)
    check(f"{name}: no remote image to block or track", "<img" not in html.lower())
    check(f"{name}: states the link's lifetime", "minute" in text)

sys.exit(1 if failures else 0)
PY
st=${PIPESTATUS[0]}
set -e
[ "$st" -eq 0 ] || { echo "FAIL: directory email acceptance"; exit 1; }
echo "PASS: directory email acceptance"
