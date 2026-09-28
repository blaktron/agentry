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
# Since agentry#720 the frame's header shows the Agentry mark inline. It
# names cid:logo, and authentik attaches whatever PNG is at its logo path;
# the compose stack mounts the core's mark there
# (deploy/compose/authentik/brand/mail-logo.png). The script puts the same
# file at that path and checks that the attachment authentik builds is that
# file, byte for byte, and not authentik's own logo.
#
# Needs docker and the image the compose file pins; no database, no network
# beyond pulling that image.
set -euo pipefail
cd "$(cd "$(dirname "$0")/../.." && pwd)"
echo "== directory email acceptance =="

BLUEPRINT=deploy/compose/authentik/blueprints/agentry-account-flows.yaml
TEMPLATES=deploy/compose/authentik/templates
LOGO=deploy/compose/authentik/brand/mail-logo.png
# authentik reads its mail logo from this path, relative to its working
# directory (authentik/stages/email/utils.py, logo_data()).
LOGO_PATH=/web/dist/assets/icons/icon_left_brand.png
[ -f "$LOGO" ] || { echo "FAIL: $LOGO is missing"; exit 1; }
LOGO_SHA=$(sha256sum "$LOGO" | cut -d' ' -f1)
IMAGE="${AUTHENTIK_IMAGE:-$(awk '/image: ghcr.io\/goauthentik\/server:/{print $2; exit}' deploy/compose/docker-compose.yaml)}"
[ -n "$IMAGE" ] || { echo "FAIL: no authentik image pinned in the compose file"; exit 1; }

# Every email stage in the blueprint, and the template each one names. Two
# today (enrollment, recovery): a third stage fails here on purpose, so its
# mail gets a template and a check before it ships.
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
  -e LOGO_SHA="$LOGO_SHA" \
  "$IMAGE" - "${NAMES[@]}")
trap 'docker rm -f "$cid" >/dev/null 2>&1 || true' EXIT
docker cp "$TEMPLATES/." "$cid:/templates" >/dev/null
docker cp "$LOGO" "$cid:$LOGO_PATH" >/dev/null
set +e
docker start -ai "$cid" <<'PY' 2>&1 | grep -v '"level": "info"'
import hashlib
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import django

django.setup()
from authentik.stages.email.utils import TemplateEmailMessage, logo_data  # noqa: E402

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
    # The header's mark: one inline image, cid:logo, which authentik attaches
    # (tasks.py attaches logo_data() whenever the body names cid:logo). No
    # other image, so nothing remote to block or track.
    imgs = re.findall(r"<img\b[^>]*>", html, re.I)
    check(f"{name}: one image, the inline mark (cid:logo)", len(imgs) == 1 and 'src="cid:logo"' in imgs[0])
    check(f"{name}: the mark has a size and empty alt text", len(imgs) == 1 and 'width="' in imgs[0] and 'height="' in imgs[0] and 'alt=""' in imgs[0])
    check(f"{name}: no other cid: reference", html.count("cid:") == 1)
    check(f"{name}: states the link's lifetime", "minute" in text)

# What authentik attaches for cid:logo is the core's mark, not its own logo.
logo = logo_data()
payload = logo.get_payload(decode=True)
check("the attached logo is the core's mail-logo.png", hashlib.sha256(payload).hexdigest() == os.environ["LOGO_SHA"])
check("the attached logo's Content-ID is <logo>", logo["Content-ID"] == "<logo>")

sys.exit(1 if failures else 0)
PY
st=${PIPESTATUS[0]}
set -e
[ "$st" -eq 0 ] || { echo "FAIL: directory email acceptance"; exit 1; }
echo "PASS: directory email acceptance"
