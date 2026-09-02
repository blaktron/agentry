#!/usr/bin/env bash
# lighthouse-a11y.sh BASE_URL [PAGE ...]
#
# §17.1 / §18.2 M5: "Lighthouse a11y ≥ 90 on public pages" (DEV-031's open
# half, agentry#42). Runs Lighthouse's accessibility category against each
# page with headless Chromium and fails when any page scores below the
# threshold. Meant to run inside e2e-browser.sh against the booted stack (the
# Playwright Chromium is reused), and by hand against any deployment:
#
#   ./scripts/acceptance/lighthouse-a11y.sh https://dev.secureagentry.net / /search /trust
#
# LH_MIN (default 90) is the threshold; CHROME_PATH overrides browser
# discovery; LH_VERSION pins the Lighthouse release npx fetches.
set -euo pipefail
BASE="${1:?base url}"; shift || true
PAGES=("$@")
if [ ${#PAGES[@]} -eq 0 ]; then
  PAGES=(/ /search /login /trust /about /advisories /privacy /terms /download /build)
fi
MIN="${LH_MIN:-90}"
LH_VERSION="${LH_VERSION:-12.8.2}"
if [ -z "${CHROME_PATH:-}" ]; then
  CHROME_PATH="$(ls -d "$HOME"/.cache/ms-playwright/chromium-*/chrome-linux*/chrome 2>/dev/null | sort | tail -1 || true)"
  [ -n "$CHROME_PATH" ] || CHROME_PATH="$(command -v chromium || command -v chromium-browser || command -v google-chrome || true)"
fi
[ -n "$CHROME_PATH" ] || { echo "no Chromium found — run 'npx playwright install chromium' in web/ or set CHROME_PATH"; exit 1; }
export CHROME_PATH
OUT="$(mktemp -d)"; trap 'rm -rf "$OUT"' EXIT
fail=0
printf '%-28s %5s  %s\n' page score failing-audits
for p in "${PAGES[@]}"; do
  f="$OUT/$(echo "$p" | tr '/?&=' '____').json"
  if ! (cd web && npx --yes "lighthouse@$LH_VERSION" "$BASE$p" --only-categories=accessibility \
        --output=json --output-path="$f" --quiet \
        --chrome-flags="--headless=new --no-sandbox --disable-gpu" >/dev/null 2>"$OUT/err.log"); then
    echo "lighthouse failed on $p:"; tail -5 "$OUT/err.log"; fail=1; continue
  fi
  python3 - "$f" "$p" "$MIN" "$BASE" <<'PY' || fail=1
import json, sys
r = json.load(open(sys.argv[1])); page, minimum, base = sys.argv[2], int(sys.argv[3]), sys.argv[4]
final = r.get("finalDisplayedUrl", "")
if not final.startswith(base):
    print(f"{page:28s} {'skip':>5}  redirected off-site ({final[:60]})"); sys.exit(0)
score = int(round((r["categories"]["accessibility"]["score"] or 0) * 100))
fails = [a["id"] for a in r["audits"].values()
         if a.get("score") is not None and a["score"] < 1 and a.get("scoreDisplayMode") in ("binary", "numeric")]
print(f"{page:28s} {score:5d}  {', '.join(fails)}")
for a in r["audits"].values():
    if a["id"] in fails:
        for it in (a.get("details") or {}).get("items", [])[:3]:
            n = it.get("node") or {}
            print(f"{'':28s}        {a['id']}: {(n.get('selector') or '')[:70]} | {(n.get('snippet') or '')[:100]}")
sys.exit(0 if score >= minimum else 1)
PY
done
if [ "$fail" -ne 0 ]; then echo "LIGHTHOUSE A11Y FAILED (min $MIN)"; exit 1; fi
echo "LIGHTHOUSE A11Y PASSED (min $MIN)"
