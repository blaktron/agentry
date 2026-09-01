#!/usr/bin/env bash
# Build the downloadable binaries the web app's /download page serves, plus
# the manifest it renders from.
#
#   scripts/release/build-downloads.sh [OUT_DIR]
#
# Produces, in OUT_DIR (default ./dist/downloads):
#   agentry-<ver>-<os>-<arch>[.exe]          the CLI, every target below
#   agentry-desktop-<ver>-linux-amd64        the desktop app, when this host
#                                            can build it (Linux + GTK/WebKit
#                                            dev headers); other desktop
#                                            targets need their own host
#   SHA256SUMS                               one line per artifact
#   manifest.json                            what the page reads: version,
#                                            file, size, sha256 per artifact
#
# The CLI is pure Go, so it cross-compiles from anywhere with CGO off. The
# desktop app is a Wails/CGO build and is only attempted for the host's own
# platform; targets that were not built are simply absent from the manifest,
# and the page shows them as not yet available rather than as broken links.
#
# Sibling checkouts are expected at ../agentry-cli and ../agentry-desktop
# (override with AGENTRY_CLI_DIR / AGENTRY_DESKTOP_DIR). Versions come from
# `git describe` in each repo.
set -euo pipefail

here=$(cd "$(dirname "$0")/../.." && pwd)
OUT=${1:-"$here/dist/downloads"}
CLI_DIR=${AGENTRY_CLI_DIR:-"$here/../agentry-cli"}
DESKTOP_DIR=${AGENTRY_DESKTOP_DIR:-"$here/../agentry-desktop"}
GO=${GO:-go}

mkdir -p "$OUT"
rm -f "$OUT"/agentry-* "$OUT"/SHA256SUMS "$OUT"/manifest.json

describe() { (cd "$1" && git describe --tags --always --dirty 2>/dev/null || echo 0.0.0-dev); }

CLI_VERSION=$(describe "$CLI_DIR")
DESKTOP_VERSION=$(describe "$DESKTOP_DIR")

# The registry these binaries talk to when the user configures nothing.
# Set it to the site that will serve them, so a download from /download
# connects back to that site by default. Empty keeps the source defaults
# (CLI: http://localhost:8080; desktop: the production URL).
REGISTRY_LDFLAGS=""
DESKTOP_REGISTRY_LDFLAGS=""
if [ -n "${AGENTRY_DEFAULT_REGISTRY:-}" ]; then
  REGISTRY_LDFLAGS=" -X main.defaultRegistryURL=${AGENTRY_DEFAULT_REGISTRY}"
  DESKTOP_REGISTRY_LDFLAGS=" -X github.com/blaktron/agentry-desktop/internal/settings.DefaultRegistryURL=${AGENTRY_DEFAULT_REGISTRY}"
fi
echo "cli $CLI_VERSION · desktop $DESKTOP_VERSION · default registry ${AGENTRY_DEFAULT_REGISTRY:-<source default>} → $OUT"

# ---- CLI: linux/darwin/windows ------------------------------------------
CLI_TARGETS="linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64"
for t in $CLI_TARGETS; do
  os=${t%/*}; arch=${t#*/}
  ext=""; [ "$os" = windows ] && ext=.exe
  file="agentry-${CLI_VERSION}-${os}-${arch}${ext}"
  echo "  cli  $os/$arch"
  (cd "$CLI_DIR" && CGO_ENABLED=0 GOOS=$os GOARCH=$arch $GO build -trimpath \
     -ldflags "-s -w -X github.com/blaktron/agentry-cli/internal/version.Version=${CLI_VERSION}${REGISTRY_LDFLAGS}" \
     -o "$OUT/$file" ./cmd/agentry)
done

# ---- Desktop: this host only ---------------------------------------------
desktop_built=""
if [ "$(uname -s)" = Linux ] && [ "$(uname -m)" = x86_64 ] \
   && pkg-config --exists gtk+-3.0 webkit2gtk-4.1 2>/dev/null; then
  file="agentry-desktop-${DESKTOP_VERSION}-linux-amd64"
  echo "  desktop linux/amd64"
  if [ ! -f "$DESKTOP_DIR/frontend/dist/index.html" ]; then
    echo "    (frontend/dist missing — building it)"
    (cd "$DESKTOP_DIR/frontend" && npm ci --silent && npm run build --silent)
  fi
  (cd "$DESKTOP_DIR" && CGO_ENABLED=1 $GO build -trimpath -tags "desktop production webkit2_41" \
     -ldflags "-s -w -X github.com/blaktron/agentry-desktop/internal/version.Version=${DESKTOP_VERSION}${DESKTOP_REGISTRY_LDFLAGS}" \
     -o "$OUT/$file" .)
  desktop_built=$file
else
  echo "  desktop: skipped (needs Linux x86_64 with gtk+-3.0 and webkit2gtk-4.1 dev headers)"
fi

# ---- checksums + manifest ------------------------------------------------
(cd "$OUT" && sha256sum agentry-* > SHA256SUMS)

python3 - "$OUT" "$CLI_VERSION" "$DESKTOP_VERSION" "${AGENTRY_DEFAULT_REGISTRY:-}" <<'PY'
import hashlib, json, os, re, sys, datetime
out, cli_v, desk_v, default_registry = sys.argv[1:5]
arts = []
for name in sorted(os.listdir(out)):
    if not name.startswith("agentry-") or name in ("SHA256SUMS", "manifest.json"):
        continue
    m = re.match(r"^(agentry(?:-desktop)?)-(.+)-(linux|darwin|windows)-(amd64|arm64|universal)(\.exe)?$", name)
    if not m:
        continue
    product = "desktop" if m.group(1) == "agentry-desktop" else "cli"
    path = os.path.join(out, name)
    h = hashlib.sha256(open(path, "rb").read()).hexdigest()
    arts.append({
        "product": product, "os": m.group(3), "arch": m.group(4), "file": name,
        "version": m.group(2), "sizeBytes": os.path.getsize(path), "sha256": h,
    })
json.dump({
    "generatedAt": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "cli": {"version": cli_v}, "desktop": {"version": desk_v},
    "defaultRegistry": default_registry or None,
    "artifacts": arts,
}, open(os.path.join(out, "manifest.json"), "w"), indent=2)
print(f"manifest: {len(arts)} artifacts")
PY

ls -la "$OUT"
