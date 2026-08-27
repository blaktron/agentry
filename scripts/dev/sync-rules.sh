#!/usr/bin/env bash
# Sync the canonical /rules bundle into the embeddable copy under
# internal/scan/ruleset/rules (go:embed cannot reach outside a package dir).
# --check fails (CI) when the copy has drifted.
set -euo pipefail
cd "$(cd "$(dirname "$0")/../.." && pwd)"
SRC=rules
DST=internal/scan/ruleset/rules

if [ "${1:-}" = "--check" ]; then
  for f in "$SRC"/*.yaml; do
    base="$(basename "$f")"
    if ! diff -q "$f" "$DST/$base" >/dev/null 2>&1; then
      echo "ruleset copy drifted: $base — run 'make sync-rules'"; exit 1
    fi
  done
  echo "ruleset copy in sync"
else
  cp "$SRC"/*.yaml "$DST"/
  echo "synced $SRC -> $DST"
fi
