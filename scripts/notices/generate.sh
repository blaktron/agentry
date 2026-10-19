#!/usr/bin/env bash
# Regenerate THIRD_PARTY_NOTICES, the licence and NOTICE texts of the Go
# modules compiled into agentryd (the file the container image ships), or
# verify it.
#
#   scripts/notices/generate.sh           rewrite THIRD_PARTY_NOTICES
#   scripts/notices/generate.sh --check   fail when the committed file is stale
#
# The output is deterministic: every platform agentryd is released for, modules
# sorted by path, no timestamps. It reads the Go module cache only, so with
# the modules already downloaded (`go mod download`) it needs no network.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

case "${1:-}" in
  "")      exec go run ./scripts/notices ;;
  --check) exec go run ./scripts/notices -check ;;
  *)       echo "usage: scripts/notices/generate.sh [--check]" >&2; exit 2 ;;
esac
