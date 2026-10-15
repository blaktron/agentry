#!/usr/bin/env bash
# Resolve (and build if needed) the agentry CLI, which lives in its own repo,
# github.com/blaktron/agentry-cli. Prints the binary path.
#
# Resolution order:
#   1. $AGENTRY_CLI_BIN            — an existing binary
#   2. $AGENTRY_CLI_SRC            — a checkout to build from
#   3. ../agentry-cli              — the conventional sibling checkout
#   4. clone github.com/blaktron/agentry-cli (uses $AGENTRY_GIT_TOKEN if set)
#
# The CLI module depends on this main module; building it needs GOPRIVATE and
# git access to github.com/blaktron (builders have access to all the repos).
set -euo pipefail
cd "$(cd "$(dirname "$0")/../.." && pwd)"
export PATH=/opt/homebrew/bin:$PATH

if [ -n "${AGENTRY_CLI_BIN:-}" ] && [ -x "${AGENTRY_CLI_BIN}" ]; then
  echo "$AGENTRY_CLI_BIN"; exit 0
fi

SRC="${AGENTRY_CLI_SRC:-}"
if [ -z "$SRC" ] && [ -d ../agentry-cli/cmd/agentry ]; then
  SRC=../agentry-cli
fi
if [ -z "$SRC" ]; then
  SRC=.devdata/agentry-cli
  if [ ! -d "$SRC/cmd/agentry" ]; then
    URL=https://github.com/blaktron/agentry-cli.git
    if [ -n "${AGENTRY_GIT_TOKEN:-}" ]; then
      URL="https://x-access-token:${AGENTRY_GIT_TOKEN}@github.com/blaktron/agentry-cli.git"
    fi
    git clone --depth 1 "$URL" "$SRC" >&2
  fi
fi

OUT="$(cd "$SRC" && pwd)/bin/agentry"
export GOPRIVATE="${GOPRIVATE:-github.com/blaktron/*}"
if [ -n "${AGENTRY_GIT_TOKEN:-}" ]; then
  export GIT_CONFIG_COUNT=1 \
    GIT_CONFIG_KEY_0="url.https://x-access-token:${AGENTRY_GIT_TOKEN}@github.com/blaktron/.insteadOf" \
    GIT_CONFIG_VALUE_0="https://github.com/blaktron/"
fi
(cd "$SRC" && go build -o bin/agentry ./cmd/agentry) >&2
echo "$OUT"
