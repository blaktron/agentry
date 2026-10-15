#!/usr/bin/env bash
# Every test named as evidence for a security invariant exists under that
# name: a renamed or deleted test must not keep standing as the evidence.
#
#   invariant-test-names.sh              check scripts/acceptance/invariant-tests.txt
#                                  against `go test -list` over the module
#   invariant-test-names.sh --from FILE  also compare the list with the test names
#                                  in the `## 9.` section of the Markdown file
#                                  FILE, to keep the two in sync
set -euo pipefail
cd "$(cd "$(dirname "$0")/../.." && pwd)"

list=scripts/acceptance/invariant-tests.txt
have=$(mktemp)
trap 'rm -f "$have"' EXIT
# `go test -list` compiles each package's tests and prints the top-level
# tests, fuzz targets and examples it would run: build tags and _test files
# a grep would miscount are accounted for.
go test -list '.' ./... | grep -E '^(Test|Fuzz|Example)' | sort -u >"$have"

want=$(grep -vE '^\s*(#|$)' "$list" | sort -u)
missing=$(comm -23 <(printf '%s\n' "$want") "$have")
if [ -n "$missing" ]; then
  echo "the invariant list names tests this module does not have (renamed, deleted, or never written):" >&2
  printf '  %s\n' $missing >&2
  echo "invariant test names: FAILED" >&2
  exit 1
fi
echo "invariant test names: OK ($(printf '%s\n' "$want" | wc -l | tr -d ' ') tests found under the listed names)"

if [ "${1:-}" = "--from" ]; then
  arch=${2:?usage: invariant-test-names.sh --from FILE.md}
  cited=$(awk '/^## 9\. /{f=1; next} /^## /{f=0} f' "$arch" | grep -oE '\bTest[A-Za-z0-9_]+' | sort -u)
  echo "-- tests named in $arch that exist here but are missing from $list (add them):"
  comm -12 <(printf '%s\n' "$cited") "$have" | comm -23 - <(printf '%s\n' "$want") | sed 's/^/  /'
  echo "-- names in $list that $arch no longer cites (remove them):"
  comm -13 <(printf '%s\n' "$cited") <(printf '%s\n' "$want") | sed 's/^/  /'
  echo "-- names in $arch that are not tests here (another repository's test, or a broken citation to fix there):"
  comm -23 <(printf '%s\n' "$cited") "$have" | sed 's/^/  /'
fi
