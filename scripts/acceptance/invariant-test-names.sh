#!/usr/bin/env bash
# Every test ARCHITECTURE.md §9 names for a core row exists under that name
# (agentry#420): a renamed or deleted test must not keep standing as the
# evidence for an invariant.
#
#   invariant-test-names.sh              check scripts/acceptance/invariant-tests.txt
#                                  against `go test -list` over the module
#   invariant-test-names.sh --from FILE  also compare the list with the test names
#                                  in FILE's §9, to keep the two in sync
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
  echo "§9 names tests this module does not have (renamed, deleted, or never written):" >&2
  printf '  %s\n' $missing >&2
  echo "section 9 test names: FAILED" >&2
  exit 1
fi
echo "section 9 test names: OK ($(printf '%s\n' "$want" | wc -l | tr -d ' ') tests found under the names §9 gives)"

if [ "${1:-}" = "--from" ]; then
  arch=${2:?usage: invariant-test-names.sh --from ARCHITECTURE.md}
  cited=$(awk '/^## 9\. /{f=1; next} /^## /{f=0} f' "$arch" | grep -oE '\bTest[A-Za-z0-9_]+' | sort -u)
  echo "-- §9 names that are tests here but missing from $list (add them):"
  comm -12 <(printf '%s\n' "$cited") "$have" | comm -23 - <(printf '%s\n' "$want") | sed 's/^/  /'
  echo "-- names in $list that §9 no longer cites (remove them):"
  comm -13 <(printf '%s\n' "$cited") <(printf '%s\n' "$want") | sed 's/^/  /'
  echo "-- §9 names that are not tests here (another repository's row, or a broken citation to fix in §9):"
  comm -23 <(printf '%s\n' "$cited") "$have" | sed 's/^/  /'
fi
