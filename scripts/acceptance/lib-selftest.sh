#!/usr/bin/env bash
# The acceptance helper refuses what used to print OK (agentry#420): a -run
# filter that matches nothing, a list with one name that matches nothing, and
# a test that skips. Runs in CI beside the §9 name check; needs no database.
set -euo pipefail
cd "$(cd "$(dirname "$0")/../.." && pwd)"

# must_fail DESCRIPTION [gotest arguments...]: the helper, in a subshell,
# must exit non-zero and print no OK line.
must_fail() {
  local what=$1
  shift
  local out
  if out=$(. scripts/acceptance/lib.sh && gotest "$what" "$@" 2>/dev/null); then
    echo "helper self-test: FAILED: '$what' passed: $out" >&2
    exit 1
  fi
  if grep -q ': OK$' <<<"$out"; then
    echo "helper self-test: FAILED: '$what' printed OK" >&2
    exit 1
  fi
  echo "refused as it should be: $what"
}

must_fail "a filter that matches no test" ./pkg/archive -run 'TestNoSuchTestAnywhere' -count=1
must_fail "a list with one name that matches no test" ./pkg/archive -run 'TestArchiveReproducible|TestNoSuchTestAnywhere' -count=1
must_fail "two packages, one with no match" ./pkg/archive ./pkg/manifest -run 'TestArchiveReproducible' -count=1
AGENTRY_TEST_DATABASE_URL='' must_fail "a test that skips" ./internal/notify -run 'TestAllowsEmailFailureDirections' -count=1

# And it still says OK for a run that checked what it names.
. scripts/acceptance/lib.sh
gotest "a named test that passes" ./pkg/archive -run 'TestArchiveReproducible$' -count=1
echo "== acceptance helper self-test PASSED =="
