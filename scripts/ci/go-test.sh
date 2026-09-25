#!/usr/bin/env bash
# go test with a verdict a reader can find (agentry#452). It runs
# `go test "$@"` unchanged and passes its exit status through; when a
# package was killed by -timeout it also says so in one line, naming the
# package and the tests that were running, and whether any test failed. A
# timeout used to be legible only by reading a goroutine dump that named
# whatever happened to be running, which looked like a failing test.
set -uo pipefail
GO=${GO:-go}
log=$(mktemp)
trap 'rm -f "$log"' EXIT

"$GO" test "$@" 2>&1 | tee "$log"
st=${PIPESTATUS[0]}
[ "$st" -eq 0 ] && exit 0

if grep -q '^panic: test timed out after' "$log"; then
  after=$(grep -m1 '^panic: test timed out after' "$log" | awk '{print $NF}')
  # The package is the first FAIL line after the panic; the tests running
  # when it was killed are listed under "running tests:".
  pkg=$(awk '/^panic: test timed out after/{p=1} p && /^FAIL[ \t]/{print $2; exit}' "$log")
  running=$(awk '/^[ \t]*running tests:/{f=1; next} f && /^[ \t][ \t]/{sub(/^[ \t]+/, ""); printf "%s; ", $0; next} {f=0}' "$log")
  if grep -qE '^[ \t]*--- FAIL:' "$log"; then
    failed="Some test also failed: see the --- FAIL lines."
  else
    failed="No test failed."
  fi
  msg="${pkg:-a package} overran the go test timeout ($after) and was killed${running:+ while running: ${running%; }}. $failed The goroutine dump above is the kill, not a failure. The timeout's sizing is in the Makefile (agentry#452)."
  if [ -n "${GITHUB_ACTIONS:-}" ]; then
    echo "::error title=go test timeout::$msg"
  fi
  echo "go test: $msg" >&2
fi
exit "$st"
