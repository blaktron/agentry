# shellcheck shell=bash
# Shared by the acceptance scripts: sourced, never run.

# gotest LABEL [go test arguments...]
#
# Runs `go test -v` with the arguments and prints "LABEL: OK" only when the
# run checked something:
#   - go test exited 0;
#   - no package answered "no tests to run" (a -run filter that matches
#     nothing exits 0 and would otherwise print OK for an invariant never checked);
#   - at least one top-level test passed, and none was skipped (a test that
#     skips, for want of a database or a tool, checked nothing);
#   - every alternative of the -run filter (split on "|", anchors dropped)
#     names a test or subtest that passed, so one renamed test in a list
#     cannot hide behind the others.
# Anything else prints the reason and the output's tail on stderr and exits
# the script non-zero, whatever `set -e` would have done with an && list.
gotest() {
  local label=$1
  shift
  local run="" prev="" a
  for a in "$@"; do
    [ "$prev" = "-run" ] && run=$a
    case $a in -run=*) run=${a#-run=} ;; esac
    prev=$a
  done
  local out st=0
  out=$(go test -v "$@" 2>&1) || st=$?
  local why=""
  if [ "$st" -ne 0 ]; then
    why="go test exited $st"
  elif grep -q 'no tests to run' <<<"$out"; then
    why="a package matched no test: $(grep -E '^ok .*no tests to run' <<<"$out" | awk '{print $2}' | tr '\n' ' ')"
  elif ! grep -q '^--- PASS: ' <<<"$out"; then
    why="no test passed"
  elif grep -q '^--- SKIP: ' <<<"$out"; then
    why="skipped, so nothing was checked: $(grep '^--- SKIP: ' <<<"$out" | sed 's/^--- SKIP: //; s/ (.*//' | tr '\n' ' ')"
  elif [ -n "$run" ]; then
    local -a alts
    IFS='|' read -r -a alts <<<"$run"
    for a in "${alts[@]}"; do
      a=${a#^}
      a=${a%\$}
      [ -z "$a" ] && continue
      if ! grep -qF -- "--- PASS: $a" <<<"$out"; then
        why="the -run alternative '$a' matched no passing test"
        break
      fi
    done
  fi
  if [ -n "$why" ]; then
    printf '%s\n' "$out" | tail -40 >&2
    echo "$label: FAILED ($why)" >&2
    exit 1
  fi
  echo "$label: OK"
}

# seed_session HANDLE
#
# Makes an account HANDLE with a verified address at example.test and opens
# a session for it, straight in the acceptance database through
# scripts/dev/dbexec, as the sign-in callback does once the deployment's
# OpenID provider has vouched for the person: the server keeps no password
# to sign in with, and a script has no provider to sign in at. Sets SESSION
# and CSRF; only the session token's SHA-256 is stored, as the server
# stores it.
seed_session() {
  local handle=$1
  SESSION="agys_$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
  CSRF="csrf_$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
  go run ./scripts/dev/dbexec \
    "INSERT INTO handles (id, handle, kind) VALUES (gen_random_uuid(), '$handle', 'user')" \
    "INSERT INTO users (id, email, display_name, email_verified_at) SELECT id, '$handle@example.test', '$handle', now() FROM handles WHERE handle = '$handle'" \
    "INSERT INTO sessions (id, user_id, token_sha256, csrf_token, expires_at) SELECT gen_random_uuid(), id, sha256(convert_to('$SESSION', 'UTF8')), '$CSRF', now() + interval '1 hour' FROM handles WHERE handle = '$handle'" \
    >/dev/null
}
