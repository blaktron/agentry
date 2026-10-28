#!/usr/bin/env bash
# The headless compose stack's image pins.
#
#   scripts/compose-pins.sh check [--online]   the form of every pin (default)
#   scripts/compose-pins.sh bump               rewrite each digest to its tag's current one
#   scripts/compose-pins.sh --self-test        the script's own cases
#
# Every `image:` in deploy/compose/docker-compose.yaml is `name:tag@sha256:<64 hex>`,
# the digest of the multi-architecture index, so a pull fetches the image that
# was tested and not whatever a tag points at that day. A YAML alias
# (`image: *name`) repeats an anchored image and is not read again.
#
# `check` fails when an image has no tag, no digest or a malformed one. With
# `--online` it also asks the registry (run daily by .github/workflows/pins.yaml):
#   - the pinned digest must still be served, else a fresh host cannot pull it;
#   - the tag, resolved now, should still be that digest. A tag that has moved
#     is a rebuild or a new release: `bump` rewrites the digest, and a new
#     version is a change of tag first, then `bump`.
#
# A read the registry does not answer (Docker Hub's anonymous rate limit
# answers 429, a network or server error) is asked twice more, 15 s apart
# (COMPOSE_PINS_RETRY_WAIT); if it still fails, that image is reported as not
# checked, a warning, never as a digest that is gone.
#
# The registry is read through `docker buildx imagetools inspect`; set
# COMPOSE_PINS_INSPECT to an executable that prints the index digest of the
# reference it is given to use another reader: exit 0 with the digest, exit 1
# when the registry has no such manifest, any other exit when it could not be
# read (the first line it writes to stderr is the reason). COMPOSE_PINS_FILE
# names another compose file.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
file=${COMPOSE_PINS_FILE:-deploy/compose/docker-compose.yaml}

pin_re='^[a-z0-9][a-z0-9./_-]*:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}$'

errors=0
err() { echo "::error::$*"; errors=$((errors + 1)); }
unread=0
warn() { echo "::warning::$*"; unread=$((unread + 1)); }

# images <file>: each distinct image reference, in file order. The
# `image:` key at any depth, its optional anchor (`&name`) dropped, a
# trailing comment dropped, an alias (`*name`) skipped, a comment line skipped.
images() {
  sed -nE 's/^[[:space:]]+image:[[:space:]]+(&[^[:space:]]+[[:space:]]+)?([^[:space:]#]+).*$/\2/p' "$1" |
    awk '!/^\*/ && !seen[$0]++'
}

# digest_of <reference>: the registry's answer for it, one line: the index
# digest; "missing" when the registry says it has no such manifest; or
# "unreadable: <reason>" when the registry could not be asked.
digest_of() {
  local out rc=0 why
  why=$(mktemp)
  if [ -n "${COMPOSE_PINS_INSPECT:-}" ]; then
    out=$("$COMPOSE_PINS_INSPECT" "$1" 2>"$why") || rc=$?
    case $rc in
      0) ;;
      1) out=missing ;;
      *) out="unreadable: $(head -1 "$why")" ;;
    esac
  elif [ -z "${COMPOSE_PINS_NO_BUILDX:-}" ] && docker buildx version >/dev/null 2>&1; then
    out=$(docker buildx imagetools inspect --format '{{.Manifest.Digest}}' "$1" 2>"$why") || rc=$?
    if [ "$rc" != 0 ]; then
      if grep -qiE 'not found|manifest unknown' "$why"; then out=missing; else out="unreadable: $(head -1 "$why")"; fi
    fi
  else
    out=$(registry_digest "$1")
  fi
  rm -f "$why"
  case $out in
    missing | unreadable:*) echo "$out" ;;
    *) tr -d '[:space:]' <<<"$out"; echo ;;
  esac
}

# read_digest <reference>: digest_of, asked again after a pause while the
# registry cannot be read.
read_digest() {
  local got i
  for i in 1 2 3; do
    got=$(digest_of "$1")
    [[ $got == unreadable:* ]] || break
    [ "$i" = 3 ] || sleep "${COMPOSE_PINS_RETRY_WAIT:-15}"
  done
  echo "$got"
}

# registry_digest <reference>: the digest header of a HEAD on the manifest,
# through the registry's anonymous token flow, for a host without buildx.
registry_digest() {
  local ref=$1 rest host repo tagref base hdr realm service tok
  rest=${ref}
  host=${rest%%/*}
  if [[ $rest == */* && ( $host == *.* || $host == *:* || $host == localhost ) ]]; then rest=${rest#*/}; else host=registry-1.docker.io; fi
  [ "$host" != docker.io ] || host=registry-1.docker.io
  if [ "$host" = registry-1.docker.io ] && [[ $rest != */* ]]; then rest=library/$rest; fi
  if [[ $rest == *@* ]]; then repo=${rest%@*} tagref=${rest#*@}; else repo=${rest%:*} tagref=${rest##*:}; fi
  base=https://$host/v2/$repo/manifests/$tagref
  local accept='Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json'
  hdr=$(curl -sSI -H "$accept" "$base" 2>/dev/null | tr -d '\r' || true)
  realm=$(sed -nE 's/^[Ww]ww-[Aa]uthenticate:.*realm="([^"]+)".*/\1/p' <<<"$hdr")
  if [ -n "$realm" ]; then
    # A 401 names the token endpoint: fetch an anonymous pull token, ask again.
    service=$(sed -nE 's/^[Ww]ww-[Aa]uthenticate:.*service="([^"]+)".*/\1/p' <<<"$hdr")
    tok=$(curl -fsS "$realm?service=$service&scope=repository:$repo:pull" 2>/dev/null | sed -nE 's/.*"(access_)?token" *: *"([^"]+)".*/\2/p' | head -1 || true)
    [ -n "$tok" ] || { echo "unreadable: no anonymous pull token from $realm"; return 0; }
    hdr=$(curl -sSI -H "$accept" -H "Authorization: Bearer $tok" "$base" 2>/dev/null | tr -d '\r' || true)
  fi
  local digest status
  digest=$(sed -nE 's/^[Dd]ocker-[Cc]ontent-[Dd]igest: *(sha256:[0-9a-f]{64}).*/\1/p' <<<"$hdr" | head -1)
  status=$(sed -nE '1s|^HTTP/[0-9.]+ ([0-9]{3}).*|\1|p' <<<"$hdr")
  if [ -n "$digest" ]; then
    echo "$digest"
  elif [ "$status" = 404 ]; then
    echo missing
  else
    echo "unreadable: HTTP ${status:-no answer} from $host"
  fi
}

check() {
  local online=$1 ref name_tag pinned now served
  mapfile -t refs < <(images "$file")
  [ "${#refs[@]}" -gt 0 ] || { err "$file: no image found"; return; }
  for ref in "${refs[@]}"; do
    if [[ ! $ref =~ $pin_re ]]; then
      err "$file: image '$ref' is not name:tag@sha256:<digest>"
      continue
    fi
    name_tag=${ref%@*} pinned=${ref#*@}
    [ "$online" = 1 ] || continue
    served=$(read_digest "${name_tag%:*}@$pinned")
    case $served in
      unreadable:*)
        warn "$name_tag: not checked, the registry could not be read (${served#unreadable: })"
        continue
        ;;
      "$pinned") ;;
      *)
        err "$name_tag: the pinned digest $pinned is no longer served by the registry (bump, or change the image)"
        continue
        ;;
    esac
    now=$(read_digest "$name_tag")
    case $now in
      unreadable:*) warn "$name_tag: the tag was not resolved, the registry could not be read (${now#unreadable: })" ;;
      "$pinned") ;;
      sha256:*) err "$name_tag: the tag is now $now, the pin is $pinned: run scripts/compose-pins.sh bump" ;;
      *) err "$name_tag: the tag cannot be resolved now" ;;
    esac
  done
}

bump() {
  local ref name_tag pinned now
  mapfile -t refs < <(images "$file")
  for ref in "${refs[@]}"; do
    [[ $ref =~ ^[a-z0-9][a-z0-9./_-]*:[A-Za-z0-9._-]+(@sha256:[0-9a-f]{64})?$ ]] || { err "$file: image '$ref' has no tag"; continue; }
    name_tag=${ref%@*} pinned=""
    [ "$ref" = "$name_tag" ] || pinned=${ref#*@}
    now=$(read_digest "$name_tag")
    if [[ ! $now =~ ^sha256:[0-9a-f]{64}$ ]]; then
      err "$name_tag: the tag cannot be resolved ('$now')"
      continue
    fi
    if [ "$now" != "$pinned" ]; then
      # '%' cannot occur in a reference, so it delimits the substitution; the
      # dots of the reference are literal.
      sed -i "s%${ref//./\\.}\([[:space:]#]\|\$\)%$name_tag@$now\1%" "$file"
      echo "$name_tag: ${pinned:-(unpinned)} -> $now"
    fi
  done
}

self_test() {
  local dir fails=0 sha_a sha_b out
  dir=$(mktemp -d)
  trap 'rm -rf "$dir"' RETURN
  sha_a=$(printf 'a%.0s' $(seq 64)) sha_b=$(printf 'b%.0s' $(seq 64))

  t() { # t <name> <expected exit> <command...>
    local name=$1 want=$2 got=0
    shift 2
    "$@" >"$dir/out" 2>&1 || got=$?
    if [ "$got" != "$want" ]; then
      echo "FAIL $name: exit $got, want $want"
      sed 's/^/    /' "$dir/out"
      fails=$((fails + 1))
    fi
  }
  INSPECT=""
  # shellcheck disable=SC2329 # called through t
  run() { COMPOSE_PINS_FILE="$dir/c.yaml" COMPOSE_PINS_INSPECT="$INSPECT" COMPOSE_PINS_RETRY_WAIT=0 "$@"; }
  script=$(readlink -f "${BASH_SOURCE[0]}")

  cat >"$dir/stub" <<EOF
#!/usr/bin/env bash
case "\$1" in
  *@sha256:$sha_a) echo sha256:$sha_a ;;
  *@sha256:$sha_b) exit 1 ;;
  *) echo sha256:$sha_b ;;
esac
EOF
  chmod +x "$dir/stub"

  cat >"$dir/c.yaml" <<EOF
services:
  # image: not-an-image:latest
  a:
    image: &base docker.io/library/x:1.2@sha256:$sha_a # a comment
  b:
    image: *base
  c:
    image: ghcr.io/o/y:v3@sha256:$sha_a
EOF
  t "pinned file passes" 0 run "$script" check

  sed -i 's|image: ghcr.io/o/y:v3@sha256:[a-f0-9]*|image: ghcr.io/o/y:v3|' "$dir/c.yaml"
  t "an image without a digest fails" 1 run "$script" check

  sed -i "s|image: ghcr.io/o/y:v3|image: ghcr.io/o/y@sha256:$sha_a|" "$dir/c.yaml"
  t "an image without a tag fails" 1 run "$script" check

  sed -i "s|image: ghcr.io/o/y@sha256:$sha_a|image: ghcr.io/o/y:v3@sha256:abc|" "$dir/c.yaml"
  t "a short digest fails" 1 run "$script" check

  sed -i "s|image: ghcr.io/o/y:v3@sha256:abc|image: ghcr.io/o/y:v3@sha256:$sha_a|" "$dir/c.yaml"
  cat >"$dir/stub-current" <<EOF
#!/usr/bin/env bash
case "\$1" in *@sha256:*) echo "\${1#*@}" ;; *) echo sha256:$sha_a ;; esac
EOF
  chmod +x "$dir/stub-current"
  INSPECT="$dir/stub-current"
  t "online: a current pin passes" 0 run "$script" check --online
  INSPECT="$dir/stub"
  t "online: a moved tag fails" 1 run "$script" check --online

  # A registry that cannot be read (here, a 429) leaves the pin unchecked:
  # a warning, not a digest reported gone.
  cat >"$dir/stub-429" <<STUB
#!/usr/bin/env bash
echo "unexpected status from HEAD request: 429 Too Many Requests" >&2
exit 3
STUB
  chmod +x "$dir/stub-429"
  INSPECT="$dir/stub-429"
  t "online: an unreadable registry passes with a warning" 0 run "$script" check --online
  if ! grep "not checked, the registry could not be read (unexpected status from HEAD request: 429" "$dir/out" >/dev/null ||
    grep "no longer served" "$dir/out" >/dev/null; then
    echo "FAIL online: an unreadable registry is not reported as not checked"
    sed 's/^/    /' "$dir/out"
    fails=$((fails + 1))
  fi
  t "bump: an unreadable registry fails" 1 run "$script" bump
  INSPECT="$dir/stub"

  sed -i "s|@sha256:$sha_a|@sha256:$sha_b|" "$dir/c.yaml"
  t "online: a digest no longer served fails" 1 run "$script" check --online
  grep -q "no longer served" "$dir/out" || { echo "FAIL online: a missing digest is not reported as no longer served"; fails=$((fails + 1)); }

  # bump moves each digest to its tag's current one, keeps the anchor, the
  # alias and the comment, and leaves a current pin untouched.
  t "bump rewrites" 0 run "$script" bump
  out=$(cat "$dir/c.yaml")
  for want in "image: &base docker.io/library/x:1.2@sha256:$sha_b # a comment" "image: *base" "image: ghcr.io/o/y:v3@sha256:$sha_b"; do
    case "$out" in *"$want"*) ;; *) echo "FAIL bump: missing '$want'"; fails=$((fails + 1)) ;; esac
  done
  cat >"$dir/stub-b" <<EOF
#!/usr/bin/env bash
case "\$1" in *@sha256:*) echo "\${1#*@}" ;; *) echo sha256:$sha_b ;; esac
EOF
  chmod +x "$dir/stub-b"
  INSPECT="$dir/stub-b"
  t "bumped file passes online" 0 run "$script" check --online

  [ "$fails" = 0 ] || { echo "compose-pins self-test: $fails failure(s)"; return 1; }
  echo "compose-pins self-test: ok"
}

case "${1:-check}" in
  --self-test) self_test; exit ;;
  check)
    online=0
    [ "${2:-}" != "--online" ] || online=1
    check "$online"
    ;;
  bump) bump ;;
  *) echo "usage: $0 [check [--online] | bump | --self-test]" >&2; exit 2 ;;
esac

if [ "$errors" -gt 0 ]; then
  echo "compose-pins: $errors error(s)"
  exit 1
fi
if [ "$unread" -gt 0 ]; then
  echo "compose-pins: every image in $file is pinned by tag and digest; $unread online check(s) not made, the registry could not be read"
else
  echo "compose-pins: every image in $file is pinned by tag and digest"
fi
