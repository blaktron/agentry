#!/usr/bin/env bash
# config-guard.sh — what release-please may do with the version it reads.
# release-please.yaml runs it before each of its two
# steps. Needs jq; reads release-please-config.json and
# .release-please-manifest.json.
#
#   config-guard.sh release        before tagging a merged release PR
#   config-guard.sh pull-request   before opening or updating the release PR
#
# Both refuse a manifest version of 1.x or later unless AGENTRY_ALLOW_V1 is
# exactly "true" (the repository variable only the maintainers' 1.0 step sets):
# after a release PR merges, the manifest holds the version it
# is about to tag. pull-request also refuses
#   - a release-as of 1.x or later without it, so no 1.x release PR is opened;
#   - a release-as that is not above the manifest's version: that version is
#     released, and release-please would propose it again, so it is removed
#     (or raised by a maintainer) first.
# A Release-As footer in a commit is not seen here; a 1.x PR it opens is
# refused at `release` once merged, and by release.yaml's guard.
set -euo pipefail
mode=${1:?usage: config-guard.sh release|pull-request}
refuse() { echo "config-guard: $*" >&2; exit 1; }
v1() { # v1 <what> <version>
  local major=${2%%.*}
  if [[ $major =~ ^[0-9]+$ ]] && [ "$major" -ge 1 ] && [ "${AGENTRY_ALLOW_V1:-}" != true ]; then
    refuse "$1 is $2: a v$major release is a maintainer's call (set the repository variable AGENTRY_ALLOW_V1=true)"
  fi
}
manifest=$(jq -r '.["."] // empty' .release-please-manifest.json)
[ -n "$manifest" ] || refuse "no version for \".\" in .release-please-manifest.json"
v1 "the manifest's version" "$manifest"

case "$mode" in
  release) ;;
  pull-request)
    release_as=$(jq -r '.packages["."]["release-as"] // empty' release-please-config.json)
    if [ -n "$release_as" ]; then
      v1 release-as "$release_as"
      if [ "$manifest" != 0.0.0 ] \
          && [ "$(printf '%s\n%s\n' "$manifest" "$release_as" | sort -V | tail -1)" = "$manifest" ]; then
        refuse "release-as $release_as is not above the released $manifest: remove it from release-please-config.json (or raise it) so the next release follows the commits"
      fi
    fi
    ;;
  *) refuse "unknown mode $mode" ;;
esac
echo "config-guard: $mode ok (manifest $manifest${release_as:+, release-as $release_as})"
