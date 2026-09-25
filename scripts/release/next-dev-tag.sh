#!/usr/bin/env bash
# next-dev-tag.sh — the tag a dev prerelease of HEAD gets, or nothing when
# HEAD needs none (DEV-148, agentry#597). dev-release.yaml runs it on every
# push to dev.
#
#   next-dev-tag.sh [--force]
#
# Prints vX.Y.Z-dev.N and exits 0. Prints nothing and exits 0 when HEAD
# already carries a v* tag, or, without --force, when no commit since the
# last v* tag reachable from HEAD is one release-please would release on
# main: a feat, fix, perf, security, deps or revert subject (the visible
# sections of release-please-config.json).
#
# X.Y.Z is the version main's next release will have:
#   - the config's release-as, while no vX.Y.Z tag exists for it and it is
#     above the newest release (the operator moving the version);
#   - else the newest vX.Y.Z tag with its patch bumped, since the config's
#     versioning is always-bump-patch;
#   - else, before any release, the config's initial-version.
# The newest release is looked up among all tags, not only HEAD's ancestors:
# main's release commit is on main alone.
#
# N is one more than the highest existing vX.Y.Z-dev.N, from 1, so a dev tag
# that was deleted or never released is not reused.
set -euo pipefail
force=0
[ "${1:-}" = --force ] && force=1
config=${RELEASE_PLEASE_CONFIG:-release-please-config.json}
die() { echo "next-dev-tag: $*" >&2; exit 1; }
[ -f "$config" ] || die "no $config"

if git tag --points-at HEAD | grep -E '^v[0-9]' >/dev/null; then
  exit 0
fi

if [ "$force" = 0 ]; then
  prev=$(git describe --tags --abbrev=0 --match 'v[0-9]*' HEAD 2>/dev/null || true)
  if ! git log --format=%s "${prev:+$prev..}HEAD" \
      | grep -E '^(feat|fix|perf|security|deps|revert)(\([^)]*\))?!?: ' >/dev/null; then
    exit 0
  fi
fi

setting() { sed -nE "s/^[[:space:]]*\"$1\"[[:space:]]*:[[:space:]]*\"([^\"]+)\".*/\1/p" "$config" | head -1; }
semver='^[0-9]+\.[0-9]+\.[0-9]+$'
latest=$(git tag -l 'v*' | sed 's/^v//' | { grep -E "$semver" || true; } | sort -V | tail -1)
release_as=$(setting release-as)

if [ -n "$release_as" ]; then
  [[ $release_as =~ $semver ]] || die "release-as '$release_as' is not X.Y.Z"
fi
if [ -n "$release_as" ] && [ "$release_as" != "$latest" ] \
    && ! git rev-parse -q --verify "refs/tags/v$release_as" >/dev/null \
    && [ "$(printf '%s\n%s\n' "$latest" "$release_as" | sort -V | tail -1)" = "$release_as" ]; then
  next=$release_as
elif [ -n "$latest" ]; then
  IFS=. read -r major minor patch <<<"$latest"
  next="$major.$minor.$((patch + 1))"
else
  next=$(setting initial-version)
  [[ $next =~ $semver ]] || die "no release yet and no initial-version in $config"
fi

n=$(git tag -l "v$next-dev.*" | sed -nE "s/^v${next//./\\.}-dev\.([0-9]+)$/\1/p" | sort -n | tail -1)
echo "v$next-dev.$(( ${n:-0} + 1 ))"
