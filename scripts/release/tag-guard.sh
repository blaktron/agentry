#!/usr/bin/env bash
# tag-guard.sh — refuses a release tag of the wrong shape, one on the wrong
# branch, and any 1.x or later without the operator (DEV-148, agentry#597).
# release.yaml's first job runs it, and dev-release.yaml runs it before it
# creates a tag.
#
#   tag-guard.sh <tag> [<commit>]
#
# The two shapes:
#   vX.Y.Z        a main release: its commit must be on origin/main
#   vX.Y.Z-dev.N  a dev prerelease (N from 1): its commit must be on origin/dev
# The commit defaults to the tag's own. With RUN_REF set (a workflow passes
# github.ref), the release must also run on that same branch: the signing
# certificate names the branch the workflow ran on, so a dev prerelease
# signed from main, or a main release signed from dev, would carry the other
# channel's identity. A major version of 1 or more is refused unless
# AGENTRY_ALLOW_V1 is exactly "true": the repository variable only the
# operator's 1.0 step sets (agentry#522).
#
# On success it prints the lines a workflow appends to $GITHUB_OUTPUT,
#   version=X.Y.Z[-dev.N]
#   prerelease=true|false
#   branch=main|dev
#   latest=true|false    (a main release that is the newest vX.Y.Z tag)
# and exits 0. Otherwise it names the refusal on stderr and exits 1.
set -euo pipefail
tag=${1:?usage: tag-guard.sh <tag> [<commit>]}
commit=${2:-}
refuse() { echo "tag-guard: refused $tag: $*" >&2; exit 1; }

n='(0|[1-9][0-9]*)'
stable="^v$n\.$n\.$n\$"
[[ $tag =~ ^v$n\.$n\.$n(-dev\.([1-9][0-9]*))?$ ]] \
  || refuse "not vX.Y.Z or vX.Y.Z-dev.N"
major=${BASH_REMATCH[1]}
if [ -n "${BASH_REMATCH[4]}" ]; then
  branch=dev prerelease=true
else
  branch=main prerelease=false
fi

if [ "$major" -ge 1 ] && [ "${AGENTRY_ALLOW_V1:-}" != true ]; then
  refuse "a v$major release is the operator's (set the repository variable AGENTRY_ALLOW_V1=true, agentry#522)"
fi

if [ -n "${RUN_REF:-}" ] && [ "$RUN_REF" != "refs/heads/$branch" ]; then
  refuse "a $branch release runs on $branch, not on $RUN_REF"
fi

if [ -z "$commit" ]; then
  commit=$(git rev-parse -q --verify "refs/tags/$tag^{commit}") || refuse "no such tag"
fi
git rev-parse -q --verify "refs/remotes/origin/$branch" >/dev/null \
  || refuse "origin/$branch is not fetched (check out with fetch-depth: 0)"
git merge-base --is-ancestor "$commit" "origin/$branch" \
  || refuse "its commit $commit is not on $branch"

latest=false
if [ "$prerelease" = false ]; then
  newest=$( { git tag -l 'v*'; echo "$tag"; } | { grep -E "$stable" || true; } | sort -V | tail -1)
  [ "$newest" = "$tag" ] && latest=true
fi

echo "version=${tag#v}"
echo "prerelease=$prerelease"
echo "branch=$branch"
echo "latest=$latest"
