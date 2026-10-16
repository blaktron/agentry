#!/usr/bin/env bash
# prune-prereleases.sh — keeps the newest dev prereleases and deletes the
# older ones, so their assets do not pile up one release per dev push.
# release.yaml's sbom-and-sign job runs it after publishing a prerelease.
#
#   prune-prereleases.sh <keep>
#
# Environment: GH_TOKEN (contents: write), GITHUB_REPOSITORY.
#
# A candidate is a published (not draft) release marked prerelease whose tag
# is vX.Y.Z-dev.N. The newest <keep> candidates by version are kept and the
# rest deleted. A stable release, a draft and a release under any other tag
# are never touched. Deleting a release leaves its tag, so a module version
# that names the tag still resolves; the image and the chart of every tag
# live in the container registry, not in the release.
# Needs curl and jq.
set -euo pipefail
keep=${1:?usage: prune-prereleases.sh <keep>}
[[ "$keep" =~ ^[1-9][0-9]*$ ]] || { echo "keep must be a positive number, not $keep" >&2; exit 2; }
: "${GH_TOKEN:?}" "${GITHUB_REPOSITORY:?}"
api() {
  curl -fsS --retry 3 -H "Authorization: Bearer $GH_TOKEN" -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" "$@"
}
repo="https://api.github.com/repos/$GITHUB_REPOSITORY"

# Each page to a file: a page of release bodies outgrows an argument list.
pages=$(mktemp -d); trap 'rm -rf "$pages"' EXIT
for page in $(seq 1 50); do
  api "$repo/releases?per_page=100&page=$page" > "$pages/$(printf %02d "$page").json"
  [ "$(jq length "$pages/$(printf %02d "$page").json")" -lt 100 ] && break
done
all=$(jq -cs 'add | map({id, tag_name, prerelease, draft})' "$pages"/*.json)

doomed=$(jq -r --argjson keep "$keep" '
  map(select(.prerelease and (.draft | not)
             and (.tag_name | test("^v[0-9]+\\.[0-9]+\\.[0-9]+-dev\\.[0-9]+$"))))
  | sort_by(.tag_name | ltrimstr("v") | split("-dev.") | (.[0] | split(".") | map(tonumber)) + [(.[1] | tonumber)])
  | .[:-$keep][]
  | "\(.id) \(.tag_name)"' <<<"$all")

echo "$(jq length <<<"$all") releases; $(grep -c . <<<"$doomed" || true) dev prereleases past the newest $keep"
while read -r id tag; do
  [ -n "$id" ] || continue
  api -X DELETE "$repo/releases/$id" >/dev/null
  echo "deleted $tag (release $id); the tag stays"
done <<<"$doomed"
