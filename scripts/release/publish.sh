#!/usr/bin/env bash
# publish.sh — attaches a release's signed assets and only then publishes it
# (DEV-148, agentry#597). release.yaml's sbom-and-sign job runs it after
# signing, so neither channel shows a published release without its assets.
#
#   publish.sh <tag> <assets-dir> <notes-file>
#
# Environment: GH_TOKEN (contents: write), GITHUB_REPOSITORY, PRERELEASE and
# LATEST (true|false, from tag-guard.sh).
#
#   1. The release for <tag>, drafts included: for a main release, the draft
#      release-please created with the changelog as its body; for a dev
#      prerelease none exists yet, so a draft is created here with GitHub's
#      generated notes. (The API's release-by-tag lookup never returns a
#      draft, which is why the listing is read.)
#   2. Every file in <assets-dir> is uploaded, replacing an asset of the same
#      name, so a rebuild of a release left in draft (a run that failed
#      part-way) finishes it cleanly. A release already published is left as
#      it is: replacing a live release's assets one by one could leave it
#      with a new SHA256SUMS.txt beside an old signature.
#   3. The notes file is appended to the body unless its first line (a
#      marker) is already there.
#   4. The release is published: draft false, its prerelease flag, and
#      make_latest, which only the newest main release gets.
# Needs curl and jq.
set -euo pipefail
tag=${1:?usage: publish.sh <tag> <assets-dir> <notes-file>}
dir=${2:?usage: publish.sh <tag> <assets-dir> <notes-file>}
notes=${3:?usage: publish.sh <tag> <assets-dir> <notes-file>}
: "${GH_TOKEN:?}" "${GITHUB_REPOSITORY:?}" "${PRERELEASE:?}" "${LATEST:?}"
api() {
  curl -fsS --retry 3 -H "Authorization: Bearer $GH_TOKEN" -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" "$@"
}
repo="https://api.github.com/repos/$GITHUB_REPOSITORY"

release=""
for page in 1 2 3 4 5; do
  list=$(api "$repo/releases?per_page=100&page=$page")
  release=$(jq -c --arg t "$tag" 'map(select(.tag_name == $t)) | first // empty' <<<"$list")
  [ -n "$release" ] && break
  [ "$(jq length <<<"$list")" -lt 100 ] && break
done
if [ -z "$release" ]; then
  echo "creating the draft release $tag"
  release=$(jq -n --arg t "$tag" --argjson pre "$PRERELEASE" \
      '{tag_name: $t, name: $t, draft: true, prerelease: $pre, generate_release_notes: true}' \
    | api -X POST "$repo/releases" -d @-)
fi
id=$(jq -r .id <<<"$release")
[[ $id =~ ^[0-9]+$ ]] || { echo "publish: no release id for $tag" >&2; exit 1; }
if [ "$(jq -r .draft <<<"$release")" = false ]; then
  echo "publish: $tag is already published with its assets; left as it is"
  exit 0
fi

for f in "$dir"/*; do
  name=$(basename "$f")
  old=$(jq -r --arg n "$name" '.assets[] | select(.name == $n) | .id' <<<"$release")
  [ -n "$old" ] && api -X DELETE "$repo/releases/assets/$old" >/dev/null
  api -X POST -H "Content-Type: application/octet-stream" --data-binary "@$f" \
    "https://uploads.github.com/repos/$GITHUB_REPOSITORY/releases/$id/assets?name=$(jq -rn --arg n "$name" '$n|@uri')" >/dev/null
  echo "attached $name"
done

body=$(jq -r '.body // ""' <<<"$release")
marker=$(head -1 "$notes")
if ! grep -F -- "$marker" <<<"$body" >/dev/null; then
  [ -n "$body" ] && body+=$'\n\n'
  body+=$(cat "$notes")
fi
jq -n --arg b "$body" --argjson pre "$PRERELEASE" --arg latest "$LATEST" \
    '{body: $b, draft: false, prerelease: $pre, make_latest: $latest}' \
  | api -X PATCH "$repo/releases/$id" -d @- \
  | jq -r '"published \(.tag_name): \(.html_url) (prerelease \(.prerelease), draft \(.draft))"'
