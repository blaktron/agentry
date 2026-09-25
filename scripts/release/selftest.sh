#!/usr/bin/env bash
# selftest.sh — the release scripts against a throwaway repository and a fake
# GitHub API (agentry#597): the version each channel gets, when a dev push is
# released at all, every tag and configuration the guards refuse, and how
# publish.sh finds, fills and publishes a release. CI's check job runs it; it
# needs git, jq and bash, and nothing on the network.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
next="$here/next-dev-tag.sh"
guard="$here/tag-guard.sh"
cguard="$here/config-guard.sh"
publish="$here/publish.sh"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
unset AGENTRY_ALLOW_V1 RUN_REF

fails=0
expect() { # expect <want> <what> <cmd…>
  local want=$1 what=$2; shift 2
  local got; got=$("$@" 2>/dev/null) || got="<exit $?>"
  if [ "$got" = "$want" ]; then echo "ok   $what"; else echo "FAIL $what: want '$want', got '$got'"; fails=$((fails+1)); fi
}
accepts() { # accepts <what> <cmd…>
  local what=$1; shift
  if "$@" >/dev/null 2>&1; then echo "ok   $what"; else echo "FAIL $what: refused"; fails=$((fails+1)); fi
}
refuses() { # refuses <what> <cmd…>
  local what=$1; shift
  if "$@" >/dev/null 2>&1; then echo "FAIL $what: accepted"; fails=$((fails+1)); else echo "ok   $what"; fi
}
repo() { mkdir "$tmp/$1"; cd "$tmp/$1"; git init -q -b dev; git config user.email s@example.invalid; git config user.name s; }
config() { # config [release-as]
  jq -n --arg ra "${1:-}" '{
    packages: {".": ({versioning: "always-bump-patch", "initial-version": "0.1.0"}
                     + (if $ra == "" then {} else {"release-as": $ra} end))},
    "changelog-sections": [
      {type: "feat"}, {type: "fix"}, {type: "perf"}, {type: "security"}, {type: "deps"}, {type: "revert"},
      {type: "docs", hidden: true}, {type: "ci", hidden: true}, {type: "chore", hidden: true}]}' > release-please-config.json
}
manifest() { jq -n --arg v "$1" '{".": $v}' > .release-please-manifest.json; }
commit() { git add -A; git commit -q --allow-empty -m "$1"; }
publish_ref() { git update-ref "refs/remotes/origin/$1" HEAD; }
count() { grep -c -- "$1" "$2" || true; }

# --- next-dev-tag.sh ----------------------------------------------------------
repo r
config 0.6.0; commit "feat: the first feature"; publish_ref dev
expect v0.6.0-dev.1 "release-as names the version before its tag exists" "$next"
git tag v0.6.0-dev.1
expect "" "a head that is already tagged is not released twice" "$next"
expect "" "not even with --force" "$next" --force
commit "chore: tidy"; publish_ref dev
expect "" "a push with nothing release-please would release gets no tag" "$next"
expect v0.6.0-dev.2 "--force cuts one anyway, N counting up" "$next" --force
commit "fix(api): a bug"; publish_ref dev
expect v0.6.0-dev.2 "a fix since the last dev tag is released" "$next"
git tag v0.6.0-dev.2
commit "docs: words"; commit "deps!: a breaking bump"; publish_ref dev
expect v0.6.0-dev.3 "a type with a scope-less bang is releasable" "$next"
commit "ci: hidden"; commit "featured: not a type"; publish_ref dev
expect v0.6.0-dev.3 "the releasable commit still counts under later hidden ones" "$next"

# main's release commit is not on dev: the newest vX.Y.Z tag counts wherever it is.
dev_head=$(git rev-parse HEAD)
git checkout -q -b main; commit "chore(main): release 0.6.0"; git tag v0.6.0; publish_ref main
git checkout -q dev
expect v0.6.1-dev.1 "after v0.6.0 a lingering release-as gives way to a patch bump" "$next"
config 0.7.0; commit "feat!: the operator moves the minor"; publish_ref dev
expect v0.7.0-dev.1 "a newer release-as moves the version" "$next"
config 0.5.0; commit "fix: stale release-as"; publish_ref dev
expect v0.6.1-dev.1 "a release-as below the newest release is ignored" "$next"
config; commit "perf: faster"; publish_ref dev
expect v0.6.1-dev.1 "no release-as: the newest release, patch bumped" "$next"
git tag v0.6.1-dev.1; git tag v0.6.1-dev.7 "$dev_head"
commit "security: a fix"; publish_ref dev
expect v0.6.1-dev.8 "N is one more than the highest, not the count" "$next"
commit "chore: only hidden since the last dev tag"; publish_ref dev; git tag -d v0.6.1-dev.1 >/dev/null; git tag v0.6.1-dev.8 HEAD~1
expect "" "only hidden commits since the nearest dev tag: nothing" "$next"

repo fresh
config; commit "feat: a new repository"; publish_ref dev
expect v0.1.0-dev.1 "no tag and no release-as: initial-version" "$next"
cd "$tmp/r"

# --- tag-guard.sh -------------------------------------------------------------
expect $'version=0.6.0\nprerelease=false\nbranch=main\nlatest=true' "a main release on main, the newest" "$guard" v0.6.0
expect $'version=0.6.1-dev.9\nprerelease=true\nbranch=dev\nlatest=false' "a dev prerelease on dev, never latest" "$guard" v0.6.1-dev.9 HEAD
accepts "a dev release run on dev" env RUN_REF=refs/heads/dev "$guard" v0.6.1-dev.9 HEAD
refuses "a dev release run on main (it would sign as main)" env RUN_REF=refs/heads/main "$guard" v0.6.1-dev.9 HEAD
refuses "a main release run on dev" env RUN_REF=refs/heads/dev "$guard" v0.6.0
refuses "a main tag on a commit only dev has" "$guard" v0.6.2 HEAD
refuses "a dev tag on a commit only main has" "$guard" v0.6.1-dev.9 "$(git rev-parse v0.6.0)"
for bad in v0.6 0.6.0 v0.6.0-rc.1 v0.6.0-dev.0 v0.6.0-dev v01.2.3 v0.6.0-dev.1-x; do
  refuses "the shape $bad" "$guard" "$bad" HEAD
done
refuses "a tag that does not exist, with no commit given" "$guard" v0.9.9
git checkout -q main
commit "chore(main): release 0.9.0"; git tag v0.9.0; commit "chore(main): release 0.10.0"; git tag v0.10.0; publish_ref main
expect $'version=0.9.0\nprerelease=false\nbranch=main\nlatest=false' "an older main release rebuilt is not latest (0.9 < 0.10)" "$guard" v0.9.0
expect latest=true "the newest main release is" sh -c "'$guard' v0.10.0 | tail -1"
commit "chore(main): release 1.0.0"; git tag v1.0.0; publish_ref main; git checkout -q dev
refuses "v1.0.0 without AGENTRY_ALLOW_V1" "$guard" v1.0.0
refuses "v1.0.0-dev.1 without AGENTRY_ALLOW_V1" "$guard" v1.0.0-dev.1 HEAD
refuses "v1.0.0 with AGENTRY_ALLOW_V1=yes (only true opens it)" env AGENTRY_ALLOW_V1=yes "$guard" v1.0.0
expect $'version=1.0.0\nprerelease=false\nbranch=main\nlatest=true' "v1.0.0 with AGENTRY_ALLOW_V1=true" env AGENTRY_ALLOW_V1=true "$guard" v1.0.0

# --- config-guard.sh ----------------------------------------------------------
repo c
config 0.6.0; manifest 0.0.0
accepts "the first release-as over an unreleased manifest" "$cguard" pull-request
manifest 0.6.0
accepts "release: tagging the merged 0.6.0" "$cguard" release
refuses "pull-request: release-as 0.6.0 once 0.6.0 is released" "$cguard" pull-request
config; accepts "pull-request: no release-as after the release" "$cguard" pull-request
config 0.7.0; accepts "pull-request: the operator's newer release-as" "$cguard" pull-request
config 1.0.0; refuses "pull-request: release-as 1.0.0 without AGENTRY_ALLOW_V1" "$cguard" pull-request
accepts "pull-request: release-as 1.0.0 with AGENTRY_ALLOW_V1=true" env AGENTRY_ALLOW_V1=true "$cguard" pull-request
config; manifest 1.0.0
refuses "release: a merged 1.0.0 without AGENTRY_ALLOW_V1" "$cguard" release
accepts "release: a merged 1.0.0 with AGENTRY_ALLOW_V1=true" env AGENTRY_ALLOW_V1=true "$cguard" release
refuses "an unknown mode" "$cguard" tag

# --- publish.sh, against a fake API -------------------------------------------
# The fake curl records each call ("METHOD URL") and each JSON request body,
# and answers from $FAKE: list.json for the listing, a new release for POST
# /releases, and the PATCH body echoed back.
fake="$tmp/fake"; mkdir -p "$fake/bin" "$tmp/assets"
cat > "$fake/bin/curl" <<'EOF'
#!/usr/bin/env bash
method=GET url= data=
while [ $# -gt 0 ]; do
  case "$1" in
    -X) method=$2; shift ;;
    -d|--data-binary) data=$2; shift ;;
    -H) shift ;;
    http*) url=$1 ;;
  esac
  shift
done
echo "$method $url" >> "$FAKE/calls"
[ "$data" = @- ] && cat > "$FAKE/body.$method"
case "$method $url" in
  "GET "*"/releases?"*) cat "$FAKE/list.json" ;;
  "POST https://api.github.com/"*"/releases") echo '{"id": 7, "tag_name": "v0.6.1-dev.1", "body": "generated notes", "assets": []}' ;;
  "PATCH "*) jq '. + {tag_name: "t", html_url: "u"}' "$FAKE/body.PATCH" ;;
  *) echo '{}' ;;
esac
EOF
chmod +x "$fake/bin/curl"
echo sums > "$tmp/assets/SHA256SUMS.txt"; echo bin > "$tmp/assets/agentryd-linux-amd64"
printf '<!-- agentry-release-verification -->\nVerify it.\n' > "$tmp/notes.md"
run_publish() { # run_publish <tag> <prerelease> <latest>
  rm -f "$fake/calls" "$fake"/body.*
  env PATH="$fake/bin:$PATH" FAKE="$fake" GH_TOKEN=t GITHUB_REPOSITORY=o/r PRERELEASE="$2" LATEST="$3" \
    "$publish" "$1" "$tmp/assets" "$tmp/notes.md"
}

echo '[{"id": 3, "tag_name": "v0.6.0", "draft": false, "assets": []}]' > "$fake/list.json"
accepts "publish: a dev prerelease with no release yet" run_publish v0.6.1-dev.1 true false
expect true "  it is created as a draft" jq -r .draft "$fake/body.POST"
expect true "  with GitHub's generated notes" jq -r .generate_release_notes "$fake/body.POST"
expect 2 "  both assets are uploaded to it" count '^POST https://uploads.github.com/repos/o/r/releases/7/assets' "$fake/calls"
expect $'false\ntrue\nfalse' "  then published as a prerelease, not latest" jq -r '.draft, .prerelease, .make_latest' "$fake/body.PATCH"
expect $'generated notes\n\n<!-- agentry-release-verification -->\nVerify it.' "  the verification block under the notes" jq -r .body "$fake/body.PATCH"

echo '[{"id": 9, "tag_name": "v0.6.0", "draft": true, "body": "## 0.6.0 changelog", "assets": [{"id": 51, "name": "SHA256SUMS.txt"}]}]' > "$fake/list.json"
accepts "publish: release-please's draft main release" run_publish v0.6.0 false true
expect 0 "  no second release is created" count '^POST https://api.github.com/repos/o/r/releases$' "$fake/calls"
expect 1 "  an asset of the same name is replaced" count '^DELETE https://api.github.com/repos/o/r/releases/assets/51$' "$fake/calls"
expect $'false\nfalse\ntrue' "  published, not a prerelease, latest" jq -r '.draft, .prerelease, .make_latest' "$fake/body.PATCH"
expect $'## 0.6.0 changelog\n\n<!-- agentry-release-verification -->\nVerify it.' "  the changelog kept, the block appended" jq -r .body "$fake/body.PATCH"

echo '[{"id": 9, "tag_name": "v0.6.0", "draft": false, "body": "## 0.6.0 changelog\n\n<!-- agentry-release-verification -->\nVerify it.", "assets": []}]' > "$fake/list.json"
accepts "publish: a rebuild of a published release" run_publish v0.6.0 false false
expect $'## 0.6.0 changelog\n\n<!-- agentry-release-verification -->\nVerify it.' "  the block is not appended twice" jq -r .body "$fake/body.PATCH"

[ "$fails" = 0 ] || { echo "release selftest: $fails failed"; exit 1; }
echo "release selftest: all passed"
