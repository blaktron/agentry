#!/usr/bin/env bash
# selftest.sh — next-dev-tag.sh and tag-guard.sh against a throwaway
# repository (agentry#597): the version each channel gets, when a dev push is
# released at all, and every tag the guard must refuse. CI's check job runs
# it; it needs only git and bash.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
next="$here/next-dev-tag.sh"
guard="$here/tag-guard.sh"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/r"; cd "$tmp/r"
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
git init -q -b dev
git config user.email selftest@example.invalid
git config user.name selftest
unset AGENTRY_ALLOW_V1

fails=0
expect() { # expect <want> <what> <cmd…>
  local want=$1 what=$2; shift 2
  local got; got=$("$@" 2>/dev/null) || got="<exit $?>"
  if [ "$got" = "$want" ]; then echo "ok   $what"; else echo "FAIL $what: want '$want', got '$got'"; fails=$((fails+1)); fi
}
refuses() { # refuses <what> <cmd…>
  local what=$1; shift
  if "$@" >/dev/null 2>&1; then echo "FAIL $what: accepted"; fails=$((fails+1)); else echo "ok   $what"; fi
}
config() { # config [release-as]
  { echo '{'; echo '  "packages": {'; echo '    ".": {'
    [ -n "${1:-}" ] && echo "      \"release-as\": \"$1\","
    echo '      "versioning": "always-bump-patch",'
    echo '      "initial-version": "0.1.0"'
    echo '    }'; echo '  }'; echo '}'; } > release-please-config.json
}
commit() { git add -A; git commit -q --allow-empty -m "$1"; }
publish() { git update-ref "refs/remotes/origin/$1" HEAD; }

config 0.6.0; commit "feat: the first feature"; publish dev
expect v0.6.0-dev.1 "release-as names the version before its tag exists" "$next"
git tag v0.6.0-dev.1
expect "" "a head that is already tagged is not released twice" "$next"
commit "chore: tidy"; publish dev
expect "" "a push with nothing release-please would release gets no tag" "$next"
expect v0.6.0-dev.2 "--force cuts one anyway, N counting up" "$next" --force
commit "fix(api): a bug"; publish dev
expect v0.6.0-dev.2 "a fix since the last dev tag is released" "$next"
git tag v0.6.0-dev.2
commit "docs: words"; commit "deps!: a breaking bump"; publish dev
expect v0.6.0-dev.3 "a type with a scope-less bang is releasable" "$next"

# main's release commit is not on dev: the newest vX.Y.Z tag counts wherever it is.
dev_head=$(git rev-parse HEAD)
git checkout -q -b main; commit "chore(main): release 0.6.0"; git tag v0.6.0; publish main
git checkout -q dev
expect v0.6.1-dev.1 "after v0.6.0 a lingering release-as gives way to a patch bump" "$next"
config 0.7.0; commit "feat!: the operator moves the minor"; publish dev
expect v0.7.0-dev.1 "a newer release-as moves the version" "$next"
config 0.5.0; commit "fix: stale release-as"; publish dev
expect v0.6.1-dev.1 "a release-as below the newest release is ignored" "$next"
config; commit "perf: faster"; publish dev
expect v0.6.1-dev.1 "no release-as: the newest release, patch bumped" "$next"
git tag v0.6.1-dev.1; git tag v0.6.1-dev.7 "$dev_head"
commit "security: a fix"; publish dev
expect v0.6.1-dev.8 "N is one more than the highest, not the count" "$next"

mkdir "$tmp/fresh"; cd "$tmp/fresh"
git init -q -b dev; git config user.email s@example.invalid; git config user.name s
config; commit "feat: a new repository"; publish dev
expect v0.1.0-dev.1 "no tag and no release-as: initial-version" "$next"
cd "$tmp/r"

# The guard: the two shapes, the channel's branch, and no 1.x without the operator.
expect $'version=0.6.0\nprerelease=false' "a main release on main" "$guard" v0.6.0
expect $'version=0.6.1-dev.8\nprerelease=true' "a dev prerelease on dev" "$guard" v0.6.1-dev.8 HEAD
refuses "a main tag on a commit only dev has" "$guard" v0.6.2 HEAD
refuses "a dev tag on a commit only main has" "$guard" v0.6.1-dev.9 "$(git rev-parse v0.6.0)"
for bad in v0.6 0.6.0 v0.6.0-rc.1 v0.6.0-dev.0 v0.6.0-dev v01.2.3 v0.6.0-dev.1-x; do
  refuses "the shape $bad" "$guard" "$bad" HEAD
done
refuses "a tag that does not exist, with no commit given" "$guard" v0.9.9
git checkout -q main; commit "chore(main): release 1.0.0"; git tag v1.0.0; publish main; git checkout -q dev
refuses "v1.0.0 without AGENTRY_ALLOW_V1" "$guard" v1.0.0
refuses "v1.0.0-dev.1 without AGENTRY_ALLOW_V1" "$guard" v1.0.0-dev.1 HEAD
refuses "v1.0.0 with AGENTRY_ALLOW_V1=yes (only true opens it)" env AGENTRY_ALLOW_V1=yes "$guard" v1.0.0
expect $'version=1.0.0\nprerelease=false' "v1.0.0 with AGENTRY_ALLOW_V1=true" env AGENTRY_ALLOW_V1=true "$guard" v1.0.0

[ "$fails" = 0 ] || { echo "release selftest: $fails failed"; exit 1; }
echo "release selftest: all passed"
