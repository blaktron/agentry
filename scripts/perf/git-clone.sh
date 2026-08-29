#!/usr/bin/env bash
# §17.6 baseline: 50 concurrent git clones.
#
# k6 speaks HTTP, and smart-HTTP v2 clone is a multi-request negotiation with
# packfile streaming — driving it from k6 would measure a reimplementation of
# git rather than git. So this harness runs real `git clone` processes and
# collects wall-clock timings itself.
#
#   BASE_URL=https://staging.agentry.invalid AGENTRY_PAT=agy_… ./scripts/perf/git-clone.sh
#
# Not run by CI (see scripts/perf/README.md) — staging only.
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
CONCURRENCY="${CONCURRENCY:-50}"     # §17.6 target
ITERATIONS="${ITERATIONS:-4}"        # waves of CONCURRENCY clones
P95_BUDGET_MS="${P95_BUDGET_MS:-2000}" # §18.2 M2: clone p95 < 2s on seed repos
REPOS="${REPOS:-}"                   # newline- or space-separated ns/name list

if [ -z "${AGENTRY_PAT:-}" ]; then
  echo "AGENTRY_PAT is required (scope: repo:read)" >&2
  exit 2
fi
command -v git >/dev/null || { echo "git not on PATH" >&2; exit 2; }
command -v jq  >/dev/null || { echo "jq not on PATH" >&2; exit 2; }

# Discover repos to clone unless the caller named some.
if [ -z "$REPOS" ]; then
  REPOS="$(curl -fsS "${BASE_URL}/api/v1/agents?limit=${CONCURRENCY}" \
    | jq -r '(.items // .)[] | "\(.namespace)/\(.name)"')"
fi
if [ -z "$REPOS" ]; then
  echo "no repositories to clone — run scripts/seed and create repos first" >&2
  exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
TIMINGS="$WORK/timings"
: > "$TIMINGS"

# Credentials go in a git credential file, never in the URL: a URL with a
# token in it lands in the reflog, in `ps`, and in the server's access log.
export GIT_TERMINAL_PROMPT=0
CRED="$WORK/credentials"
HOST_PART="${BASE_URL#*://}"
SCHEME="${BASE_URL%%://*}"
printf '%s://x-access-token:%s@%s\n' "$SCHEME" "$AGENTRY_PAT" "$HOST_PART" > "$CRED"
chmod 600 "$CRED"
export GIT_CONFIG_COUNT=2
export GIT_CONFIG_KEY_0=credential.helper
export GIT_CONFIG_VALUE_0="store --file=$CRED"
export GIT_CONFIG_KEY_1=credential.useHttpPath
export GIT_CONFIG_VALUE_1=true

clone_one() {
  local ref="$1" n="$2"
  local start end
  start="$(date +%s%3N 2>/dev/null || python3 -c 'import time;print(int(time.time()*1000))')"
  if git clone --quiet --depth 1 "${BASE_URL}/${ref}.git" "$WORK/c-$n" >/dev/null 2>&1; then
    end="$(date +%s%3N 2>/dev/null || python3 -c 'import time;print(int(time.time()*1000))')"
    echo "$((end - start)) ok $ref" >> "$TIMINGS"
  else
    echo "0 fail $ref" >> "$TIMINGS"
  fi
  rm -rf "$WORK/c-$n"
}

echo "== git clone baseline: ${CONCURRENCY} concurrent x ${ITERATIONS} waves against ${BASE_URL} =="
n=0
for _ in $(seq 1 "$ITERATIONS"); do
  pids=()
  for _ in $(seq 1 "$CONCURRENCY"); do
    ref="$(echo "$REPOS" | sed -n "$(( (n % $(echo "$REPOS" | wc -l | tr -d ' ')) + 1 ))p")"
    clone_one "$ref" "$n" &
    pids+=($!)
    n=$((n + 1))
  done
  for pid in "${pids[@]}"; do wait "$pid" || true; done
done

total="$(wc -l < "$TIMINGS" | tr -d ' ')"
failures="$(grep -c ' fail ' "$TIMINGS" || true)"
p95="$(awk '$2=="ok" {print $1}' "$TIMINGS" | sort -n \
       | awk '{a[NR]=$1} END {if (NR==0) {print 0} else {print a[int(NR*0.95+0.999)]}}')"
median="$(awk '$2=="ok" {print $1}' "$TIMINGS" | sort -n \
       | awk '{a[NR]=$1} END {if (NR==0) {print 0} else {print a[int(NR/2)+1]}}')"

printf 'clones: %s   failures: %s   median: %s ms   p95: %s ms   budget: %s ms\n' \
  "$total" "$failures" "$median" "$p95" "$P95_BUDGET_MS"

status=0
if [ "$failures" -gt 0 ]; then
  echo "FAIL: ${failures} clone(s) failed at concurrency ${CONCURRENCY}" >&2
  status=1
fi
if [ "$p95" -gt "$P95_BUDGET_MS" ]; then
  echo "FAIL: p95 ${p95} ms exceeds the ${P95_BUDGET_MS} ms budget (§18.2 M2)" >&2
  status=1
fi
[ "$status" -eq 0 ] && echo "PASS"
exit "$status"
