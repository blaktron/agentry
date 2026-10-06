# shellcheck shell=bash disable=SC2034
# The label array is consumed by each sourcing script.
# Sourced by directory acceptance scripts. Local runs keep their EXIT trap;
# CI also has an independent cleanup step and a host-side expiry sweep (#800).
DIRECTORY_DOCKER_LABELS=()
if [ "${GITHUB_ACTIONS:-}" = true ]; then
  DIRECTORY_JOB="${GITHUB_REPOSITORY:?}/${GITHUB_RUN_ID:?}/${GITHUB_RUN_ATTEMPT:?}/${GITHUB_JOB:?}"
  DIRECTORY_DOCKER_LABELS=(
    --label io.agentry.ci.directory=true
    --label "io.agentry.ci.directory.job=$DIRECTORY_JOB"
    # Every directory job times out in <=25 minutes. Ten minutes of grace
    # covers cancellation; the ten-minute cron removes killed jobs by 45m.
    --label "io.agentry.ci.directory.expires-at=$(( $(date +%s) + 2100 ))"
  )
fi
