-- Stars and the per-agent counters the stats endpoint reports (§9.2
-- "Stars & counts"). Install counts read the download_stats daily rollup
-- (§4.2) rather than raw events.

-- name: StarAgent :exec
-- Idempotent by design: PUT /user/stars/{ns}/{name} may be retried.
INSERT INTO stars (user_id, agent_id) VALUES ($1, $2)
ON CONFLICT (user_id, agent_id) DO NOTHING;

-- name: UnstarAgent :execrows
DELETE FROM stars WHERE user_id = $1 AND agent_id = $2;

-- name: IsAgentStarred :one
SELECT EXISTS (SELECT 1 FROM stars WHERE user_id = $1 AND agent_id = $2);

-- name: CountAgentStars :one
SELECT count(*)::bigint FROM stars WHERE agent_id = $1;

-- name: GetAgentInstallCounts :one
-- Lifetime and trailing-30-day installs from the daily rollup, in one pass.
SELECT
  coalesce(sum(installs), 0)::bigint AS installs_total,
  coalesce(sum(installs) FILTER (WHERE day >= current_date - 30), 0)::bigint AS installs_30d
FROM download_stats WHERE agent_id = $1;
