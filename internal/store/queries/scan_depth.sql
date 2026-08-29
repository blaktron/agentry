-- Queries the scanner stages need beyond the scan-run bookkeeping in
-- scanning.sql (§8.3). Kept in their own file so the pipeline's read-only
-- context lookups are obvious to a reviewer.

-- name: ListPopularAgentNames :many
-- Top-N published public agent names by lifetime installs — the live feed for
-- S8's anti-typosquat compare (§8.3 S8, T-10). Without it the confusable and
-- edit-distance checks compare against an empty list and never fire.
-- Quarantined/blocked agents are excluded: a name nobody should be installing
-- is not a name worth protecting from imitation.
SELECT a.name::text AS name
FROM agents a
LEFT JOIN (
  SELECT agent_id, sum(installs) AS installs
  FROM download_stats GROUP BY agent_id
) d ON d.agent_id = a.id
WHERE a.visibility = 'public'
  AND a.quarantine_state = 'none'
  AND a.latest_published_version_id IS NOT NULL
ORDER BY coalesce(d.installs, 0) DESC, a.created_at ASC
LIMIT $1;
