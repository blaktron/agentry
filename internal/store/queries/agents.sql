-- Agents, repos, and per-agent grants (M2/WG-C; grows in M3).

-- name: CreateRepo :one
INSERT INTO repos (id) VALUES ($1) RETURNING *;

-- name: GetRepo :one
SELECT * FROM repos WHERE id = $1;

-- name: UpdateRepoOnPush :exec
UPDATE repos SET size_bytes = $2, last_push_at = now() WHERE id = $1;

-- name: CreateAgent :one
INSERT INTO agents (id, namespace_id, name, kind, visibility, repo_id, summary)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: GetAgentByPath :one
SELECT a.*, h.handle AS namespace, h.kind AS namespace_kind, r.default_branch, r.size_bytes
FROM agents a
JOIN handles h ON h.id = a.namespace_id
JOIN repos r ON r.id = a.repo_id
WHERE h.handle = $1 AND a.name = $2;

-- name: UpdateAgentSettings :exec
UPDATE agents SET
  summary = coalesce(sqlc.narg('summary'), summary),
  visibility = coalesce(sqlc.narg('visibility'), visibility),
  auto_publish_tags = coalesce(sqlc.narg('auto_publish_tags'), auto_publish_tags),
  updated_at = now()
WHERE id = $1;

-- name: ListAgentsByNamespace :many
SELECT a.*, h.handle AS namespace
FROM agents a JOIN handles h ON h.id = a.namespace_id
WHERE h.handle = $1
  AND (a.visibility = 'public' OR sqlc.arg(include_private)::boolean)
ORDER BY a.name;

-- name: CountAgentsInNamespace :one
SELECT count(*) FROM agents WHERE namespace_id = $1;

-- name: UpsertAgentUserGrant :exec
INSERT INTO agent_user_grants (agent_id, user_id, role) VALUES ($1, $2, $3)
ON CONFLICT (agent_id, user_id) DO UPDATE SET role = EXCLUDED.role, updated_at = now();

-- name: DeleteAgentUserGrant :execrows
DELETE FROM agent_user_grants WHERE agent_id = $1 AND user_id = $2;

-- name: UpsertAgentTeamGrant :exec
INSERT INTO agent_team_grants (agent_id, team_id, role) VALUES ($1, $2, $3)
ON CONFLICT (agent_id, team_id) DO UPDATE SET role = EXCLUDED.role, updated_at = now();

-- name: DeleteAgentTeamGrant :execrows
DELETE FROM agent_team_grants WHERE agent_id = $1 AND team_id = $2;

-- name: ListAgentGrants :many
SELECT 'user' AS kind, h.handle AS grantee, g.role
FROM agent_user_grants g JOIN handles h ON h.id = g.user_id
WHERE g.agent_id = $1
UNION ALL
SELECT 'team' AS kind, t.slug::citext AS grantee, g.role
FROM agent_team_grants g JOIN teams t ON t.id = g.team_id
WHERE g.agent_id = $1
ORDER BY kind, grantee;

-- name: GetAgentUserGrant :one
SELECT role FROM agent_user_grants WHERE agent_id = $1 AND user_id = $2;

-- name: ListAgentTeamGrantsForUser :many
SELECT g.role
FROM agent_team_grants g
JOIN team_members tm ON tm.team_id = g.team_id
WHERE g.agent_id = $1 AND tm.user_id = $2;

-- name: GetAgentByID :one
SELECT a.*, h.handle AS namespace, h.kind AS namespace_kind
FROM agents a JOIN handles h ON h.id = a.namespace_id
WHERE a.id = $1;

-- name: SetAgentQuarantineState :exec
UPDATE agents SET quarantine_state = $2, updated_at = now() WHERE id = $1;

-- name: SearchAgents :many
-- Public FTS search (§10.4, D-20): weighted tsvector + trigram fuzzy fallback
-- on name, ranked by relevance × install popularity × recency decay.
SELECT a.id, a.name, a.kind, a.visibility, a.summary, a.quarantine_state,
       a.created_at, h.handle AS namespace,
       coalesce(d.installs, 0)::bigint AS installs,
       ts_rank_cd(a.search_tsv, websearch_to_tsquery('english', sqlc.arg(query)::text)) AS rank
FROM agents a
JOIN handles h ON h.id = a.namespace_id
LEFT JOIN (
  SELECT agent_id, sum(installs) AS installs
  FROM download_stats WHERE day >= current_date - 30 GROUP BY agent_id
) d ON d.agent_id = a.id
WHERE a.visibility = 'public'
  AND a.quarantine_state <> 'blocked'
  AND (
    sqlc.arg(query)::text = ''
    OR a.search_tsv @@ websearch_to_tsquery('english', sqlc.arg(query)::text)
    OR a.name::text % sqlc.arg(query)::text
  )
  AND (sqlc.narg('kind')::text IS NULL OR a.kind = sqlc.narg('kind'))
ORDER BY
  ts_rank_cd(a.search_tsv, websearch_to_tsquery('english', sqlc.arg(query)::text)) DESC,
  coalesce(d.installs, 0) DESC,
  a.created_at DESC
LIMIT $1 OFFSET $2;

-- name: SearchFacetKinds :many
SELECT a.kind, count(*)::bigint AS n
FROM agents a
WHERE a.visibility = 'public' AND a.quarantine_state <> 'blocked'
  AND (sqlc.arg(query)::text = '' OR a.search_tsv @@ websearch_to_tsquery('english', sqlc.arg(query)::text))
GROUP BY a.kind ORDER BY a.kind;
