-- Append-only audit log (M1/WG-B, §12.6).

-- name: InsertAuditEvent :exec
INSERT INTO audit_events (id, occurred_at, actor_id, actor_kind, org_id, action, target_kind, target_id, ip, user_agent, detail)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11);

-- name: EnsureAuditPartition :exec
SELECT audit_ensure_partition($1::date);

-- name: ListOrgAuditEvents :many
SELECT a.*, h.handle AS actor_handle
FROM audit_events a
LEFT JOIN handles h ON h.id = a.actor_id
WHERE a.org_id = $1
  AND (sqlc.narg('action')::text IS NULL OR a.action = sqlc.narg('action'))
  AND (sqlc.narg('before_time')::timestamptz IS NULL
       OR a.occurred_at < sqlc.narg('before_time')
       OR (a.occurred_at = sqlc.narg('before_time') AND a.id < sqlc.narg('before_id')))
ORDER BY a.occurred_at DESC, a.id DESC
LIMIT $2;

-- name: CountAuditEvents :one
SELECT count(*) FROM audit_events WHERE action = $1 AND (org_id = $2 OR $2 IS NULL);

-- name: ListPlatformAuditEvents :many
-- The platform-staff slice: every org plus un-scoped events (§12.6). Same
-- keyset cursor as the org view so one decoder serves both.
SELECT a.*, h.handle AS actor_handle
FROM audit_events a
LEFT JOIN handles h ON h.id = a.actor_id
WHERE (sqlc.narg('action')::text IS NULL OR a.action = sqlc.narg('action'))
  AND (sqlc.narg('org_id')::uuid IS NULL OR a.org_id = sqlc.narg('org_id'))
  AND (sqlc.narg('before_time')::timestamptz IS NULL
       OR a.occurred_at < sqlc.narg('before_time')
       OR (a.occurred_at = sqlc.narg('before_time') AND a.id < sqlc.narg('before_id')))
ORDER BY a.occurred_at DESC, a.id DESC
LIMIT $1;

-- name: ListAgentActivity :many
-- GET /agents/{ns}/{name}/activity (§9.2). Entries targeting the agent
-- itself, plus entries targeting any of its versions (joined so the version
-- string can be surfaced). public_actions, when non-empty, restricts the
-- result to the public-safe subset.
SELECT a.id, a.occurred_at, a.action, a.detail, a.target_kind, a.target_id,
       h.handle AS actor_handle, v.version AS version
FROM audit_events a
LEFT JOIN handles h ON h.id = a.actor_id
LEFT JOIN agent_versions v ON a.target_kind = 'agent_version' AND v.id = a.target_id
WHERE (
    (a.target_kind = 'agent' AND a.target_id = sqlc.arg(agent_id))
    OR v.agent_id = sqlc.arg(agent_id)
  )
  AND (cardinality(sqlc.arg(public_actions)::text[]) = 0
       OR a.action = ANY(sqlc.arg(public_actions)::text[]))
  AND (sqlc.narg('before_time')::timestamptz IS NULL
       OR a.occurred_at < sqlc.narg('before_time')
       OR (a.occurred_at = sqlc.narg('before_time') AND a.id < sqlc.narg('before_id')))
ORDER BY a.occurred_at DESC, a.id DESC
LIMIT $1;

-- name: PruneAuditPartitions :one
-- §4.3 retention: drop whole monthly partitions older than the cutoff rather
-- than DELETE rows (the append-only trigger refuses row deletes, and dropping
-- a partition is O(1)). Returns the number of partitions dropped.
SELECT audit_prune_partitions($1::date)::int AS dropped;
