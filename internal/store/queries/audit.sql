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
