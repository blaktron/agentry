-- MCP server vulnerability scanning (agentry#177, DEV-090).

-- name: GetMCPServerScan :one
SELECT * FROM mcp_server_scans WHERE ecosystem = $1 AND package = $2 AND version = $3;

-- name: UpsertMCPServerScan :one
INSERT INTO mcp_server_scans (ecosystem, package, version, status, max_severity, advisories, last_error)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (ecosystem, package, version) DO UPDATE SET
  status = EXCLUDED.status,
  max_severity = EXCLUDED.max_severity,
  advisories = EXCLUDED.advisories,
  last_error = EXCLUDED.last_error,
  last_checked_at = now()
RETURNING *;

-- name: ListMCPServerScansCheckedBefore :many
SELECT * FROM mcp_server_scans WHERE last_checked_at < $1 ORDER BY last_checked_at LIMIT $2;

-- name: DeleteVersionMCPServers :exec
DELETE FROM agent_version_mcp_servers WHERE version_id = $1;

-- name: InsertVersionMCPServer :exec
INSERT INTO agent_version_mcp_servers (version_id, ecosystem, package, version)
VALUES ($1, $2, $3, $4)
ON CONFLICT DO NOTHING;

-- name: ListPublishedVersionsUsingMCPServer :many
SELECT v.* FROM agent_versions v
JOIN agent_version_mcp_servers m ON m.version_id = v.id
WHERE m.ecosystem = $1 AND m.package = $2 AND m.version = $3 AND v.status = 'published'
ORDER BY v.created_at;
