-- Dependency alerts (agentry#177 M2, DEV-090).

-- name: OpenMCPDependencyAlert :one
INSERT INTO mcp_dependency_alerts (id, version_id, ecosystem, package, package_version, severity, advisory_ids, fixed_in)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (version_id, ecosystem, package, package_version) WHERE resolved_at IS NULL DO NOTHING
RETURNING *;

-- name: MarkMCPDependencyAlertNotified :exec
UPDATE mcp_dependency_alerts SET notified_at = now() WHERE id = $1;

-- name: ListOpenMCPDependencyAlertsForVersion :many
SELECT * FROM mcp_dependency_alerts WHERE version_id = $1 AND resolved_at IS NULL ORDER BY created_at;

-- name: ListOpenMCPDependencyAlertsForAgent :many
SELECT a.*, v.version AS agent_version
FROM mcp_dependency_alerts a JOIN agent_versions v ON v.id = a.version_id
WHERE v.agent_id = $1 AND a.resolved_at IS NULL
ORDER BY v.created_at DESC, a.created_at;

-- name: ListOpenMCPDependencyAlertsForSubmitter :many
SELECT a.*, v.version AS agent_version, v.agent_id
FROM mcp_dependency_alerts a JOIN agent_versions v ON v.id = a.version_id
WHERE v.submitted_by = $1 AND a.resolved_at IS NULL
ORDER BY a.created_at DESC;

-- name: ResolveMCPDependencyAlertsForVersion :execrows
UPDATE mcp_dependency_alerts SET resolved_at = now(), resolved_reason = $2
WHERE version_id = $1 AND resolved_at IS NULL;

-- name: ResolveMCPDependencyAlertsForServer :execrows
UPDATE mcp_dependency_alerts SET resolved_at = now(), resolved_reason = $4
WHERE ecosystem = $1 AND package = $2 AND package_version = $3 AND resolved_at IS NULL;

-- name: ResolveMCPDependencyAlertsForUnpublishedVersions :execrows
UPDATE mcp_dependency_alerts a SET resolved_at = now(), resolved_reason = 'version-' || v.status
FROM agent_versions v
WHERE v.id = a.version_id AND v.status <> 'published' AND a.resolved_at IS NULL;
