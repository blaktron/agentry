-- Account installs (plan web-dashboard-shell §5; agentry#448): the
-- per-account record of a BriefAgent release a person accepted and the
-- contract they consented to. Nothing here touches download_stats.

-- name: UpsertAccountInstall :one
-- A PUT on an existing record is the update: the version moves and the
-- snapshot and consents are the new release's; the ref is the name the
-- caller used, which they can read.
INSERT INTO account_installs (user_id, agent_id, version_id, ref_namespace, ref_name, capabilities, accepted_unsigned, accepted_unscanned)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (user_id, agent_id) DO UPDATE SET
  version_id = EXCLUDED.version_id,
  ref_namespace = EXCLUDED.ref_namespace,
  ref_name = EXCLUDED.ref_name,
  capabilities = EXCLUDED.capabilities,
  accepted_unsigned = EXCLUDED.accepted_unsigned,
  accepted_unscanned = EXCLUDED.accepted_unscanned,
  updated_at = now()
RETURNING *;

-- name: GetAccountInstall :one
SELECT * FROM account_installs WHERE user_id = $1 AND agent_id = $2;

-- name: DeleteAccountInstall :execrows
DELETE FROM account_installs WHERE user_id = $1 AND agent_id = $2;

-- name: DeleteAccountInstallByRef :many
-- The record as the list names it, for a BriefAgent the caller can no
-- longer read or find at that name. Returns the agent ids removed, for
-- the audit row.
DELETE FROM account_installs WHERE user_id = $1 AND ref_namespace = $2 AND ref_name = $3
RETURNING agent_id;

-- name: ListAccountInstalls :many
-- The caller's records, newest change first, with the ref each names
-- today. The handler composes the rest through the read seam every agent
-- route takes, and falls back to the stored ref for one it cannot read.
SELECT sqlc.embed(ai), h.handle AS namespace, a.name
FROM account_installs ai
JOIN agents a ON a.id = ai.agent_id
JOIN handles h ON h.id = a.namespace_id
WHERE ai.user_id = $1
ORDER BY ai.updated_at DESC, a.name;

-- name: DeleteOrgAgentAccountInstalls :execrows
DELETE FROM account_installs WHERE agent_id IN (SELECT id FROM agents WHERE namespace_id = $1);
