-- Desktop browser sign-in grants.

-- name: CreateDesktopGrant :one
INSERT INTO desktop_grants (id, user_id, code_sha256, state_sha256, scopes, name, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: ConsumeDesktopGrant :one
-- Single-use and time-bound in one statement: the row is claimed only if it
-- is unconsumed and unexpired, so two racing exchanges cannot both succeed.
UPDATE desktop_grants
SET consumed_at = now()
WHERE code_sha256 = $1 AND state_sha256 = $2 AND consumed_at IS NULL AND expires_at > now()
RETURNING *;

-- name: DeleteExpiredDesktopGrants :execrows
DELETE FROM desktop_grants WHERE expires_at < now() - interval '1 day';

-- name: ConsumeDesktopGrantsForUser :execrows
-- Clear-data: a code minted before the clear cannot be exchanged for a token
-- after it.
UPDATE desktop_grants SET consumed_at = now() WHERE user_id = $1 AND consumed_at IS NULL;
