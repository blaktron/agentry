-- PATs and sessions (M1/WG-B, D-22, D-23).

-- name: CreatePAT :one
INSERT INTO pats (id, user_id, name, token_sha256, token_prefix, scopes, org_id, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING *;

-- name: GetPATByHash :one
SELECT p.* FROM pats p
WHERE p.token_sha256 = $1 AND p.revoked_at IS NULL AND p.expires_at > now();

-- name: TouchPAT :exec
UPDATE pats SET last_used_at = now() WHERE id = $1;

-- name: ListPATs :many
SELECT p.*, h.handle AS org_handle
FROM pats p
LEFT JOIN handles h ON h.id = p.org_id
WHERE p.user_id = $1 AND p.revoked_at IS NULL
ORDER BY p.created_at DESC;

-- name: RevokePAT :execrows
UPDATE pats SET revoked_at = now() WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL;

-- name: RevokeOrgBoundPATsForUser :execrows
UPDATE pats SET revoked_at = now() WHERE user_id = $1 AND org_id = $2 AND revoked_at IS NULL;

-- name: CreateSession :one
INSERT INTO sessions (id, token_sha256, user_id, csrf_token, ip, user_agent, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: GetSessionByHash :one
SELECT s.* FROM sessions s
WHERE s.token_sha256 = $1 AND s.revoked_at IS NULL AND s.expires_at > now();

-- name: TouchSession :exec
UPDATE sessions SET last_seen_at = now() WHERE id = $1;

-- name: RevokeSession :execrows
UPDATE sessions SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL;

-- name: RevokeUserSessions :execrows
UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL;
