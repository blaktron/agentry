-- SSH keys (§6.1 Q7, agentry#70).

-- name: CreateSSHKey :one
INSERT INTO user_ssh_keys (id, user_id, title, key_type, public_key, fingerprint)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: ListSSHKeys :many
SELECT * FROM user_ssh_keys WHERE user_id = $1 AND revoked_at IS NULL ORDER BY created_at DESC;

-- name: GetSSHKeyByFingerprint :one
SELECT * FROM user_ssh_keys WHERE fingerprint = $1 AND revoked_at IS NULL;

-- name: TouchSSHKey :exec
UPDATE user_ssh_keys SET last_used_at = now() WHERE id = $1;

-- name: RevokeSSHKey :execrows
UPDATE user_ssh_keys SET revoked_at = now() WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL;
