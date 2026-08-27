-- Users, handles, and email verification (M1/WG-B).

-- name: CreateHandle :exec
INSERT INTO handles (id, handle, kind) VALUES ($1, $2, $3);

-- name: GetHandle :one
SELECT * FROM handles WHERE handle = $1;

-- name: CreateUser :one
INSERT INTO users (id, email, display_name, password_hash)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: GetUserByID :one
SELECT u.*, h.handle FROM users u JOIN handles h ON h.id = u.id WHERE u.id = $1;

-- name: GetUserByEmail :one
SELECT u.*, h.handle FROM users u JOIN handles h ON h.id = u.id WHERE u.email = $1;

-- name: GetUserByHandle :one
SELECT u.*, h.handle FROM users u JOIN handles h ON h.id = u.id WHERE h.handle = $1 AND h.kind = 'user';

-- name: UpdateUserDisplayName :one
UPDATE users SET display_name = $2, updated_at = now() WHERE id = $1 RETURNING id;

-- name: SetUserPasswordHash :exec
UPDATE users SET password_hash = $2, updated_at = now() WHERE id = $1;

-- name: SetUserTOTPSecret :exec
UPDATE users SET totp_secret_enc = $2, totp_enabled = false, updated_at = now() WHERE id = $1;

-- name: EnableUserTOTP :exec
UPDATE users SET totp_enabled = true, updated_at = now() WHERE id = $1;

-- name: MarkEmailVerified :exec
UPDATE users SET email_verified_at = now(), updated_at = now() WHERE id = $1;

-- name: CreateEmailVerification :exec
INSERT INTO email_verifications (token_sha256, user_id, expires_at) VALUES ($1, $2, $3);

-- name: ConsumeEmailVerification :one
UPDATE email_verifications
SET consumed_at = now()
WHERE token_sha256 = $1 AND consumed_at IS NULL AND expires_at > now()
RETURNING user_id;
