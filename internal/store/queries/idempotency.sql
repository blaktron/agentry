-- Idempotency-Key replay store ("Mutating POSTs accept Idempotency-Key").

-- name: ClaimIdempotencyKey :one
-- Reserves the key for this request. A conflicting row means the key was
-- used before: the existing row comes back so the caller can decide between
-- replaying its recorded response (same request_hash) and refusing (409).
INSERT INTO idempotency_keys (key, user_id, endpoint, request_hash, expires_at)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (user_id, endpoint, key) DO UPDATE
  SET key = idempotency_keys.key           -- no-op update so RETURNING fires
RETURNING *, (xmax = 0) AS claimed;

-- name: CompleteIdempotencyKey :exec
UPDATE idempotency_keys
SET response_status = $4, response_body = $5, resource_id = $6
WHERE user_id = $1 AND endpoint = $2 AND key = $3;

-- name: ReleaseIdempotencyKey :exec
-- Drops an unfinished claim so a failed request does not poison the key.
DELETE FROM idempotency_keys
WHERE user_id = $1 AND endpoint = $2 AND key = $3 AND response_status IS NULL;

-- name: PurgeExpiredIdempotencyKeys :execrows
DELETE FROM idempotency_keys WHERE expires_at < now();
