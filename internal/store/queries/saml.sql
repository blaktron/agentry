-- name: ConsumeSAMLAssertion :execrows
-- Records the assertion id until its expiry, or renews a row whose expiry
-- has passed; a live row stays as it is, and the zero rows affected then
-- say the assertion was seen before.
INSERT INTO saml_consumed_assertions (id, expires_at) VALUES ($1, $2)
ON CONFLICT (id) DO UPDATE SET expires_at = EXCLUDED.expires_at
WHERE saml_consumed_assertions.expires_at <= now();

-- name: SweepSAMLAssertions :execrows
DELETE FROM saml_consumed_assertions WHERE expires_at <= now();

-- name: TrackSAMLRequest :exec
INSERT INTO saml_requests (id, expires_at) VALUES ($1, $2)
ON CONFLICT (id) DO UPDATE SET expires_at = EXCLUDED.expires_at;

-- name: ConsumeSAMLRequest :execrows
-- Single use: the row goes with the read, and an expired one counts as gone.
DELETE FROM saml_requests WHERE id = $1 AND expires_at > now();

-- name: SweepSAMLRequests :execrows
DELETE FROM saml_requests WHERE expires_at <= now();
