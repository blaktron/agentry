-- SAML shared state: the consumed-assertion replay set and the
-- outstanding-AuthnRequest tracker, shared by every API replica (agentry#414).

-- name: ConsumeSAMLAssertion :execrows
-- Records the assertion id, or renews a row whose recorded expiry has
-- passed; a live row stays as it is, and the zero rows affected then say
-- the assertion was seen before. Two replicas presenting one id
-- concurrently cannot both win: the loser of the insert waits on the
-- winner's row and re-reads it against the WHERE, which by then finds it
-- live.
-- The record is kept for at least the caller's floor, on the database's
-- own clock — the one the WHERE reads — because the validator goes on
-- accepting an assertion for its clock skew past the expiry the assertion
-- carries, so a record that lapsed at that expiry would leave the tail of
-- the window unprotected. Flooring on the database clock keeps the margin
-- whatever the replicas' clocks say.
INSERT INTO saml_consumed_assertions (id, expires_at)
VALUES ($1, GREATEST(sqlc.arg(expires_at)::timestamptz, now() + make_interval(secs => sqlc.arg(floor_seconds)::double precision)))
ON CONFLICT (id) DO UPDATE SET expires_at = EXCLUDED.expires_at
WHERE saml_consumed_assertions.expires_at <= now();

-- name: DeleteExpiredSAMLAssertions :execrows
DELETE FROM saml_consumed_assertions WHERE expires_at <= now();

-- name: TrackSAMLRequest :exec
INSERT INTO saml_requests (id, expires_at) VALUES ($1, $2)
ON CONFLICT (id) DO UPDATE SET expires_at = EXCLUDED.expires_at;

-- name: ConsumeSAMLRequest :execrows
-- Single use: the row goes with the read, and an expired one counts as gone.
DELETE FROM saml_requests WHERE id = $1 AND expires_at > now();

-- name: DeleteExpiredSAMLRequests :execrows
DELETE FROM saml_requests WHERE expires_at <= now();
