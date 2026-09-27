-- Trusted devices (plan trusted-devices.md, agentry#461). The credential a
-- browser earns by answering the second factor, so a later password sign-in
-- from it skips the code.
--
-- These are the auth-path queries: establish and touch the credential. The
-- account-facing one — clear all of an account's records — arrives with the
-- route that uses it (agentry#672; the list and per-browser removal of the
-- closed agentry#462 were dropped by DEV-163), following the split auth.sql
-- and sessions_api.sql already set.

-- name: CreateTrustedDevice :one
INSERT INTO trusted_devices (id, user_id, token_sha256, ip, user_agent, expires_at)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING id, user_id, created_at, last_seen_at, expires_at;

-- GetTrustedDeviceByHash answers "is this cookie this user's, and is it still
-- live?" in one statement. Scoped by user_id as well as the hash, so "not
-- mine" and "does not exist" collapse into zero rows in the database rather
-- than in a branch above it — there is no lookup that could leak another
-- user's record, and no path where a valid token for someone else is
-- distinguished from an invalid one. Expiry and revocation are filtered here
-- too, so a row the sweep has not reached yet behaves exactly like one it has.
-- name: GetTrustedDeviceByHash :one
SELECT id, user_id, created_at, last_seen_at, expires_at
FROM trusted_devices
WHERE token_sha256 = $1 AND user_id = $2 AND revoked_at IS NULL AND expires_at > now();

-- TouchTrustedDevice records use. It moves last_seen_at and deliberately not
-- expires_at: the lifetime is absolute, so a stolen cookie does not become
-- immortal by being used, and a person who signs in daily is still asked
-- again on day thirty (plan D9, matching §12.4's "24 h absolute" for
-- sessions).
-- name: TouchTrustedDevice :exec
UPDATE trusted_devices SET last_seen_at = now() WHERE id = $1;

-- RevokeTrustedDevicesForUser revokes every live record of one account. It
-- sits beside RevokeUserSessions in §12.5 SCIM deactivation, because a
-- remembered browser is a way back in that outliving the sessions would
-- otherwise leave open.
--
-- That deactivation is what makes this load-bearing rather than tidy: it drops
-- the membership, revokes the org-bound PATs and kills the sessions, but it
-- deliberately does not change the account's state or clear its password,
-- since the person may exist outside the organization. So without this, a
-- deprovisioned user could sign straight back in with their password from a
-- remembered browser and be asked for *less* than before — the second factor
-- skipped — which is the opposite of the guarantee scimDeactivate exists to
-- make (agentry#461).
--
-- §12.7 erasure is the other place access is taken away, and it uses
-- DeleteTrustedDevicesForUser below instead: erasure sets state='deleted' and
-- nulls the password hash, so its rows are already inert as credentials, and
-- what it owes is the removal of the personal data they hold.
--
-- The account-facing revocation — every record, from the site's "Clear
-- remembered devices" button — arrives with agentry#672 (DEV-163).
-- name: RevokeTrustedDevicesForUser :execrows
UPDATE trusted_devices SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL;

-- DeleteTrustedDevicesForUser is the erasure half (§12.7), and it deletes
-- rather than revokes. A revoked row still holds an address and a user agent,
-- which is personal data belonging to a person who asked to be deleted; the
-- users row survives erasure only because audit events and immutable published
-- content need a stable, now-opaque actor id, and nothing needs that of a
-- browser credential. That the credential was issued is already in the audit
-- log as user.trusted_device_add, so deleting the row loses no record.
-- name: DeleteTrustedDevicesForUser :execrows
DELETE FROM trusted_devices WHERE user_id = $1;
