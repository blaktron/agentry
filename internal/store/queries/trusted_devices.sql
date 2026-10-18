-- Trusted devices. The credential a browser earns by answering the second
-- factor at a directory, so a later sign-in from it skips the code.
--
-- The credential's queries: establish and touch it, take it away when access
-- is taken away (deprovisioning, erasure), the account's own count and clear, and the
-- expiry sweep. There is no list and no per-browser removal.

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
-- too, so a row the sweep has not reached yet behaves exactly like one it
-- has.
-- name: GetTrustedDeviceByHash :one
SELECT id, user_id, created_at, last_seen_at, expires_at
FROM trusted_devices
WHERE token_sha256 = $1 AND user_id = $2 AND revoked_at IS NULL AND expires_at > now();

-- TouchTrustedDevice records use. It moves last_seen_at and deliberately not
-- expires_at: the lifetime is absolute, so a stolen cookie does not become
-- immortal by being used, and a person who signs in daily is still asked
-- again on day thirty (matching the 24 h absolute lifetime of sessions).
-- name: TouchTrustedDevice :exec
UPDATE trusted_devices SET last_seen_at = now() WHERE id = $1;

-- RevokeTrustedDevicesForUser revokes every live record of one account. It
-- sits beside RevokeUserSessions in deprovisioning, because a remembered
-- browser is a way back in that outliving the sessions would otherwise leave
-- open.
--
-- That deactivation is what makes this load-bearing rather than tidy: it
-- drops the membership, revokes the org-bound PATs and kills the sessions,
-- but it deliberately does not change the account's state, since the
-- person may exist outside the organization. So without this, a
-- deprovisioned user could sign straight back in from a remembered browser
-- and be asked for *less* than before — the second factor skipped — which is
-- the opposite of the guarantee deprovisioning exists to make.
--
-- Erasure is the other place access is taken away, and it uses
-- DeleteTrustedDevicesForUser below instead: erasure sets state='deleted', so
-- its rows are already inert as credentials, and what it owes is the removal
-- of the personal data they hold.
--
-- The account-facing clear is ClearLiveTrustedDevicesForUser below, which
-- touches live records only so that what it reports matches the count.
-- name: RevokeTrustedDevicesForUser :execrows
UPDATE trusted_devices SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL;

-- CountLiveTrustedDevicesForUser is what the site's "Clear remembered
-- devices" button reads to say whether there is anything to clear. Live is
-- what the lookup honours: not revoked, not expired, so the number is exactly
-- the browsers that would skip the code.
-- name: CountLiveTrustedDevicesForUser :one
SELECT count(*) FROM trusted_devices
WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > now();

-- ClearLiveTrustedDevicesForUser is the site's "Clear remembered devices"
-- (DELETE /user/trusted-devices), for the caller's own account only. It
-- revokes exactly the rows the count counts, live ones, so the number the
-- button reports is the number it showed; expired rows are already inert and
-- are the sweep's.
-- name: ClearLiveTrustedDevicesForUser :execrows
UPDATE trusted_devices SET revoked_at = now()
WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > now();

-- DeleteExpiredTrustedDevices is the expiry sweep: it removes the rows past
-- their own expiry, and only those. A revoked record that has not expired yet
-- is kept until it does: it is already inert, and keeping it to its own
-- lifetime means no cap or clock of the sweep's ever decides when a record
-- goes. Every read already filters on expiry, so a row the sweep has not
-- reached behaves exactly like one it has.
-- name: DeleteExpiredTrustedDevices :execrows
DELETE FROM trusted_devices WHERE expires_at <= now();

-- DeleteTrustedDevicesForUser is the erasure half, and it deletes rather than
-- revokes. A revoked row still holds an address and a user agent, which is
-- personal data belonging to a person who asked to be deleted; the users row
-- survives erasure only because audit events and immutable published content
-- need a stable, now-opaque actor id, and nothing needs that of a browser
-- credential. That the credential was issued is already in the audit log as
-- user.trusted_device_add, so deleting the row loses no record.
-- name: DeleteTrustedDevicesForUser :execrows
DELETE FROM trusted_devices WHERE user_id = $1;
