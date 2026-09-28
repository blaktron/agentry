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

-- name: ListUserDirectoryLinks :many
-- The directory accounts the account is linked to by directory sign-ins
-- (agentry#706, agentry#727), oldest first: each one's subject, "authentik:"
-- stripped (the uid the directory reports for it), and the directory's own
-- id for it, learnt at sign-in (0 until the identity signs in under a
-- directory that sends it). The settings page reads the oldest, so its
-- answer does not move while the account keeps one; erasure takes them all.
SELECT substring(i.subject from 11)::text AS directory_subject,
       COALESCE(i.directory_account_id, 0)::bigint AS directory_account_id
FROM identities i
WHERE i.user_id = $1 AND i.provider_kind = 'social'
  AND i.sso_connection_id IS NULL AND i.subject LIKE 'authentik:%'
ORDER BY i.created_at, i.id;

-- name: SetSocialIdentityDirectoryAccount :exec
-- Records the directory's id for the account a directory identity signs in
-- as (agentry#727), from the directory's signed ID token; moves it when the
-- directory reports another.
UPDATE identities SET directory_account_id = $2
WHERE sso_connection_id IS NULL AND provider_kind = 'social' AND subject = $1
  AND directory_account_id IS DISTINCT FROM $2;

-- name: ListStaffMirrorAccounts :many
-- Every account that is platform staff and active, with its verified
-- address (lower-cased; the directory's match is case-blind) and each
-- directory subject it is linked to by a directory sign-in, "authentik:"
-- stripped (empty when it has none): the set the directory's staff mirror
-- group is kept equal to (agentry#598).
SELECT u.id, lower(u.email)::text AS email,
       coalesce(substring(i.subject from 11), '')::text AS directory_subject
FROM users u
LEFT JOIN identities i ON i.user_id = u.id AND i.provider_kind = 'social'
     AND i.sso_connection_id IS NULL AND i.subject LIKE 'authentik:%'
WHERE u.platform_staff AND u.state = 'active' AND u.email_verified_at IS NOT NULL
ORDER BY 2, 3;

-- name: ListStaffOrgMembersNotStaff :many
-- Active members of the staff organization who are not platform staff: an
-- address outside its domain or unverified, or an account that is not
-- active (agentry#598). Reported at start-up, never removed.
SELECT h.handle FROM memberships m
JOIN users u ON u.id = m.user_id
JOIN handles h ON h.id = u.id
WHERE m.org_id = $1 AND m.state = 'active' AND NOT u.platform_staff
ORDER BY h.handle;

-- name: ListStaffSyncCandidates :many
-- The accounts whose platform_staff the staff rule could change
-- (agentry#556): every account flagged today, and every active member of
-- the staff organization. The start-up resync recomputes exactly these.
SELECT id FROM users
WHERE platform_staff
   OR id IN (SELECT m.user_id FROM memberships m WHERE m.org_id = $1 AND m.state = 'active')
ORDER BY id;

-- name: SetUserPlatformStaff :exec
-- The staff rule decides platform staff (agentry#556; registry.SyncStaffIn).
UPDATE users SET platform_staff = $2, updated_at = now() WHERE id = $1;

-- name: SetUserIdPMFA :exec
-- The directory asserted a second factor at this sign-in (agentry#23).
UPDATE users SET idp_mfa_at = now(), updated_at = now() WHERE id = $1;

-- name: SetUserCookieAck :exec
-- Write-once by intent: re-acknowledging just refreshes the timestamp.
UPDATE users SET cookie_ack_at = now(), updated_at = now() WHERE id = $1;

-- name: MarkEmailVerified :exec
UPDATE users SET email_verified_at = now(), updated_at = now() WHERE id = $1;

-- name: CreateEmailVerification :exec
INSERT INTO email_verifications (token_sha256, user_id, expires_at) VALUES ($1, $2, $3);

-- name: ConsumeEmailVerification :one
UPDATE email_verifications
SET consumed_at = now()
WHERE token_sha256 = $1 AND consumed_at IS NULL AND expires_at > now()
RETURNING user_id;

-- name: CountPublishedVersionsByUser :one
-- Published public versions under a user's PERSONAL namespace (§12.7: the
-- deletion chooser needs to know whether consumers depend on them).
SELECT count(*) FROM agent_versions av
JOIN agents a ON a.id = av.agent_id
JOIN handles h ON h.id = a.namespace_id
WHERE h.id = $1 AND h.kind = 'user' AND a.visibility = 'public' AND av.status = 'published';

-- name: ListPersonalNamespaceAgents :many
SELECT a.id, a.name, a.visibility, a.latest_published_version_id
FROM agents a JOIN handles h ON h.id = a.namespace_id
WHERE h.id = $1 AND h.kind = 'user';

-- name: PseudonymizeUser :exec
-- GDPR erasure (§12.7): PII is purged, the row survives so audit events and
-- immutable published content keep a stable (now opaque) actor id. The
-- tombstone keeps only a salted hash of the email for abuse-recurrence
-- detection — never the address itself.
UPDATE users SET
  email = $2,
  email_verified_at = NULL,
  display_name = 'deleted user',
  password_hash = NULL,
  totp_secret_enc = NULL,
  totp_enabled = false,
  state = 'deleted',
  deleted_tombstone = $3,
  updated_at = now()
WHERE id = $1;

-- name: ReleaseHandle :exec
-- The handle is retired, not recycled: renaming it to a reserved sentinel
-- keeps the global namespace free of impersonation of a deleted account.
UPDATE handles SET handle = $2, reserved = true WHERE id = $1;
