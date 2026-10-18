-- Users, handles, and email verification.

-- name: CreateHandle :exec
INSERT INTO handles (id, handle, kind) VALUES ($1, $2, $3);

-- name: GetHandle :one
SELECT * FROM handles WHERE handle = $1;

-- name: CreateUser :one
INSERT INTO users (id, email, display_name)
VALUES ($1, $2, $3)
RETURNING *;

-- name: GetUserByID :one
SELECT u.*, h.handle FROM users u JOIN handles h ON h.id = u.id WHERE u.id = $1;

-- name: GetUserByEmail :one
SELECT u.*, h.handle FROM users u JOIN handles h ON h.id = u.id WHERE u.email = $1;

-- name: GetUserByHandle :one
SELECT u.*, h.handle FROM users u JOIN handles h ON h.id = u.id WHERE h.handle = $1 AND h.kind = 'user';

-- name: UpdateUserDisplayName :one
UPDATE users SET display_name = $2, updated_at = now() WHERE id = $1 RETURNING id;

-- name: ListUserDirectoryLinks :many
-- The directory accounts the account is linked to by sign-ins through the
-- sign-in provider whose id is provider_id, oldest first: each one's subject
-- with "<provider_id>:" stripped (the uid the directory reports for it), and
-- the directory's own id for it where one was recorded (0 otherwise).
-- Erasure takes them all.
SELECT substring(i.subject from char_length(sqlc.arg(provider_id)::text) + 2)::text AS directory_subject,
       COALESCE(i.directory_account_id, 0)::bigint AS directory_account_id
FROM identities i
WHERE i.user_id = sqlc.arg(user_id) AND i.provider_kind = 'social'
  AND i.sso_connection_id IS NULL
  AND i.subject LIKE sqlc.arg(provider_id)::text || ':%'
ORDER BY i.created_at, i.id;

-- name: ListPlatformStaff :many
-- Every account that is platform staff and active, with its handle and its
-- verified address, lower-cased: what an extension mirrors staff from.
SELECT u.id, h.handle, lower(u.email)::text AS email
FROM users u
JOIN handles h ON h.id = u.id
WHERE u.platform_staff AND u.state = 'active' AND u.email_verified_at IS NOT NULL
ORDER BY h.handle;

-- name: ListUserSignInSubjects :many
-- The subjects the account signs in with at individual providers
-- ("<provider>:<sub>"), oldest first.
SELECT i.subject FROM identities i
WHERE i.user_id = $1 AND i.provider_kind = 'social' AND i.sso_connection_id IS NULL
ORDER BY i.created_at, i.id;

-- name: ListStaffOrgMembersNotStaff :many
-- Active members of the staff organization who are not platform staff: an
-- address outside its domain or unverified, or an account that is not active.
-- Reported at start-up, never removed.
SELECT h.handle FROM memberships m
JOIN users u ON u.id = m.user_id
JOIN handles h ON h.id = u.id
WHERE m.org_id = $1 AND m.state = 'active' AND NOT u.platform_staff
ORDER BY h.handle;

-- name: ListStaffSyncCandidates :many
-- The accounts whose platform_staff the staff rule could change: every
-- account flagged today, and every active member of the staff organization.
-- The start-up resync recomputes exactly these.
SELECT id FROM users
WHERE platform_staff
   OR id IN (SELECT m.user_id FROM memberships m WHERE m.org_id = $1 AND m.state = 'active')
ORDER BY id;

-- name: SetUserPlatformStaff :exec
-- The staff rule decides platform staff (registry.SyncStaffIn).
UPDATE users SET platform_staff = $2, updated_at = now() WHERE id = $1;

-- name: SetUserIdPMFA :exec
-- The directory asserted a second factor at this sign-in.
UPDATE users SET idp_mfa_at = now(), updated_at = now() WHERE id = $1;

-- name: SetUserCookieAck :exec
-- Write-once by intent: re-acknowledging just refreshes the timestamp.
UPDATE users SET cookie_ack_at = now(), updated_at = now() WHERE id = $1;

-- name: MarkEmailVerified :exec
UPDATE users SET email_verified_at = now(), updated_at = now() WHERE id = $1;

-- name: CreateEmailVerification :exec
INSERT INTO email_verifications (token_sha256, user_id, expires_at) VALUES ($1, $2, $3);

-- name: LockUserRow :one
-- Serializes the activation mail per account: the five-minute limit is read
-- and the new link written under this lock, so two replicas answering at once
-- send one mail, not two.
SELECT id FROM users WHERE id = $1 FOR UPDATE;

-- name: LatestEmailVerificationAt :one
-- When the account's newest verification link was made, or the epoch when it
-- has none (for the five-minute limit).
SELECT COALESCE(max(created_at), 'epoch'::timestamptz)::timestamptz AS sent_at
FROM email_verifications WHERE user_id = $1;

-- name: CountEmailVerificationsSince :one
-- How many links the account was sent since a moment, and the oldest of them
-- (for the daily cap).
SELECT count(*)::bigint AS sent,
       COALESCE(min(created_at), now())::timestamptz AS oldest
FROM email_verifications WHERE user_id = $1 AND created_at > $2;

-- name: DeleteEmailVerificationsForUser :exec
-- An erased account's links go with it: one followed afterwards would confirm
-- an address nobody holds any more.
DELETE FROM email_verifications WHERE user_id = $1;

-- name: ConsumeEmailVerification :one
UPDATE email_verifications
SET consumed_at = now()
WHERE token_sha256 = $1 AND consumed_at IS NULL AND expires_at > now()
RETURNING user_id;

-- name: CountPublishedVersionsByUser :one
-- Published public versions under a user's PERSONAL namespace (the deletion
-- chooser needs to know whether consumers depend on them).
SELECT count(*) FROM agent_versions av
JOIN agents a ON a.id = av.agent_id
JOIN handles h ON h.id = a.namespace_id
WHERE h.id = $1 AND h.kind = 'user' AND a.visibility = 'public' AND av.status = 'published';

-- name: ListPersonalNamespaceAgents :many
SELECT a.id, a.name, a.visibility, a.latest_published_version_id, a.retired_at, a.deleted_at
FROM agents a JOIN handles h ON h.id = a.namespace_id
WHERE h.id = $1 AND h.kind = 'user';

-- name: PseudonymizeUser :exec
-- GDPR erasure: PII is purged, the row survives so audit events and immutable
-- published content keep a stable (now opaque) actor id. The tombstone keeps
-- only a salted hash of the email for abuse-recurrence detection — never the
-- address itself.
UPDATE users SET
  email = $2,
  email_verified_at = NULL,
  display_name = 'deleted user',
  state = 'deleted',
  deleted_tombstone = $3,
  updated_at = now()
WHERE id = $1;

-- name: ReleaseHandle :exec
-- The handle is retired, not recycled: renaming it to a reserved sentinel
-- keeps the global namespace free of impersonation of a deleted account.
UPDATE handles SET handle = $2, reserved = true WHERE id = $1;
