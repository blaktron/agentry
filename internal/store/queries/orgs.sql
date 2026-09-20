-- Orgs, memberships, teams (M1/WG-B).

-- name: CreateOrg :one
-- activated_at is now() where nothing will activate the org later (no
-- admission extension), NULL where one will (agentry#360). domain is the
-- creator's verified email domain, or NULL for none (agentry#363); the
-- unique constraint refuses a second organization at one domain.
INSERT INTO orgs (id, display_name, created_by, activated_at, domain)
VALUES ($1, $2, $3, CASE WHEN sqlc.arg(activated)::boolean THEN now() ELSE NULL END, sqlc.narg(domain)::citext)
RETURNING *;

-- name: ActivateOrg :execrows
UPDATE orgs SET activated_at = now(), updated_at = now() WHERE id = $1 AND activated_at IS NULL;

-- name: GetPendingOrgCreatedBy :one
-- At most one exists per creator (the unique partial index).
SELECT h.handle FROM orgs o JOIN handles h ON h.id = o.id
WHERE o.created_by = $1 AND o.activated_at IS NULL
LIMIT 1;

-- name: LockKey :exec
-- A transaction-scoped advisory lock on a name, for the rules that span
-- more than one table or row and so have no constraint to hold them: a
-- domain across orgs.domain and the verified claims, a person's once-a-day
-- request for access (agentry#363). Released with the transaction.
SELECT pg_advisory_xact_lock(hashtext(sqlc.arg(key)::text));

-- name: LockOrg :exec
-- Serialises the membership changes of one organization inside a
-- transaction (the last-admin guard counts under this lock).
SELECT id FROM orgs WHERE id = $1 FOR UPDATE;

-- name: GetOrgByHandle :one
-- verified_domains is every domain the organization proved control of
-- over DNS (domain_claims.verified_at), oldest first: the T-12 auto-link
-- rule and the invitation door read it (agentry#363).
SELECT o.*, h.handle,
  coalesce((SELECT array_agg(dc.domain::text ORDER BY dc.verified_at)
            FROM domain_claims dc WHERE dc.org_id = o.id AND dc.verified_at IS NOT NULL), '{}')::text[] AS verified_domains
FROM orgs o JOIN handles h ON h.id = o.id WHERE h.handle = $1 AND h.kind = 'org';

-- name: GetOrgByID :one
SELECT o.*, h.handle,
  coalesce((SELECT array_agg(dc.domain::text ORDER BY dc.verified_at)
            FROM domain_claims dc WHERE dc.org_id = o.id AND dc.verified_at IS NOT NULL), '{}')::text[] AS verified_domains
FROM orgs o JOIN handles h ON h.id = o.id WHERE o.id = $1;

-- name: GetOrgByDomain :one
-- The organization a domain belongs to: recorded at its creation, or
-- verified over DNS by it. One organization per domain (D21, D26) spans
-- both facts, so a creation at a DNS-verified domain and a verification
-- of another organization's creation domain are both refused by the API
-- against this lookup. A decommissioned organization has released its
-- domain (both columns are cleared by the erasure), so it never matches.
SELECT o.*, h.handle
FROM orgs o JOIN handles h ON h.id = o.id
WHERE o.domain = sqlc.arg(domain)::citext
   OR EXISTS (SELECT 1 FROM domain_claims dc
              WHERE dc.org_id = o.id AND dc.domain = sqlc.arg(domain)::citext AND dc.verified_at IS NOT NULL)
ORDER BY o.created_at
LIMIT 1;

-- name: GetOrgState :one
-- What the organization's state permits, for the one gate the API, the
-- git door and the membership chokepoint consult (agentry#363).
SELECT state, decommission_at FROM orgs WHERE id = $1;

-- name: DecommissionOrg :execrows
-- Only an active organization enters the hold; a repeat is 0 rows.
UPDATE orgs SET state = 'decommissioning', decommission_at = $2, decommission_reason = $3, updated_at = now()
WHERE id = $1 AND state = 'active';

-- name: SuspendOrg :execrows
UPDATE orgs SET state = 'suspended', decommission_reason = $2, updated_at = now()
WHERE id = $1 AND state = 'active';

-- name: ReinstateOrg :execrows
-- Back to active from a suspension or from the decommission hold; the
-- erasure that already ran cannot be undone, so decommissioned stays.
UPDATE orgs SET state = 'active', decommission_at = NULL, decommission_reason = NULL, updated_at = now()
WHERE id = $1 AND state IN ('suspended','decommissioning');

-- name: ListOrgsDueForErasure :many
SELECT o.id, h.handle FROM orgs o JOIN handles h ON h.id = o.id
WHERE o.state = 'decommissioning' AND o.decommission_at <= now()
ORDER BY o.decommission_at;

-- name: GetOrgWhereUserIsLastAdmin :one
-- The erasure guard (D14): an account that is the only active admin of an
-- organization that still exists cannot be erased until another admin is
-- in place. Counts the way CountOrgAdmins does.
SELECT h.handle FROM memberships m
JOIN orgs o ON o.id = m.org_id
JOIN handles h ON h.id = m.org_id
WHERE m.user_id = $1 AND m.role = 'admin' AND m.state = 'active'
  AND o.state IN ('active','suspended','decommissioning')
  AND (SELECT count(*) FROM memberships m2 JOIN users u ON u.id = m2.user_id
       WHERE m2.org_id = m.org_id AND m2.role = 'admin' AND m2.state = 'active' AND u.state = 'active') <= 1
ORDER BY h.handle
LIMIT 1;

-- name: ListOrgAdminsForMail :many
-- The organization's active admins with what a mail to them needs; whether
-- each may be written to — a verified address, the orgInvites preference —
-- is notify.AllowsEmail's decision, not this query's (agentry#363).
SELECT u.id, u.email, h.handle
FROM memberships m
JOIN users u ON u.id = m.user_id
JOIN handles h ON h.id = u.id
WHERE m.org_id = $1 AND m.role = 'admin' AND m.state = 'active' AND u.state = 'active'
ORDER BY h.handle;

-- name: DeleteUserMemberships :execrows
-- An erased account holds no seat anywhere (agentry#363): its rows go
-- with it, after the last-admin guard has passed.
DELETE FROM memberships WHERE user_id = $1;

-- name: UpdateOrgDisplayName :one
UPDATE orgs SET display_name = $2, updated_at = now() WHERE id = $1 RETURNING id;

-- name: UpsertMembership :execrows
-- Role changes only, and it cannot create: every door that makes someone a
-- member goes through registry.ActivateMember (agentry#361), which counts
-- seats. An UPDATE with no row is 0 rows, so a caller that reaches here
-- with nobody to change writes nothing rather than admitting them.
UPDATE memberships SET role = $3, updated_at = now()
WHERE org_id = $1 AND user_id = $2;

-- name: CreateFounderMembership :exec
-- The one membership written without a seat check: the person creating the
-- organization, who is its first admin. There is nothing yet to count and
-- nobody yet to approve them.
INSERT INTO memberships (org_id, user_id, role, state)
VALUES ($1, $2, $3, 'active');

-- name: UpsertPendingMembership :execrows
-- The SCIM and fold-in doors: a membership that holds no seat and confers
-- nothing until an admin approves it. An existing membership is left alone
-- — approving twice, or provisioning someone who is already active, must
-- not push them back to pending. Reports 1 when this call wrote the row,
-- which is how the fold-in knows to audit and count it once (agentry#364).
INSERT INTO memberships (org_id, user_id, role, via_scim, via_domain, state)
VALUES ($1, $2, $3, $4, $5, 'pending')
ON CONFLICT (org_id, user_id) DO NOTHING;

-- name: ActivateMembership :execrows
-- The one write that makes a membership active. Returns 0 rows when it was
-- already active, so the caller can tell a first activation from a repeat
-- and emit member.added exactly once. The door flags of a pending row are
-- kept: the console still says how the person arrived.
INSERT INTO memberships AS m (org_id, user_id, role, via_scim, via_domain, state)
VALUES ($1, $2, $3, $4, $5, 'active')
ON CONFLICT (org_id, user_id) DO UPDATE
  SET role = EXCLUDED.role, state = 'active', updated_at = now()
  WHERE m.state <> 'active';

-- name: GetMembership :one
SELECT * FROM memberships WHERE org_id = $1 AND user_id = $2;

-- name: DeleteMembership :execrows
DELETE FROM memberships WHERE org_id = $1 AND user_id = $2;

-- name: ListOrgMembers :many
SELECT m.role, m.via_scim, m.via_domain, m.state, h.handle, u.display_name
FROM memberships m
JOIN users u ON u.id = m.user_id
JOIN handles h ON h.id = u.id
WHERE m.org_id = $1
ORDER BY h.handle;

-- name: CountOrgAdmins :one
-- Only an admin who can still act counts: an erased account keeps its
-- membership row (and the last-owner guard this replaces counted it), and a
-- pending admin holds nothing until they are approved (agentry#361).
SELECT count(*) FROM memberships m JOIN users u ON u.id = m.user_id
WHERE m.org_id = $1 AND m.role = 'admin' AND m.state = 'active' AND u.state = 'active';

-- name: CountOrgSeats :one
-- A seat is every active membership plus every open invitation (plan §4
-- "Seats"); pending members hold none and are reported so an admin can see
-- who is waiting.
SELECT
  (SELECT count(*) FROM memberships am WHERE am.org_id = $1 AND am.state = 'active')::bigint AS used,
  (SELECT count(*) FROM org_invitations oi WHERE oi.org_id = $1 AND oi.accepted_at IS NULL AND oi.expires_at > now())::bigint AS invited,
  (SELECT count(*) FROM memberships pm WHERE pm.org_id = $1 AND pm.state = 'pending')::bigint AS pending;

-- name: CountActiveMembershipsElsewhere :one
-- One organization per person (D26): an invitation or an approval for
-- someone already active elsewhere is refused.
SELECT count(*) FROM memberships m WHERE m.user_id = $1 AND m.state = 'active' AND m.org_id <> $2;

-- name: CountActiveMemberships :one
-- The same rule at the creation door (agentry#370): a person who is an
-- active member anywhere founds nothing until they leave.
SELECT count(*) FROM memberships m WHERE m.user_id = $1 AND m.state = 'active';

-- name: ListUserMemberships :many
-- The caller's org roles, for the principal every request is authorized
-- against. ACTIVE memberships only (agentry#361): a pending member —
-- provisioned by the IdP, or folded in from the domain — is waiting for an
-- admin and holds nothing of the organization until then, so their row
-- must not reach auth.Check as a role.
SELECT m.org_id, m.role FROM memberships m WHERE m.user_id = $1 AND m.state = 'active';

-- name: ListUserMembershipsWithHandles :many
SELECT m.org_id, m.role, m.state, h.handle
FROM memberships m
JOIN handles h ON h.id = m.org_id
WHERE m.user_id = $1
ORDER BY h.handle;

-- name: CountMemberships :one
-- Every membership row a person holds, pending included: the fold-in
-- (agentry#364) fires only for a member of no organization, and a person
-- already waiting somewhere is not folded in elsewhere.
SELECT count(*) FROM memberships m WHERE m.user_id = $1;

-- name: GetUserPendingOrg :one
-- The organization a person is waiting to be approved by, for GET /user's
-- pendingOrg (agentry#364): every page and client says it until an admin
-- approves or declines. Active organizations only: a suspended one is
-- absent to everyone, its pending members included, and one in its hold
-- can approve nobody, so a notice that its admins have been asked would
-- promise what cannot happen.
SELECT h.handle, o.display_name, m.via_scim, m.via_domain
FROM memberships m
JOIN orgs o ON o.id = m.org_id
JOIN handles h ON h.id = o.id
WHERE m.user_id = $1 AND m.state = 'pending' AND o.state = 'active'
ORDER BY m.created_at
LIMIT 1;

-- name: ListUsersAtDomainForFoldIn :many
-- The accounts the fold-in sweep considers when an organization gains a
-- domain (agentry#364): a verified address at the domain — the part after
-- the last @, a trailing dot dropped, the way maildomains.Of reads it —
-- an active account, a member of nothing, and not declined by this
-- organization before. The sign-in step applies the same rules one
-- person at a time (registry.writePending).
SELECT u.id, h.handle, u.email
FROM users u
JOIN handles h ON h.id = u.id
WHERE u.email_verified_at IS NOT NULL
  AND u.state = 'active'
  AND lower(rtrim(substring(u.email::text from '[^@]*$'), '.')) = lower(sqlc.arg(domain)::text)
  AND NOT EXISTS (SELECT 1 FROM memberships m WHERE m.user_id = u.id)
  AND NOT EXISTS (SELECT 1 FROM fold_in_declines d WHERE d.org_id = sqlc.arg(org_id) AND d.user_id = u.id)
ORDER BY h.handle;

-- name: GetFoldInDecline :one
SELECT * FROM fold_in_declines WHERE org_id = $1 AND user_id = $2;

-- name: UpsertFoldInDecline :exec
-- A decline is remembered for that person at that organization (D25).
INSERT INTO fold_in_declines (org_id, user_id, declined_by)
VALUES ($1, $2, $3)
ON CONFLICT (org_id, user_id) DO UPDATE SET declined_by = EXCLUDED.declined_by, declined_at = now();

-- name: DeleteFoldInDecline :execrows
-- An admin's invitation or approval supersedes the decline: the memory
-- goes when the membership is activated.
DELETE FROM fold_in_declines WHERE org_id = $1 AND user_id = $2;

-- name: ListOrgsWithUnnotifiedPending :many
-- The organizations the daily digest has something to say to
-- (agentry#364), or the one named: active ones with a pending member no
-- admin has been mailed about. A suspended or held organization gets no
-- digest; its admins can add nobody.
SELECT o.id, h.handle, o.display_name
FROM orgs o
JOIN handles h ON h.id = o.id
WHERE o.state = 'active'
  AND (sqlc.narg(org_id)::uuid IS NULL OR o.id = sqlc.narg(org_id)::uuid)
  AND EXISTS (SELECT 1 FROM memberships m WHERE m.org_id = o.id AND m.state = 'pending' AND m.admins_notified_at IS NULL)
ORDER BY h.handle;

-- name: ListPendingMembersUnnotified :many
-- One organization's pending members no admin has been mailed about yet,
-- whichever door they came through. Read under the organization's row
-- lock by the digest, so two runs at once cannot both name them.
SELECT m.user_id, uh.handle, u.email, m.via_scim, m.via_domain, m.created_at
FROM memberships m
JOIN users u ON u.id = m.user_id
JOIN handles uh ON uh.id = u.id
WHERE m.org_id = $1 AND m.state = 'pending' AND m.admins_notified_at IS NULL
ORDER BY m.created_at;

-- name: MarkPendingMembersNotified :execrows
UPDATE memberships SET admins_notified_at = now()
WHERE org_id = $1 AND user_id = ANY(sqlc.arg(user_ids)::uuid[]) AND state = 'pending' AND admins_notified_at IS NULL;

-- name: CreateInvitation :one
INSERT INTO org_invitations (id, org_id, email, role, token_sha256, invited_by, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: GetInvitationByToken :one
-- Whether the invited address is at one of the organization's DNS-verified
-- domains travels with the invitation: it decides both whether the offer
-- was mailed and whether accepting confirms the address (agentry#361).
SELECT i.*, h.handle AS org_handle, o.display_name AS org_display_name,
  EXISTS (SELECT 1 FROM domain_claims dc
          WHERE dc.org_id = i.org_id AND dc.verified_at IS NOT NULL
            AND dc.domain = split_part(i.email::text, '@', 2)::citext) AS at_verified_domain
FROM org_invitations i
JOIN orgs o ON o.id = i.org_id
JOIN handles h ON h.id = i.org_id
WHERE i.token_sha256 = $1;

-- name: ListOpenInvitations :many
SELECT i.*, h.handle AS invited_by_handle
FROM org_invitations i
LEFT JOIN handles h ON h.id = i.invited_by
WHERE i.org_id = $1 AND i.accepted_at IS NULL
ORDER BY i.created_at DESC;

-- name: DeleteInvitation :execrows
DELETE FROM org_invitations WHERE org_id = $1 AND id = $2 AND accepted_at IS NULL;

-- name: DeleteUnacceptedInvitationsFor :execrows
-- Re-inviting the same address supersedes the standing invitation, whose
-- token stops working; the unique index makes this the only way to do it.
DELETE FROM org_invitations WHERE org_id = $1 AND email = $2 AND accepted_at IS NULL;

-- name: MarkInvitationAccepted :execrows
-- Single use: the guard on accepted_at is what makes a second accept with
-- the same token a no-op rather than a second membership.
UPDATE org_invitations SET accepted_at = now(), accepted_by = $3
WHERE id = $1 AND org_id = $2 AND accepted_at IS NULL;

-- name: CreateTeam :one
INSERT INTO teams (id, org_id, slug) VALUES ($1, $2, $3) RETURNING *;

-- name: GetTeam :one
SELECT * FROM teams WHERE org_id = $1 AND slug = $2;

-- name: DeleteTeam :execrows
DELETE FROM teams WHERE org_id = $1 AND slug = $2;

-- name: ListTeams :many
SELECT * FROM teams WHERE org_id = $1 ORDER BY slug;

-- name: AddTeamMember :exec
INSERT INTO team_members (team_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING;

-- name: RemoveTeamMember :execrows
DELETE FROM team_members WHERE team_id = $1 AND user_id = $2;

-- name: ListTeamMembers :many
SELECT h.handle, u.display_name
FROM team_members tm
JOIN users u ON u.id = tm.user_id
JOIN handles h ON h.id = u.id
WHERE tm.team_id = $1
ORDER BY h.handle;

-- name: ListUserTeamIDs :many
SELECT team_id FROM team_members WHERE user_id = $1;

-- name: SetOrgLogo :one
-- Records the logo now served for the organization and returns the key
-- it replaces (NULL for none), so the caller can remove the old object
-- once the row points at the new one (agentry#367). The previous value
-- is read under the row lock in the same statement — a departure from
-- this file's LockOrg-then-write shape, taken so the swap and what it
-- replaced are one round trip and cannot disagree.
WITH old AS (SELECT logo_object_key FROM orgs WHERE id = $1 FOR UPDATE)
UPDATE orgs SET logo_object_key = $2, updated_at = now() FROM old WHERE orgs.id = $1
RETURNING old.logo_object_key AS previous_key;

-- name: ClearOrgLogo :one
-- Removes the organization's logo and returns the key that was served,
-- for the caller to delete the object (agentry#367); the same one-statement
-- shape as SetOrgLogo. No row when there was no logo.
WITH old AS (SELECT logo_object_key FROM orgs WHERE id = $1 AND logo_object_key IS NOT NULL FOR UPDATE)
UPDATE orgs SET logo_object_key = NULL, updated_at = now() FROM old WHERE orgs.id = $1
RETURNING old.logo_object_key AS previous_key;
