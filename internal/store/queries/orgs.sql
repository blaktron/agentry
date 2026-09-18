-- Orgs, memberships, teams (M1/WG-B).

-- name: CreateOrg :one
-- activated_at is now() where nothing will activate the org later (no
-- admission extension), NULL where one will (agentry#360).
INSERT INTO orgs (id, display_name, created_by, activated_at)
VALUES ($1, $2, $3, CASE WHEN sqlc.arg(activated)::boolean THEN now() ELSE NULL END)
RETURNING *;

-- name: ActivateOrg :execrows
UPDATE orgs SET activated_at = now(), updated_at = now() WHERE id = $1 AND activated_at IS NULL;

-- name: GetPendingOrgCreatedBy :one
-- At most one exists per creator (the unique partial index).
SELECT h.handle FROM orgs o JOIN handles h ON h.id = o.id
WHERE o.created_by = $1 AND o.activated_at IS NULL
LIMIT 1;

-- name: LockOrg :exec
-- Serialises the membership changes of one organization inside a
-- transaction (the last-admin guard counts under this lock).
SELECT id FROM orgs WHERE id = $1 FOR UPDATE;

-- name: GetOrgByHandle :one
SELECT o.*, h.handle FROM orgs o JOIN handles h ON h.id = o.id WHERE h.handle = $1 AND h.kind = 'org';

-- name: GetOrgByID :one
SELECT o.*, h.handle FROM orgs o JOIN handles h ON h.id = o.id WHERE o.id = $1;

-- name: UpdateOrgDisplayName :one
UPDATE orgs SET display_name = $2, updated_at = now() WHERE id = $1 RETURNING id;

-- name: UpsertMembership :exec
-- Role changes only: every door that *creates* an active membership goes
-- through registry.ActivateMember (agentry#361), which counts seats.
INSERT INTO memberships (org_id, user_id, role, via_scim)
VALUES ($1, $2, $3, $4)
ON CONFLICT (org_id, user_id) DO UPDATE SET role = EXCLUDED.role, updated_at = now();

-- name: UpsertPendingMembership :exec
-- The SCIM and fold-in doors: a membership that holds no seat and confers
-- nothing until an admin approves it. An existing membership is left alone
-- — approving twice, or provisioning someone who is already active, must
-- not push them back to pending.
INSERT INTO memberships (org_id, user_id, role, via_scim, state)
VALUES ($1, $2, $3, $4, 'pending')
ON CONFLICT (org_id, user_id) DO NOTHING;

-- name: ActivateMembership :execrows
-- The one write that makes a membership active. Returns 0 rows when it was
-- already active, so the caller can tell a first activation from a repeat
-- and emit member.added exactly once.
INSERT INTO memberships AS m (org_id, user_id, role, via_scim, state)
VALUES ($1, $2, $3, $4, 'active')
ON CONFLICT (org_id, user_id) DO UPDATE
  SET role = EXCLUDED.role, state = 'active', updated_at = now()
  WHERE m.state <> 'active';

-- name: GetMembership :one
SELECT * FROM memberships WHERE org_id = $1 AND user_id = $2;

-- name: DeleteMembership :execrows
DELETE FROM memberships WHERE org_id = $1 AND user_id = $2;

-- name: ListOrgMembers :many
SELECT m.role, m.via_scim, m.state, h.handle, u.display_name
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

-- name: ListUserMemberships :many
SELECT m.org_id, m.role FROM memberships m WHERE m.user_id = $1;

-- name: ListUserMembershipsWithHandles :many
SELECT m.org_id, m.role, m.state, h.handle
FROM memberships m
JOIN handles h ON h.id = m.org_id
WHERE m.user_id = $1
ORDER BY h.handle;

-- name: CreateInvitation :one
INSERT INTO org_invitations (id, org_id, email, role, token_sha256, invited_by, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: GetInvitationByToken :one
SELECT i.*, h.handle AS org_handle, o.display_name AS org_display_name
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
