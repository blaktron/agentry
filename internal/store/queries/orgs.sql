-- Orgs, memberships, teams (M1/WG-B).

-- name: CreateOrg :one
-- activated_at is now() where nothing will activate the org later (no
-- admission extension), NULL where one will (agentry#360).
INSERT INTO orgs (id, display_name, created_by, activated_at)
VALUES ($1, $2, $3, CASE WHEN sqlc.arg(activated)::boolean THEN now() ELSE NULL END)
RETURNING *;

-- name: ActivateOrg :execrows
UPDATE orgs SET activated_at = now(), updated_at = now() WHERE id = $1 AND activated_at IS NULL;

-- name: ListPendingOrgsCreatedBy :many
SELECT h.handle FROM orgs o JOIN handles h ON h.id = o.id
WHERE o.created_by = $1 AND o.activated_at IS NULL AND o.state = 'active'
ORDER BY o.created_at;

-- name: GetOrgByHandle :one
SELECT o.*, h.handle FROM orgs o JOIN handles h ON h.id = o.id WHERE h.handle = $1 AND h.kind = 'org';

-- name: GetOrgByID :one
SELECT o.*, h.handle FROM orgs o JOIN handles h ON h.id = o.id WHERE o.id = $1;

-- name: UpdateOrgDisplayName :one
UPDATE orgs SET display_name = $2, updated_at = now() WHERE id = $1 RETURNING id;

-- name: UpsertMembership :exec
INSERT INTO memberships (org_id, user_id, role, via_scim)
VALUES ($1, $2, $3, $4)
ON CONFLICT (org_id, user_id) DO UPDATE SET role = EXCLUDED.role, updated_at = now();

-- name: GetMembership :one
SELECT * FROM memberships WHERE org_id = $1 AND user_id = $2;

-- name: DeleteMembership :execrows
DELETE FROM memberships WHERE org_id = $1 AND user_id = $2;

-- name: ListOrgMembers :many
SELECT m.role, m.via_scim, h.handle, u.display_name
FROM memberships m
JOIN users u ON u.id = m.user_id
JOIN handles h ON h.id = u.id
WHERE m.org_id = $1
ORDER BY h.handle;

-- name: CountOrgAdmins :one
-- Only an admin who can still act counts: an erased account keeps its
-- membership row, and the last-owner guard this replaces counted it.
SELECT count(*) FROM memberships m JOIN users u ON u.id = m.user_id
WHERE m.org_id = $1 AND m.role = 'admin' AND u.state = 'active';

-- name: ListUserMemberships :many
SELECT m.org_id, m.role FROM memberships m WHERE m.user_id = $1;

-- name: ListUserMembershipsWithHandles :many
SELECT m.org_id, m.role, h.handle
FROM memberships m
JOIN handles h ON h.id = m.org_id
WHERE m.user_id = $1
ORDER BY h.handle;

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
