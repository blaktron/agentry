-- Orgs, memberships, teams (M1/WG-B).

-- name: CreateOrg :one
INSERT INTO orgs (id, display_name) VALUES ($1, $2) RETURNING *;

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

-- name: CountOrgOwners :one
SELECT count(*) FROM memberships WHERE org_id = $1 AND role = 'owner';

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
