-- The erasure that ends an organization's decommission hold. Each statement
-- removes one kind of thing the organization owned; the job in
-- internal/api/handlers_org_lifecycle.go runs them in one transaction under
-- the organization's row lock, which also flips the row to decommissioned and
-- releases the handle — the point of no return, taken first — and then yanks
-- the versions and deletes the blobs and repositories, which it can resume if
-- interrupted. Version rows are immutable and are never deleted: the agents
-- are retired private under the released handle instead, the way an erased
-- person's are.

-- name: ListOrgVersionsForErasure :many
SELECT av.id, av.agent_id, av.status, av.archive_key
FROM agent_versions av JOIN agents a ON a.id = av.agent_id
WHERE a.namespace_id = $1
ORDER BY av.created_at;

-- name: ListDecommissionedOrgsWithLiveVersions :many
-- Organizations already flipped to decommissioned whose releases are not
-- yet all terminal: the sweep resumes their second phase (the yanks, the
-- blobs, the repositories) after an interruption.
SELECT DISTINCT o.id, h.handle FROM orgs o
JOIN handles h ON h.id = o.id
JOIN agents a ON a.namespace_id = o.id
JOIN agent_versions av ON av.agent_id = a.id
WHERE o.state = 'decommissioned'
  AND av.status IN ('published','quarantined','needs_review','submitted','scanning');

-- name: ListOrgAgentsForErasure :many
SELECT a.id, a.name, a.repo_id FROM agents a WHERE a.namespace_id = $1 ORDER BY a.name;

-- name: ListOrgAuditExportKeys :many
SELECT object_key FROM audit_exports WHERE org_id = $1 AND object_key IS NOT NULL;

-- name: DeleteOrgInvitations :execrows
DELETE FROM org_invitations WHERE org_id = $1;

-- name: DeleteOrgMemberships :execrows
DELETE FROM memberships WHERE org_id = $1;

-- name: DeleteOrgFoldInDeclines :execrows
-- An erased organization remembers no decline; the rows would go with the
-- organization's row if it were deleted, and it is not.
DELETE FROM fold_in_declines WHERE org_id = $1;

-- name: DeleteOrgTeams :execrows
-- team_members and agent_team_grants cascade.
DELETE FROM teams WHERE org_id = $1;

-- name: DeleteOrgWebhookEndpoints :execrows
-- Deliveries cascade with their endpoint.
DELETE FROM webhook_endpoints WHERE org_id = $1;

-- name: DeleteOrgSSOIdentities :execrows
DELETE FROM identities WHERE sso_connection_id IN (SELECT id FROM sso_connections WHERE org_id = $1);

-- name: DeleteOrgSSOConnections :execrows
DELETE FROM sso_connections WHERE org_id = $1;

-- name: DeleteOrgSCIMTokens :execrows
DELETE FROM scim_tokens WHERE org_id = $1;

-- name: DeleteOrgDomainClaims :execrows
DELETE FROM domain_claims WHERE org_id = $1;

-- name: DeleteOrgPolicy :execrows
DELETE FROM policies WHERE org_id = $1;

-- name: DeleteOrgAuditExports :execrows
DELETE FROM audit_exports WHERE org_id = $1;

-- name: DeleteOrgAgentUserGrants :execrows
DELETE FROM agent_user_grants WHERE agent_id IN (SELECT id FROM agents WHERE namespace_id = $1);

-- name: DeleteOrgAgentStars :execrows
DELETE FROM stars WHERE agent_id IN (SELECT id FROM agents WHERE namespace_id = $1);

-- name: RevokeOrgBoundPATs :execrows
UPDATE pats SET revoked_at = now() WHERE org_id = $1 AND revoked_at IS NULL;

-- name: RetireOrgAgents :execrows
-- Private, nameless and pointing at no release: with no member left to
-- derive a role and every grant gone, nobody can read them, and the
-- retired handle keeps their path from ever resolving again.
UPDATE agents SET visibility = 'private', summary = '', readme_text = '',
  latest_published_version_id = NULL, updated_at = now()
WHERE namespace_id = $1;

-- name: ScrubDecommissionedOrg :execrows
-- The row stays for the records that point at its id; everything that named
-- the organization, or its founder, goes. The domain is freed here; the
-- handle is released by ReleaseHandle in the same transaction; and created_by
-- is cleared so an organization created awaiting activation (the hosted
-- product's pending state) stops counting as the founder's pending one once
-- it is erased — the unique partial index on (created_by) WHERE activated_at
-- IS NULL would otherwise refuse them a fresh start forever.
UPDATE orgs SET state = 'decommissioned', display_name = 'decommissioned organization',
  domain = NULL, sso_required = false, created_by = NULL, updated_at = now()
WHERE id = $1 AND state = 'decommissioning';
