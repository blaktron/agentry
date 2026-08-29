-- Enterprise features (M6/WG-J): SSO connections, identities, SCIM tokens and
-- SCIM data-plane, webhooks, domain claims, audit exports, enforced-SSO helpers.

-- ============================ SSO connections ============================

-- name: UpsertSSOConnection :one
INSERT INTO sso_connections (id, org_id, kind, config, enabled)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (org_id, kind)
  DO UPDATE SET config = EXCLUDED.config, enabled = EXCLUDED.enabled
RETURNING *;

-- name: GetSSOConnection :one
SELECT * FROM sso_connections WHERE org_id = $1 AND kind = $2;

-- name: GetEnabledSSOConnection :one
SELECT * FROM sso_connections WHERE org_id = $1 AND kind = $2 AND enabled = true;

-- name: ListSSOConnections :many
SELECT * FROM sso_connections WHERE org_id = $1 ORDER BY kind;

-- name: DeleteSSOConnection :execrows
DELETE FROM sso_connections WHERE org_id = $1 AND kind = $2;

-- ============================ Identities (JIT) ============================

-- name: GetIdentityBySubject :one
SELECT * FROM identities WHERE sso_connection_id = $1 AND subject = $2;

-- name: CreateIdentity :one
INSERT INTO identities (id, user_id, provider_kind, sso_connection_id, subject)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetSocialIdentity :one
-- Social login (§12.1) has no sso_connection: the subject is namespaced by
-- provider ("google:1234") and unique on its own.
SELECT * FROM identities
WHERE sso_connection_id IS NULL AND provider_kind = 'social' AND subject = $1;

-- ============================ Enforced SSO ============================

-- name: SetOrgSSORequired :exec
UPDATE orgs SET sso_required = $2, updated_at = now() WHERE id = $1;

-- name: TagSessionSSO :exec
-- Merge a fresh {org_id: refreshed_at} entry into the session's sso_tags.
UPDATE sessions
SET sso_tags = sso_tags || jsonb_build_object($2::text, $3::text)
WHERE id = $1;

-- ============================ SCIM tokens ============================

-- name: CreateSCIMToken :one
INSERT INTO scim_tokens (id, org_id, token_sha256, expires_at)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: GetSCIMTokenByHash :one
SELECT * FROM scim_tokens
WHERE token_sha256 = $1 AND revoked_at IS NULL
  AND (expires_at IS NULL OR expires_at > now());

-- name: ListSCIMTokens :many
SELECT * FROM scim_tokens WHERE org_id = $1 AND revoked_at IS NULL ORDER BY created_at DESC;

-- name: RevokeSCIMToken :execrows
UPDATE scim_tokens SET revoked_at = now() WHERE id = $1 AND org_id = $2 AND revoked_at IS NULL;

-- ============================ SCIM users (data plane) ============================

-- name: ListScimUsers :many
SELECT u.id, u.email, u.display_name, u.state, h.handle, m.role, m.via_scim
FROM memberships m
JOIN users u ON u.id = m.user_id
JOIN handles h ON h.id = u.id
WHERE m.org_id = $1
ORDER BY u.email;

-- name: GetScimUser :one
SELECT u.id, u.email, u.display_name, u.state, h.handle, m.role, m.via_scim
FROM memberships m
JOIN users u ON u.id = m.user_id
JOIN handles h ON h.id = u.id
WHERE m.org_id = $1 AND u.id = $2;

-- name: FindOrgMemberByEmail :one
SELECT u.id, u.email, u.display_name, u.state, h.handle, m.role, m.via_scim
FROM memberships m
JOIN users u ON u.id = m.user_id
JOIN handles h ON h.id = u.id
WHERE m.org_id = $1 AND u.email = $2;

-- ============================ SCIM groups (teams) ============================

-- name: CreateTeamWithScim :one
INSERT INTO teams (id, org_id, slug, scim_group_id) VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: GetTeamByID :one
SELECT * FROM teams WHERE id = $1 AND org_id = $2;

-- name: GetTeamByScimGroupID :one
SELECT * FROM teams WHERE org_id = $1 AND scim_group_id = $2;

-- name: SetTeamScimGroupID :exec
UPDATE teams SET scim_group_id = $2 WHERE id = $1;

-- name: ListTeamMemberIDs :many
SELECT user_id FROM team_members WHERE team_id = $1;

-- name: ClearTeamMembers :exec
DELETE FROM team_members WHERE team_id = $1;

-- GetAgentOwnerOrg returns the owning org id when an agent's namespace is an
-- org (webhook fan-out is org-scoped; personal-namespace agents return no row).
-- name: GetAgentOwnerOrg :one
SELECT a.namespace_id AS org_id
FROM agents a JOIN handles h ON h.id = a.namespace_id
WHERE a.id = $1 AND h.kind = 'org';

-- ============================ Webhooks ============================

-- name: CreateWebhookEndpoint :one
INSERT INTO webhook_endpoints (id, org_id, url, secret_enc, events, active)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: GetWebhookEndpoint :one
SELECT * FROM webhook_endpoints WHERE id = $1 AND org_id = $2;

-- name: ListWebhookEndpoints :many
SELECT * FROM webhook_endpoints WHERE org_id = $1 ORDER BY created_at DESC;

-- name: ListActiveWebhookEndpointsForEvent :many
SELECT * FROM webhook_endpoints
WHERE org_id = $1 AND active = true AND sqlc.arg('event')::text = ANY(events);

-- name: UpdateWebhookEndpoint :one
UPDATE webhook_endpoints
SET url = $3, events = $4, active = $5, updated_at = now()
WHERE id = $1 AND org_id = $2
RETURNING *;

-- name: DeleteWebhookEndpoint :execrows
DELETE FROM webhook_endpoints WHERE id = $1 AND org_id = $2;

-- name: CreateWebhookDelivery :one
INSERT INTO webhook_deliveries (id, endpoint_id, event_type, payload)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: GetWebhookDeliveryWithEndpoint :one
SELECT d.id, d.endpoint_id, d.event_type, d.payload, d.attempt,
       e.url, e.secret_enc, e.active AS endpoint_active, e.org_id
FROM webhook_deliveries d
JOIN webhook_endpoints e ON e.id = d.endpoint_id
WHERE d.id = $1;

-- name: RecordWebhookDeliveryResult :exec
UPDATE webhook_deliveries
SET attempt = $2, status_code = $3, error = $4, delivered_at = $5, next_retry_at = $6
WHERE id = $1;

-- name: ListWebhookDeliveries :many
-- Keyset-paged on (created_at, id) so the §9.1 cursor stays stable while new
-- deliveries land at the head.
SELECT * FROM webhook_deliveries
WHERE endpoint_id = $1
  AND (sqlc.narg('before_time')::timestamptz IS NULL
       OR created_at < sqlc.narg('before_time')
       OR (created_at = sqlc.narg('before_time') AND id < sqlc.narg('before_id')))
ORDER BY created_at DESC, id DESC
LIMIT $2;

-- name: CountWebhookEndpoints :one
-- §19: 20 webhook endpoints per org.
SELECT count(*)::bigint FROM webhook_endpoints WHERE org_id = $1;

-- ============================ Domain claims ============================

-- name: CreateDomainClaim :one
INSERT INTO domain_claims (id, org_id, domain, verification_token)
VALUES ($1, $2, $3, $4)
ON CONFLICT (org_id, domain)
  DO UPDATE SET verification_token = EXCLUDED.verification_token
RETURNING *;

-- name: GetDomainClaim :one
SELECT * FROM domain_claims WHERE org_id = $1 AND domain = $2;

-- name: ListDomainClaims :many
SELECT * FROM domain_claims WHERE org_id = $1 ORDER BY created_at DESC;

-- name: MarkDomainClaimVerified :exec
UPDATE domain_claims SET verified_at = now() WHERE org_id = $1 AND domain = $2;

-- name: SetOrgVerifiedDomain :exec
UPDATE orgs SET verified_domain = $2, updated_at = now() WHERE id = $1;

-- name: GetOrgByVerifiedDomain :one
SELECT o.*, h.handle FROM orgs o JOIN handles h ON h.id = o.id WHERE o.verified_domain = $1;

-- ============================ Audit exports ============================

-- name: CreateAuditExport :one
INSERT INTO audit_exports (id, org_id, requested_by, action_filter, status)
VALUES ($1, $2, $3, $4, 'pending')
RETURNING *;

-- name: GetAuditExport :one
SELECT * FROM audit_exports WHERE id = $1 AND org_id = $2;

-- name: GetAuditExportByID :one
SELECT * FROM audit_exports WHERE id = $1;

-- name: SetAuditExportRunning :exec
UPDATE audit_exports SET status = 'running' WHERE id = $1;

-- name: CompleteAuditExport :exec
UPDATE audit_exports
SET status = 'completed', object_key = $2, event_count = $3, finished_at = now()
WHERE id = $1;

-- name: FailAuditExport :exec
UPDATE audit_exports SET status = 'failed', error = $2, finished_at = now() WHERE id = $1;

-- name: StreamOrgAuditEvents :many
SELECT a.* FROM audit_events a
WHERE a.org_id = $1
  AND (sqlc.narg('action')::text IS NULL OR a.action = sqlc.narg('action'))
  AND (sqlc.narg('after_time')::timestamptz IS NULL
       OR a.occurred_at > sqlc.narg('after_time')
       OR (a.occurred_at = sqlc.narg('after_time') AND a.id > sqlc.narg('after_id')))
ORDER BY a.occurred_at ASC, a.id ASC
LIMIT $2;
