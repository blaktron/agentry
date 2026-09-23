-- Notification settings (agentry#190).

-- name: GetUserNotificationSettings :one
SELECT * FROM user_notification_settings WHERE user_id = $1;

-- name: UpsertUserNotificationSettings :one
-- The billing switch is nullable on the way in (agentry#366): a client
-- that predates it omits it, and an omitted switch keeps the row's value
-- — or the default on a first write — in the same statement, so two
-- clients writing at once cannot resurrect a value neither sent.
INSERT INTO user_notification_settings (user_id, email_dependency_alerts, email_quarantine, email_review_decisions, email_advisories, email_org_invites, email_billing, web_dependency_alerts)
VALUES ($1, $2, $3, $4, $5, $6, COALESCE(sqlc.narg('email_billing')::boolean, true), $7)
ON CONFLICT (user_id) DO UPDATE SET
  email_dependency_alerts = EXCLUDED.email_dependency_alerts,
  email_quarantine = EXCLUDED.email_quarantine,
  email_review_decisions = EXCLUDED.email_review_decisions,
  email_advisories = EXCLUDED.email_advisories,
  email_org_invites = EXCLUDED.email_org_invites,
  email_billing = COALESCE(sqlc.narg('email_billing')::boolean, user_notification_settings.email_billing),
  web_dependency_alerts = EXCLUDED.web_dependency_alerts,
  updated_at = now()
RETURNING *;

-- name: ListOrgAdminIDs :many
-- The active administrators of an organization, for a message an
-- extension addresses to "the admins" (agentry#366): active memberships
-- of active accounts only, the same two conditions ListOrgAdminsForMail
-- and the last-admin guard carry — a pending admin holds nothing yet, a
-- suspended one holds nothing any more, and neither is told the
-- organization's business.
SELECT m.user_id FROM memberships m
JOIN users u ON u.id = m.user_id
WHERE m.org_id = $1 AND m.role = 'admin' AND m.state = 'active' AND u.state = 'active'
ORDER BY m.created_at;

-- name: DeleteUserNotificationSettings :execrows
-- Clear-data (agentry#498): no row reads as the defaults.
DELETE FROM user_notification_settings WHERE user_id = $1;
