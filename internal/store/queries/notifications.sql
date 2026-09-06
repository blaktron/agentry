-- Notification settings (agentry#190).

-- name: GetUserNotificationSettings :one
SELECT * FROM user_notification_settings WHERE user_id = $1;

-- name: UpsertUserNotificationSettings :one
INSERT INTO user_notification_settings (user_id, email_dependency_alerts, email_quarantine, email_review_decisions, email_advisories, email_org_invites, web_dependency_alerts)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (user_id) DO UPDATE SET
  email_dependency_alerts = EXCLUDED.email_dependency_alerts,
  email_quarantine = EXCLUDED.email_quarantine,
  email_review_decisions = EXCLUDED.email_review_decisions,
  email_advisories = EXCLUDED.email_advisories,
  email_org_invites = EXCLUDED.email_org_invites,
  web_dependency_alerts = EXCLUDED.web_dependency_alerts,
  updated_at = now()
RETURNING *;
