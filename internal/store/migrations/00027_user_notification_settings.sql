-- +goose Up
-- Notification settings: how the registry's alerts reach a person. One row
-- per user; no row means everything on, which is what every account had
-- before this table existed. Email per kind, and the in-app dependency-alert
-- banner. Audit events and org webhooks are the org's record and are not
-- governed here.
CREATE TABLE user_notification_settings (
  user_id                 uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  email_dependency_alerts boolean NOT NULL DEFAULT true,
  email_quarantine        boolean NOT NULL DEFAULT true,
  email_review_decisions  boolean NOT NULL DEFAULT true,
  email_advisories        boolean NOT NULL DEFAULT true,
  email_org_invites       boolean NOT NULL DEFAULT true,
  web_dependency_alerts   boolean NOT NULL DEFAULT true,
  updated_at              timestamptz NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE user_notification_settings;
