-- +goose Up
-- A person's switch for bug-report mail: what the enterprise build's
-- bug-reports extension sends through the core's notifier seam when platform
-- staff mark a report the person filed complete ("Reported bug fixed"). On by
-- default like every other kind: a new mail class is opt-out, never lost.
ALTER TABLE user_notification_settings
  ADD COLUMN email_bug_reports boolean NOT NULL DEFAULT true;

-- +goose Down
ALTER TABLE user_notification_settings DROP COLUMN email_bug_reports;
