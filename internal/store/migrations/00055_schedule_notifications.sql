-- +goose Up
-- A person's switch for schedule mail (agentry#1002, M6 of plan
-- quickagent-scheduling.md, D9): what the closed build's schedules
-- extension sends through the core's notifier seam — a scheduled run in
-- Agentry failed, or a schedule paused — and never a success. On by
-- default like every other kind: a new mail class is opt-out, never lost.
ALTER TABLE user_notification_settings
  ADD COLUMN email_schedules boolean NOT NULL DEFAULT true;

-- +goose Down
ALTER TABLE user_notification_settings DROP COLUMN email_schedules;
