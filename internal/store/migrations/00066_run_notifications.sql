-- +goose Up
-- A person's two switches for hosted-run mail, sent through the core's
-- notifier seam by the build that runs QuickAgents In Agentry: a run that
-- failed after it started or was refused by the queue (run failures), and a
-- run that completed (run finished). Both are off by default, for new rows
-- and for every existing one: a run's outcome is recorded by the hosted
-- service either way, and mail about it is something a person asks for.
ALTER TABLE user_notification_settings
  ADD COLUMN email_run_failures boolean NOT NULL DEFAULT false,
  ADD COLUMN email_run_finished boolean NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE user_notification_settings
  DROP COLUMN email_run_failures,
  DROP COLUMN email_run_finished;
