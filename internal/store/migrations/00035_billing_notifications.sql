-- +goose Up
-- A person's switch for billing mail: the messages the enterprise build's
-- billing extension sends through the core's notifier seam — a checkout
-- confirmed, a payment failed, an organization restricted, seats reached,
-- "your organization covers you". On by default like every other kind: a new
-- mail class is opt-out, never lost.
ALTER TABLE user_notification_settings
  ADD COLUMN email_billing boolean NOT NULL DEFAULT true;

-- +goose Down
ALTER TABLE user_notification_settings DROP COLUMN email_billing;
