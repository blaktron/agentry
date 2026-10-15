-- +goose Up
-- Cookie-notice acknowledgement. A timestamp, not a boolean: "when did this
-- account acknowledge the notice" is auditable and naturally write-once.
-- Stored on the account so the banner stays dismissed across devices for
-- signed-in users; anonymous visitors get a plain cookie.
ALTER TABLE users ADD COLUMN cookie_ack_at timestamptz;

-- +goose Down
ALTER TABLE users DROP COLUMN cookie_ack_at;
