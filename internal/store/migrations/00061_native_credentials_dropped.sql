-- +goose Up
-- The server keeps no credentials of its own: people sign in through the
-- deployment's OpenID provider, so no password hash, TOTP seed or consumed
-- second-factor challenge is stored. users.totp_enabled stays, always false,
-- for readers that still select it.
ALTER TABLE users DROP COLUMN password_hash;
ALTER TABLE users DROP COLUMN totp_secret_enc;
UPDATE users SET totp_enabled = false WHERE totp_enabled;
DROP TABLE totp_consumed_challenges;

-- +goose Down
CREATE TABLE totp_consumed_challenges (
  id         text PRIMARY KEY CHECK (length(id) <= 64),
  expires_at timestamptz NOT NULL
);
CREATE INDEX totp_consumed_challenges_expires_at_idx ON totp_consumed_challenges (expires_at);
ALTER TABLE users ADD COLUMN totp_secret_enc bytea;
ALTER TABLE users ADD COLUMN password_hash text;
