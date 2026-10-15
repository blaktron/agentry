-- +goose Up
-- Trusted devices: a browser that answered the second factor once may be
-- remembered, so a later password sign-in from it skips the code. This is a
-- second browser credential class beside sessions — it outlives the 24h
-- session cap by design, under its own ceiling in internal/config, and it
-- skips the second factor and nothing else.
--
-- The token is the whole trust decision: possession of the cookie is what
-- authenticates it, matched here by its hash. ip and user_agent are kept so
-- the account page can describe the browser to its owner; neither is
-- consulted in any decision, so a client-choosable X-Forwarded-For cannot
-- influence trust.
CREATE TABLE trusted_devices (
  id           uuid PRIMARY KEY,
  user_id      uuid NOT NULL REFERENCES users(id),
  token_sha256 bytea NOT NULL,
  ip           inet,
  user_agent   text,
  created_at   timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz NOT NULL,
  revoked_at   timestamptz
);
-- Live rows are unique by token hash. The index is partial so a revoked row
-- keeps its hash for the audit trail without blocking anything: the token is
-- random per mint, so a collision is not a concern, and the lookup only ever
-- asks about live rows.
CREATE UNIQUE INDEX trusted_devices_token_live_idx ON trusted_devices (token_sha256) WHERE revoked_at IS NULL;
CREATE INDEX trusted_devices_user_idx ON trusted_devices (user_id);
CREATE INDEX trusted_devices_expires_idx ON trusted_devices (expires_at);

-- +goose Down
DROP TABLE trusted_devices;
