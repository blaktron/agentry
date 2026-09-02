-- +goose Up
-- One-time grants behind the desktop app's browser sign-in (agentry#19,
-- DEV-058 hardening). The web tier's authorize form no longer mints a PAT
-- and puts it in the loopback redirect's query string (browser history);
-- it records a grant here and hands the app a short-lived code. The app
-- exchanges the code from its own process and the PAT is minted at that
-- moment — nothing token-shaped is stored, and a code read from history
-- later is already consumed or expired.
CREATE TABLE desktop_grants (
  id          uuid PRIMARY KEY,
  user_id     uuid NOT NULL REFERENCES users(id),
  code_sha256 bytea UNIQUE NOT NULL,
  state_sha256 bytea NOT NULL,          -- the app's nonce, bound to the grant
  scopes      text[] NOT NULL,
  name        text NOT NULL,
  expires_at  timestamptz NOT NULL,
  consumed_at timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX desktop_grants_expires_idx ON desktop_grants (expires_at);

-- +goose Down
DROP TABLE desktop_grants;
