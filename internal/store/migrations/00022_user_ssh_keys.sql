-- +goose Up
-- SSH git transport (§6.1 Q7, agentry#70): a user's SSH public keys are the
-- credential for ssh://git@…/{ns}/{name}.git. The fingerprint (SHA256, as
-- OpenSSH prints it) is the lookup key; the key itself is kept for display
-- and for re-deriving the fingerprint should the format ever change.
CREATE TABLE user_ssh_keys (
  id           uuid PRIMARY KEY,
  user_id      uuid NOT NULL REFERENCES users(id),
  title        text NOT NULL,
  key_type     text NOT NULL,          -- ssh-ed25519, ecdsa-sha2-nistp256, ssh-rsa, …
  public_key   text NOT NULL,          -- authorized_keys line without the comment
  fingerprint  text NOT NULL,          -- "SHA256:<base64>"
  created_at   timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz,
  revoked_at   timestamptz
);
CREATE UNIQUE INDEX user_ssh_keys_fingerprint_live_idx ON user_ssh_keys (fingerprint) WHERE revoked_at IS NULL;
CREATE INDEX user_ssh_keys_user_idx ON user_ssh_keys (user_id);

-- +goose Down
DROP TABLE user_ssh_keys;
