-- +goose Up
-- The consumed set of the 2FA social login's second leg. Its challenge is a
-- sealed blob the client hands back with a TOTP code, and it is single use:
-- without this record, within its five minutes it could open one session
-- after another, each needing only a valid code. Each challenge carries a
-- random id, recorded here when the challenge completes; a second completion
-- finds the row and is refused. It is a table and not a set in one process's
-- memory so that the refusal holds at every API replica, as the SAML
-- consumed-assertion set does. A row outlives its challenge by a margin for
-- the replicas' clocks, and the writer sweeps expired rows, so the table
-- stays the size of what is live — minutes of sign-ins.
CREATE TABLE totp_consumed_challenges (
  id         text PRIMARY KEY CHECK (length(id) <= 64),
  expires_at timestamptz NOT NULL
);
CREATE INDEX totp_consumed_challenges_expires_at_idx ON totp_consumed_challenges (expires_at);

-- +goose Down
DROP TABLE IF EXISTS totp_consumed_challenges;
