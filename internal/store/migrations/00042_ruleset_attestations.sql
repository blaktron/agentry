-- +goose Up
-- Stored ruleset attestations: the signed statement over the embedded rule
-- bundle's digest that `agentry validate --rules-update` verifies. The
-- process that holds the key (the worker, or `all`) signs it at start for the
-- bundle it carries and stores it here, one row per bundle digest and key;
-- the api role serves the row signed by the active key without holding the
-- key itself.
CREATE TABLE ruleset_attestations (
  bundle_digest text NOT NULL,
  key_id        text NOT NULL REFERENCES signing_keys(key_id),
  dsse_envelope jsonb NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (bundle_digest, key_id)
);

-- An approval a keyless role handed to the worker is marked, so the worker's
-- job and the watchdog publish only what was handed off: an approved item
-- left from before this column, whatever its version's status, is never
-- published by either.
ALTER TABLE review_items ADD COLUMN publish_pending boolean NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE review_items DROP COLUMN publish_pending;
DROP TABLE ruleset_attestations;
