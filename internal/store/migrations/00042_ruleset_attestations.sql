-- +goose Up
-- Stored ruleset attestations (agentry#479): the signed statement over the
-- embedded rule bundle's digest that `agentry validate --rules-update`
-- verifies. It was signed on request by whichever process served the route,
-- which put the private key in the api role. The process that holds the key
-- (the worker, or `all`) now signs it at start for the bundle it carries and
-- stores it here, one row per bundle digest and key; the api role serves the
-- row signed by the active key without holding the key itself.
CREATE TABLE ruleset_attestations (
  bundle_digest text NOT NULL,
  key_id        text NOT NULL REFERENCES signing_keys(key_id),
  dsse_envelope jsonb NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (bundle_digest, key_id)
);

-- +goose Down
DROP TABLE ruleset_attestations;
