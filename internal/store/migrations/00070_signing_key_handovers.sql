-- +goose Up
-- A planned rotation of the release-signing key is handed over by the
-- outgoing key: it signs a statement naming the incoming key, which a client
-- that pinned the outgoing key can verify and so adopt the new one. Every
-- handover the registry has made is kept and served, oldest first, so a
-- client several rotations behind can walk the chain from the key it pinned.
-- Both keys are recorded keys: a handover never names a key the registry did
-- not sign with.
CREATE TABLE signing_key_handovers (
  from_key_id   text NOT NULL REFERENCES signing_keys(key_id),
  to_key_id     text NOT NULL REFERENCES signing_keys(key_id),
  dsse_envelope jsonb NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (from_key_id, to_key_id),
  CHECK (from_key_id <> to_key_id)
);

-- +goose Down
DROP TABLE IF EXISTS signing_key_handovers;
