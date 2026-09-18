-- +goose Up
-- Every key the registry has signed with, with its public part (agentry#350).
-- A rotation — or, before agentry#308, a restart in dev mode — used to
-- orphan every attestation the outgoing key had signed: the private key was
-- gone, the public key was nowhere, and the well-known set advertised only
-- the current key, so a client pinning today refused everything published
-- before it. The registry now records each signer's public key at start
-- (`retired_at` set on the others), advertises the retired ones that signed
-- something, and countersigns existing attestations with the new key. Keys
-- used before this migration were never recorded and cannot be listed; the
-- attestations they signed verify through the countersignature.
CREATE TABLE signing_keys (
  key_id         text PRIMARY KEY,
  algorithm      text NOT NULL,
  public_key_pem text NOT NULL,
  first_seen_at  timestamptz NOT NULL DEFAULT now(),
  last_seen_at   timestamptz NOT NULL DEFAULT now(),
  retired_at     timestamptz
);

-- A countersignature appends to the DSSE envelope's `signatures`; the
-- envelope itself lists every key id that has signed it. The index serves
-- the containment probe ("carries a signature by this key"): the well-known
-- set asks it per retired key. The sweep's complement ("lacks this key")
-- cannot use it and scans, which a rotation-time job can afford.
CREATE INDEX attestations_signatures_idx
  ON attestations USING gin ((dsse_envelope->'signatures') jsonb_path_ops);

-- +goose Down
DROP INDEX IF EXISTS attestations_signatures_idx;
DROP TABLE IF EXISTS signing_keys;
