-- +goose Up
-- Every key the registry has signed with, with its public part. Without this
-- record, a rotation (or a restart in dev mode) orphans every attestation the
-- outgoing key had signed: the private key is gone, the public key is
-- nowhere, and the well-known set advertises only the current key, so a
-- client pinning today refuses everything published before it. The registry
-- records each signer's public key at start (`retired_at` set on the others),
-- advertises the retired ones that signed something, and countersigns
-- existing attestations with the new key. Keys used before this migration
-- were never recorded and cannot be listed; the attestations they signed
-- verify through the countersignature.
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
