-- Signing keys and re-attestation (§8.8, agentry#350).

-- A signer registers its public key at start. Seeing a key again keeps it
-- current (a rollback to the previous key file is a legitimate rotation
-- too); `inserted` tells the caller this is a key the registry has never
-- signed with, which is what triggers the re-attestation sweep.
-- name: RegisterSigningKey :one
INSERT INTO signing_keys (key_id, algorithm, public_key_pem)
VALUES ($1, $2, $3)
ON CONFLICT (key_id) DO UPDATE SET last_seen_at = now(), retired_at = NULL
RETURNING *, (xmax = 0) AS inserted;

-- Every other key is retired by the arrival of the active one: one signer
-- per deployment, so a key that is not it no longer signs.
-- name: RetireOtherSigningKeys :execrows
UPDATE signing_keys SET retired_at = now()
WHERE key_id <> $1 AND retired_at IS NULL;

-- name: GetSigningKey :one
SELECT * FROM signing_keys WHERE key_id = $1;

-- The retired keys a verifier still needs: those with at least one
-- attestation carrying their signature. A key that signed nothing (a test
-- process, an aborted start) has nothing for a client to verify and is not
-- advertised.
-- name: ListRetiredSigningKeysInUse :many
SELECT k.* FROM signing_keys k
WHERE k.retired_at IS NOT NULL
  AND EXISTS (
    SELECT 1 FROM attestations a
    WHERE a.dsse_envelope->'signatures' @> jsonb_build_array(jsonb_build_object('keyid', k.key_id))
  )
ORDER BY k.retired_at DESC, k.key_id;

-- Attestations whose envelope carries no signature by the given key
-- (`$1` is `[{"keyid": "<id>"}]`). Keyset paging: the sweep moves rows out
-- of the set it pages over.
-- name: ListAttestationsLackingSignature :many
SELECT id, version_id, dsse_envelope FROM attestations
WHERE NOT (dsse_envelope->'signatures' @> sqlc.arg('key_match')::jsonb)
  AND (sqlc.narg('after')::uuid IS NULL OR id > sqlc.narg('after'))
ORDER BY id
LIMIT sqlc.arg('batch');

-- Append a countersignature (`$2` is `[{"keyid": …, "sig": …}]`) unless the
-- envelope already carries one by that key — idempotent, so two sweeps or
-- two roles racing cannot double-sign.
-- name: AppendAttestationSignature :execrows
UPDATE attestations
SET dsse_envelope = jsonb_set(dsse_envelope, '{signatures}', (dsse_envelope->'signatures') || sqlc.arg('signature')::jsonb),
    reattested_at = now(),
    reattested_key_id = sqlc.arg('key_id')
WHERE id = sqlc.arg('id')
  AND NOT (dsse_envelope->'signatures' @> sqlc.arg('signature')::jsonb);

-- name: CountAttestationsLackingSignature :one
SELECT count(*) FROM attestations
WHERE NOT (dsse_envelope->'signatures' @> sqlc.arg('key_match')::jsonb);
