-- Signing keys and re-attestation.

-- A signer registers its public key at start. Seeing a key again keeps it
-- current (a rollback to the previous key file is a legitimate rotation
-- too); `inserted` tells the caller this is a key the registry has never
-- signed with.
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
-- (`key_match` is `[{"keyid": "<id>"}]`), with the version row's facts the
-- sweep checks the statement against before vouching for it. Keyset paging:
-- the sweep moves rows out of the set it pages over.
-- name: ListAttestationsLackingSignature :many
SELECT a.id, a.version_id, a.dsse_envelope, v.version, v.archive_digest
FROM attestations a JOIN agent_versions v ON v.id = a.version_id
WHERE NOT (a.dsse_envelope->'signatures' @> sqlc.arg('key_match')::jsonb)
  AND (sqlc.narg('after')::uuid IS NULL OR a.id > sqlc.narg('after'))
ORDER BY a.id
LIMIT sqlc.arg('batch');

-- How many attestations lack the given key's signature: at start, a count
-- above zero enqueues the sweep, so a rotation, a partial sweep and a lost
-- enqueue all complete at the next start.
-- name: CountAttestationsLackingSignature :one
SELECT count(*) FROM attestations
WHERE NOT (dsse_envelope->'signatures' @> sqlc.arg('key_match')::jsonb);

-- Append a countersignature (`signature` is `[{"keyid": …, "sig": …}]`)
-- unless the envelope already carries one by that key id (`key_match` is
-- `[{"keyid": …}]`). The guard is on the key id, not the signature: ECDSA
-- signatures are randomised, so two sweeps signing the same bytes produce
-- different ones, and a guard on the whole object would let both through.
-- name: AppendAttestationSignature :execrows
UPDATE attestations
SET dsse_envelope = jsonb_set(dsse_envelope, '{signatures}', (dsse_envelope->'signatures') || sqlc.arg('signature')::jsonb)
WHERE id = sqlc.arg('id')
  AND NOT (dsse_envelope->'signatures' @> sqlc.arg('key_match')::jsonb);

-- The key the deployment signs with today, for a process that holds no key of
-- its own (the api and git roles): the one registered most recently and not
-- retired. A registration retires every other key, so at most one row
-- qualifies once the signer has started.
-- name: GetActiveSigningKey :one
SELECT * FROM signing_keys WHERE retired_at IS NULL
ORDER BY last_seen_at DESC LIMIT 1;

-- The signer stores the ruleset attestation for the bundle it carries at
-- start; a row already there for that digest and key stays.
-- name: InsertRulesetAttestation :exec
INSERT INTO ruleset_attestations (bundle_digest, key_id, dsse_envelope)
VALUES ($1, $2, $3)
ON CONFLICT (bundle_digest, key_id) DO NOTHING;

-- The ruleset attestation to serve for a bundle: the one the active key
-- signed. None when the active key's holder has not started with this
-- bundle yet; an envelope by a retired key is never served, because the key
-- set advertises retired keys only for version attestations.
-- name: GetRulesetAttestation :one
SELECT ra.* FROM ruleset_attestations ra
JOIN signing_keys k ON k.key_id = ra.key_id
WHERE ra.bundle_digest = $1 AND k.retired_at IS NULL
ORDER BY k.last_seen_at DESC
LIMIT 1;
