-- Knowledge packs (plan knowledge.md §4.4, agentry#593). Every read and
-- write names the owner: a pack is found only by its owner, and anyone
-- else's lookup is a pack that does not exist.

-- name: CreateKnowledgePack :one
INSERT INTO knowledge_packs (owner_kind, owner_id, name, wrapper_kind, wrapper_recipient, wrapped_key)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: GetKnowledgePack :one
SELECT * FROM knowledge_packs WHERE id = $1 AND owner_kind = $2 AND owner_id = $3;

-- name: GetKnowledgePackForUpdate :one
SELECT * FROM knowledge_packs WHERE id = $1 AND owner_kind = $2 AND owner_id = $3 FOR UPDATE;

-- name: ListKnowledgePacks :many
SELECT * FROM knowledge_packs WHERE owner_kind = $1 AND owner_id = $2 ORDER BY name;

-- name: ListKnowledgePackSizes :many
-- What platform staff may see of an owner's packs: names and sizes, never
-- a byte of content, a digest or a key.
SELECT id, name, state, bytes, created_at, updated_at FROM knowledge_packs
WHERE owner_kind = $1 AND owner_id = $2 ORDER BY name;

-- name: SumKnowledgeBytesOfPool :one
-- What a pool's owners keep in the registry, the pack named aside (the one
-- an upload replaces; uuid.Nil for none): the allocation counts every other
-- pack of every owner in the pool (agentry#612). An owner's id is a handle's,
-- unique across people and organizations, so the two lists match exactly
-- the owners given, on the owner index.
SELECT COALESCE(SUM(bytes), 0)::bigint FROM knowledge_packs
WHERE owner_kind = ANY(sqlc.arg(owner_kinds)::text[]) AND owner_id = ANY(sqlc.arg(owner_ids)::uuid[])
  AND id <> sqlc.arg(except_id);

-- name: SetKnowledgeTree :one
-- A new tree is in place and its scan is queued.
UPDATE knowledge_packs
SET state = 'scanning', bytes = $2, files = $3, pages = $4, digest = $5, object_key = $6,
    scan_report = NULL, scanned_at = NULL, updated_at = now()
WHERE id = $1
RETURNING *;

-- name: FinishKnowledgeScan :execrows
-- The scan of the tree named by its object ends: ready, findings or not,
-- or failed. A scan of a tree since replaced changes nothing.
UPDATE knowledge_packs
SET state = sqlc.arg(state), scan_report = sqlc.arg(report), scanned_at = now(), updated_at = now()
WHERE id = sqlc.arg(id) AND object_key = sqlc.arg(object_key) AND state = 'scanning';

-- name: GetKnowledgePackByObject :one
-- The scan job's read: the pack whose current tree is this object.
SELECT * FROM knowledge_packs WHERE id = $1 AND object_key = $2;

-- name: DeleteKnowledgePack :one
DELETE FROM knowledge_packs WHERE id = $1 AND owner_kind = $2 AND owner_id = $3
RETURNING id;

-- name: CreateKnowledgeObject :exec
INSERT INTO knowledge_objects (key, pack_id, owner_kind, owner_id, bytes)
VALUES ($1, $2, $3, $4, $5);

-- name: ListKnowledgeObjectsOfPack :many
SELECT key FROM knowledge_objects WHERE pack_id = $1 ORDER BY created_at;

-- name: DeleteKnowledgeObject :exec
DELETE FROM knowledge_objects WHERE key = $1;

-- name: DeleteKnowledgeObjectsOfOwner :many
-- An owner's erasure, data clear or decommission, with
-- DeleteKnowledgePacksOfOwner in the same transaction: the blob keys of
-- every object come back for the caller to delete once it commits.
DELETE FROM knowledge_objects WHERE owner_kind = $1 AND owner_id = $2 RETURNING key;

-- name: DeleteKnowledgePacksOfOwner :execrows
DELETE FROM knowledge_packs WHERE owner_kind = $1 AND owner_id = $2;

-- name: GetKnowledgeOwnerSalt :one
SELECT salt FROM knowledge_owner_keys WHERE owner_kind = $1 AND owner_id = $2;

-- name: CreateKnowledgeOwnerSalt :one
-- The first wrap for an owner; a concurrent first wrap keeps the salt that
-- won.
INSERT INTO knowledge_owner_keys (owner_kind, owner_id, salt) VALUES ($1, $2, $3)
ON CONFLICT (owner_kind, owner_id) DO UPDATE SET owner_kind = EXCLUDED.owner_kind
RETURNING salt;

-- name: DeleteKnowledgeOwnerSalt :exec
DELETE FROM knowledge_owner_keys WHERE owner_kind = $1 AND owner_id = $2;
