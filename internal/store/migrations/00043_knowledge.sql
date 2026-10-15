-- +goose Up
-- Knowledge packs: a pack a person (or an organization) keeps in Agentry. The
-- row holds what may be read without the pack's data key — its name, size,
-- digest, page count, scan state and report — and the data key only as its
-- owner's wrapper wrapped it; the tree itself is sealed in the blob store
-- (knowledge_objects). The owner is a kind and an id with no foreign key,
-- because it is one of two tables: every path that erases an owner deletes
-- its packs by name (the account erasure, a data clear, an organization's
-- decommission).
CREATE TABLE knowledge_packs (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_kind        text NOT NULL CHECK (owner_kind IN ('user', 'org')),
  owner_id          uuid NOT NULL,
  name              text NOT NULL,
  -- empty (created, no tree yet) → scanning (a tree uploaded, its scan
  -- queued) → ready (scanned, findings or not) or failed (the stored
  -- tree could not be read at scan time).
  state             text NOT NULL DEFAULT 'empty' CHECK (state IN ('empty', 'scanning', 'ready', 'failed')),
  bytes             bigint NOT NULL DEFAULT 0,
  files             integer NOT NULL DEFAULT 0,
  pages             integer NOT NULL DEFAULT 0,
  digest            text NOT NULL DEFAULT '',
  object_key        text NOT NULL DEFAULT '',
  scan_report       jsonb,
  scanned_at        timestamptz,
  wrapper_kind      text NOT NULL,
  wrapper_recipient text NOT NULL,
  wrapped_key       bytea NOT NULL,
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now(),
  UNIQUE (owner_kind, owner_id, name)
);
CREATE INDEX knowledge_packs_owner ON knowledge_packs (owner_kind, owner_id);

-- Every sealed tree stored for a pack, by its blob key under the owner's
-- prefix (knowledge/<kind>/<owner>/<pack>/<object>.sealed). A new upload
-- is a new object; the pack's row names the current one, and the object it
-- replaced is deleted with its blob once the new one is in place.
CREATE TABLE knowledge_objects (
  key         text PRIMARY KEY,
  pack_id     uuid NOT NULL REFERENCES knowledge_packs(id) ON DELETE CASCADE,
  owner_kind  text NOT NULL,
  owner_id    uuid NOT NULL,
  bytes       bigint NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX knowledge_objects_owner ON knowledge_objects (owner_kind, owner_id);

-- The random salt the core's key wrapper derives an owner's key-encryption
-- key with (internal/knowledge.DeploymentWrapper). Deleting it destroys
-- every data key ever wrapped for that owner, wherever a copy is kept.
CREATE TABLE knowledge_owner_keys (
  owner_kind  text NOT NULL CHECK (owner_kind IN ('user', 'org')),
  owner_id    uuid NOT NULL,
  salt        bytea NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (owner_kind, owner_id)
);

-- +goose Down
DROP TABLE knowledge_owner_keys;
DROP TABLE knowledge_objects;
DROP TABLE knowledge_packs;
