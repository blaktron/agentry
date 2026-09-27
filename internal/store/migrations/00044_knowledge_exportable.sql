-- +goose Up
-- Shared knowledge (plan knowledge.md §4.7, D26; agentry#646): an
-- organization's pack is exported unencrypted by its admins, and by its
-- members only once an admin marks it exportable. A person's own pack
-- ignores the flag: its owner exports it.
ALTER TABLE knowledge_packs ADD COLUMN exportable boolean NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE knowledge_packs DROP COLUMN exportable;
