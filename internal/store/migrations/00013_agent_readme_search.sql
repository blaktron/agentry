-- +goose Up
-- §10.4: search_tsv is "weighted tsvector(name A, summary B, readme C)". Only
-- A and B were ever populated, so a query matching a term that appears solely
-- in an agent's README found nothing — the README is where an agent actually
-- describes what it does, so this was the majority of its searchable text.
--
-- The README lives on the version's archive, not on the agent row, and the
-- trigger cannot reach into object storage. So the extracted text is
-- denormalized onto agents.readme_text at publish time (internal/registry) and
-- the trigger reads it from there, keeping the trigger a pure function of the
-- row exactly as it was before.
ALTER TABLE agents ADD COLUMN readme_text text NOT NULL DEFAULT '';

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION agents_search_tsv_update() RETURNS trigger AS $$
BEGIN
  NEW.search_tsv :=
    setweight(to_tsvector('english', NEW.name::text), 'A') ||
    setweight(to_tsvector('english', coalesce(NEW.summary, '')), 'B') ||
    setweight(to_tsvector('english', coalesce(NEW.readme_text, '')), 'C');
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- The trigger must now also fire when readme_text changes; the old definition
-- listed only (name, summary), so a README update would not have reindexed.
DROP TRIGGER IF EXISTS agents_search_tsv_trg ON agents;
CREATE TRIGGER agents_search_tsv_trg
  BEFORE INSERT OR UPDATE OF name, summary, readme_text ON agents
  FOR EACH ROW EXECUTE FUNCTION agents_search_tsv_update();

-- No backfill of search_tsv is needed: existing rows get readme_text = '',
-- and appending an empty tsvector leaves the stored value identical. Rows get
-- their README indexed on the next publish, which is also when the text first
-- becomes available.

-- +goose Down
DROP TRIGGER IF EXISTS agents_search_tsv_trg ON agents;
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION agents_search_tsv_update() RETURNS trigger AS $$
BEGIN
  NEW.search_tsv :=
    setweight(to_tsvector('english', NEW.name::text), 'A') ||
    setweight(to_tsvector('english', coalesce(NEW.summary, '')), 'B');
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
CREATE TRIGGER agents_search_tsv_trg
  BEFORE INSERT OR UPDATE OF name, summary ON agents
  FOR EACH ROW EXECUTE FUNCTION agents_search_tsv_update();
ALTER TABLE agents DROP COLUMN IF EXISTS readme_text;
