-- +goose Up
-- search_tsv is a weighted tsvector(name A, summary B, readme C). The README
-- is where an agent describes what it does, so a query matching a term that
-- appears solely in an agent's README has to find it.
--
-- The README lives on the version's archive, not on the agent row, and the
-- trigger cannot reach into object storage. So the extracted text is
-- denormalized onto agents.readme_text at publish time (internal/registry)
-- and the trigger reads it from there, keeping the trigger a pure function of
-- the row exactly as it was before.
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

-- The trigger fires when readme_text changes as well as name and summary, so
-- a README update reindexes.
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
