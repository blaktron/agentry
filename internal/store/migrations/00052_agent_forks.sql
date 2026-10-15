-- +goose Up
-- Forks.
--
-- A fork is an agent copied from a public one: its own row, its own
-- repository (the origin's objects and refs copied, never shared), and the
-- origin it came from, kept for good. forked_from_agent_id is the origin
-- agent and forked_from_version_id the published version the fork was taken
-- from; the fork's first version is that version's content renamed into the
-- fork's namespace, submitted through the pipeline like any other.
--
-- A fork is private forever: the CHECK below, beside the API's named refusal
-- and the sites offering no button. Lineage is permanent: there is no detach,
-- so the trigger refuses any change to the two origin columns once the row
-- exists.
--
-- fork_state follows the copy, which a worker does after the row commits (the
-- api role holds no repositories): copying until the repository is copied and
-- the first version submitted, ready after, failed with fork_detail saying
-- why in words. It is NULL on an agent that is not a fork.
ALTER TABLE agents
  ADD COLUMN forked_from_agent_id   uuid REFERENCES agents(id),
  ADD COLUMN forked_from_version_id uuid REFERENCES agent_versions(id),
  ADD COLUMN forked_by              uuid REFERENCES users(id),
  ADD COLUMN fork_state             text CHECK (fork_state IN ('copying', 'ready', 'failed')),
  ADD COLUMN fork_detail            text NOT NULL DEFAULT '';

ALTER TABLE agents
  ADD CONSTRAINT agents_fork_is_private CHECK (forked_from_agent_id IS NULL OR visibility = 'private'),
  ADD CONSTRAINT agents_fork_lineage_whole CHECK (
    (forked_from_agent_id IS NULL) = (forked_from_version_id IS NULL)
    AND (forked_from_agent_id IS NULL) = (fork_state IS NULL)
  );

-- Counting an origin's forks (forkCount) and finding them (staff).
CREATE INDEX agents_forked_from_idx ON agents (forked_from_agent_id) WHERE forked_from_agent_id IS NOT NULL;

-- +goose StatementBegin
CREATE FUNCTION agents_fork_lineage_permanent() RETURNS trigger AS $$
BEGIN
  IF NEW.forked_from_agent_id IS DISTINCT FROM OLD.forked_from_agent_id
     OR NEW.forked_from_version_id IS DISTINCT FROM OLD.forked_from_version_id THEN
    RAISE EXCEPTION 'a fork''s origin is permanent';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

CREATE TRIGGER agents_fork_lineage_permanent
  BEFORE UPDATE OF forked_from_agent_id, forked_from_version_id ON agents
  FOR EACH ROW EXECUTE FUNCTION agents_fork_lineage_permanent();

-- +goose Down
DROP TRIGGER IF EXISTS agents_fork_lineage_permanent ON agents;
DROP FUNCTION IF EXISTS agents_fork_lineage_permanent();
DROP INDEX IF EXISTS agents_forked_from_idx;
ALTER TABLE agents
  DROP CONSTRAINT IF EXISTS agents_fork_lineage_whole,
  DROP CONSTRAINT IF EXISTS agents_fork_is_private;
ALTER TABLE agents
  DROP COLUMN IF EXISTS fork_detail,
  DROP COLUMN IF EXISTS fork_state,
  DROP COLUMN IF EXISTS forked_by,
  DROP COLUMN IF EXISTS forked_from_version_id,
  DROP COLUMN IF EXISTS forked_from_agent_id;
