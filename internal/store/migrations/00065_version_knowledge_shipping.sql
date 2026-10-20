-- +goose Up
-- The record of who confirmed that a version's shipped knowledge packs
-- become readable with the release: {by, at, via, packs[{name, origin?}]}.
-- It is written with the version and never changes; a version with no record
-- (one that ships no pack, say) has none.
ALTER TABLE agent_versions ADD COLUMN knowledge_shipping jsonb;

-- +goose StatementBegin
-- The immutability rule for agent_versions rows, with the record as one more
-- field that cannot change past 'submitted'.
CREATE OR REPLACE FUNCTION agent_versions_enforce_immutability() RETURNS trigger AS $$
DECLARE
  proved boolean := OLD.status = 'scanning'
    AND OLD.source = 'cli-upload' AND NEW.source = 'drafter-revision'
    AND OLD.draft_run IS NOT NULL AND OLD.draft_baseline IS NULL
    AND NEW.draft_baseline IS NOT NULL;
BEGIN
  IF OLD.status <> 'submitted' THEN
    IF NEW.status = 'submitted' THEN
      RAISE EXCEPTION 'agent_versions status cannot regress to submitted (was %)', OLD.status;
    END IF;
    IF NEW.agent_id      IS DISTINCT FROM OLD.agent_id
    OR NEW.version       IS DISTINCT FROM OLD.version
    OR NEW.commit_sha    IS DISTINCT FROM OLD.commit_sha
    OR NEW.manifest      IS DISTINCT FROM OLD.manifest
    OR NEW.capabilities  IS DISTINCT FROM OLD.capabilities
    OR NEW.archive_digest IS DISTINCT FROM OLD.archive_digest
    OR NEW.archive_key   IS DISTINCT FROM OLD.archive_key
    OR NEW.archive_size  IS DISTINCT FROM OLD.archive_size
    OR NEW.channel       IS DISTINCT FROM OLD.channel
    OR NEW.submitted_by  IS DISTINCT FROM OLD.submitted_by
    OR NEW.created_at    IS DISTINCT FROM OLD.created_at
    OR NEW.draft_run     IS DISTINCT FROM OLD.draft_run
    OR NEW.knowledge_shipping IS DISTINCT FROM OLD.knowledge_shipping
    OR (NEW.source IS DISTINCT FROM OLD.source AND NOT proved)
    OR (NEW.draft_baseline IS DISTINCT FROM OLD.draft_baseline AND NOT proved)
    THEN
      RAISE EXCEPTION 'agent_versions row is immutable past submitted (only state-machine fields may change)';
    END IF;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION agent_versions_enforce_immutability() RETURNS trigger AS $$
DECLARE
  proved boolean := OLD.status = 'scanning'
    AND OLD.source = 'cli-upload' AND NEW.source = 'drafter-revision'
    AND OLD.draft_run IS NOT NULL AND OLD.draft_baseline IS NULL
    AND NEW.draft_baseline IS NOT NULL;
BEGIN
  IF OLD.status <> 'submitted' THEN
    IF NEW.status = 'submitted' THEN
      RAISE EXCEPTION 'agent_versions status cannot regress to submitted (was %)', OLD.status;
    END IF;
    IF NEW.agent_id      IS DISTINCT FROM OLD.agent_id
    OR NEW.version       IS DISTINCT FROM OLD.version
    OR NEW.commit_sha    IS DISTINCT FROM OLD.commit_sha
    OR NEW.manifest      IS DISTINCT FROM OLD.manifest
    OR NEW.capabilities  IS DISTINCT FROM OLD.capabilities
    OR NEW.archive_digest IS DISTINCT FROM OLD.archive_digest
    OR NEW.archive_key   IS DISTINCT FROM OLD.archive_key
    OR NEW.archive_size  IS DISTINCT FROM OLD.archive_size
    OR NEW.channel       IS DISTINCT FROM OLD.channel
    OR NEW.submitted_by  IS DISTINCT FROM OLD.submitted_by
    OR NEW.created_at    IS DISTINCT FROM OLD.created_at
    OR NEW.draft_run     IS DISTINCT FROM OLD.draft_run
    OR (NEW.source IS DISTINCT FROM OLD.source AND NOT proved)
    OR (NEW.draft_baseline IS DISTINCT FROM OLD.draft_baseline AND NOT proved)
    THEN
      RAISE EXCEPTION 'agent_versions row is immutable past submitted (only state-machine fields may change)';
    END IF;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
ALTER TABLE agent_versions DROP COLUMN knowledge_shipping;
