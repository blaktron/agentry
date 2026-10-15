-- +goose Up
-- A Drafter revision S9 gives the benefit of the doubt. An upload may claim
-- the hosted draft it was published from (draft_run); the claim alone changes
-- nothing. The scan asks the extension's DraftProvenance whether the
-- submitter ran that draft against this agent's S9 baseline and whether the
-- draft's recorded proof matches the submitted files; only then does the
-- version's source become 'drafter-revision', with the baseline it was proved
-- against (draft_baseline). A rescan reads that record and never asks again,
-- so the benefit lapses neither when the draft's record is gone nor when a
-- later release becomes the baseline the rescan diffs against.
ALTER TABLE agent_versions DROP CONSTRAINT agent_versions_source_check;
ALTER TABLE agent_versions ADD CONSTRAINT agent_versions_source_check
  CHECK (source IN ('git-tag', 'cli-upload', 'drafter-revision'));
ALTER TABLE agent_versions ADD COLUMN draft_run uuid;
ALTER TABLE agent_versions ADD COLUMN draft_baseline text;
ALTER TABLE agent_versions ADD CONSTRAINT agent_versions_drafter_revision_check
  CHECK ((source = 'drafter-revision') = (draft_baseline IS NOT NULL)
     AND (source <> 'drafter-revision' OR draft_run IS NOT NULL));

-- +goose StatementBegin
-- The usual immutability rule with one edge more: past 'submitted' the source
-- may move once, from 'cli-upload' to 'drafter-revision', while the version
-- is being scanned, for a version that claimed a draft, and only with the
-- baseline it was proved against. The claim itself is immutable past
-- 'submitted', and so is the baseline once written.
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

-- +goose Down
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION agent_versions_enforce_immutability() RETURNS trigger AS $$
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
    OR NEW.source        IS DISTINCT FROM OLD.source
    OR NEW.created_at    IS DISTINCT FROM OLD.created_at
    THEN
      RAISE EXCEPTION 'agent_versions row is immutable past submitted (only state-machine fields may change)';
    END IF;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
ALTER TABLE agent_versions DROP CONSTRAINT agent_versions_drafter_revision_check;
ALTER TABLE agent_versions DROP COLUMN draft_baseline;
ALTER TABLE agent_versions DROP COLUMN draft_run;
ALTER TABLE agent_versions DROP CONSTRAINT agent_versions_source_check;
ALTER TABLE agent_versions ADD CONSTRAINT agent_versions_source_check
  CHECK (source IN ('git-tag', 'cli-upload'));
