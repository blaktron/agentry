-- +goose Up
-- A publisher may take back a version that is waiting in human review. The
-- version moves to `withdrawn`, a terminal state like `rejected`: nothing
-- leaves it, so a withdrawn version is never installable, and its number
-- stays consumed by the (agent_id, version) key. Its review item closes as
-- `withdrawn`: no reviewer decided it, and a rescan must not read the
-- closing as a person's verdict on a finding.
ALTER TABLE agent_versions DROP CONSTRAINT agent_versions_status_check;
ALTER TABLE agent_versions ADD CONSTRAINT agent_versions_status_check CHECK (status IN
  ('submitted','scanning','needs_review','approved','published',
   'rejected','yanked','quarantined','blocked','withdrawn'));

ALTER TABLE review_items DROP CONSTRAINT review_items_state_check;
ALTER TABLE review_items ADD CONSTRAINT review_items_state_check
  CHECK (state IN ('pending','approved','rejected','superseded','withdrawn'));

-- The caller's own submissions, newest first, keyset-paged.
CREATE INDEX agent_versions_submitted_by_idx ON agent_versions(submitted_by, created_at DESC, id DESC);

-- +goose Down
-- A withdrawn version becomes rejected and its item rejected: both are the
-- terminal states the older schema has, and neither is installable.
DROP INDEX agent_versions_submitted_by_idx;
UPDATE review_items SET state = 'rejected' WHERE state = 'withdrawn';
ALTER TABLE review_items DROP CONSTRAINT review_items_state_check;
ALTER TABLE review_items ADD CONSTRAINT review_items_state_check
  CHECK (state IN ('pending','approved','rejected','superseded'));

UPDATE agent_versions SET status = 'rejected' WHERE status = 'withdrawn';
ALTER TABLE agent_versions DROP CONSTRAINT agent_versions_status_check;
ALTER TABLE agent_versions ADD CONSTRAINT agent_versions_status_check CHECK (status IN
  ('submitted','scanning','needs_review','approved','published',
   'rejected','yanked','quarantined','blocked'));
