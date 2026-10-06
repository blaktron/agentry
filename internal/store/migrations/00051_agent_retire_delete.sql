-- +goose Up
-- Retire and Delete for a publisher's own QuickAgent (plan
-- forks-and-publisher.md M1, agentry#942; D1–D4, D13).
--
-- Retire puts an agent away: it becomes private (D2, the operator's answer
-- of 2026-10-06), takes no new submission, and Restore returns the
-- visibility it had, kept in retired_visibility. A retired agent does not
-- count toward the private-agent cap (D13).
--
-- Delete of an agent that has version history leaves a tombstone: the row
-- stays, so its versions (whose rows the 00004 trigger keeps forever), their
-- archives, its advisories and every receipt naming it stay with it, and so
-- does the name, which UNIQUE (namespace_id, name) then holds in its
-- namespace for good (D4). deleted_at hides the agent from every read path;
-- the agent is private as well, so no public listing can name it either.
ALTER TABLE agents
  ADD COLUMN retired_at         timestamptz,
  ADD COLUMN retired_visibility text CHECK (retired_visibility IN ('public', 'private')),
  ADD COLUMN deleted_at         timestamptz;

ALTER TABLE agents
  ADD CONSTRAINT agents_retired_is_private CHECK (retired_at IS NULL OR visibility = 'private'),
  ADD CONSTRAINT agents_retired_keeps_visibility CHECK ((retired_at IS NULL) = (retired_visibility IS NULL)),
  ADD CONSTRAINT agents_deleted_is_private CHECK (deleted_at IS NULL OR visibility = 'private');

-- +goose Down
ALTER TABLE agents
  DROP CONSTRAINT IF EXISTS agents_deleted_is_private,
  DROP CONSTRAINT IF EXISTS agents_retired_keeps_visibility,
  DROP CONSTRAINT IF EXISTS agents_retired_is_private;
ALTER TABLE agents
  DROP COLUMN IF EXISTS deleted_at,
  DROP COLUMN IF EXISTS retired_visibility,
  DROP COLUMN IF EXISTS retired_at;
