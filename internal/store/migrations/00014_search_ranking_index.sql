-- +goose Up
-- The §10.4 ranking multiplies relevance by installs over the last 30 days.
-- download_stats is keyed (agent_id, version_id, day), so a 30-day window
-- across all agents has no usable index and degrades to a full scan of the
-- table that grows fastest in the schema — on every search.
--
-- (day, agent_id, installs) lets the window be a range scan and covers the
-- aggregate, so the popularity factor is an index-only read.
CREATE INDEX IF NOT EXISTS download_stats_recent_idx
  ON download_stats (day, agent_id) INCLUDE (installs);

-- +goose Down
DROP INDEX IF EXISTS download_stats_recent_idx;
