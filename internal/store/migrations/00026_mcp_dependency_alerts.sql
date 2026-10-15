-- +goose Up
-- Dependency alerts: a published version that declares an MCP server version
-- which the daily sweep found to carry a newly known high or critical
-- vulnerability. One open alert per (version, server version); resolved when
-- the version leaves `published` (yanked, quarantined, blocked) or the
-- advisories are withdrawn. Not an advisory: an advisory is a
-- trust-and-safety record about the agent, this is a dependency fact that
-- clears itself when the author ships a fix.
CREATE TABLE mcp_dependency_alerts (
  id              uuid PRIMARY KEY,
  version_id      uuid NOT NULL REFERENCES agent_versions(id) ON DELETE CASCADE,
  ecosystem       text NOT NULL,
  package         text NOT NULL,
  package_version text NOT NULL,
  severity        text NOT NULL CHECK (severity IN ('high','critical')),
  advisory_ids    text[] NOT NULL,
  fixed_in        text[] NOT NULL DEFAULT '{}',   -- server versions the advisories name as fixed
  created_at      timestamptz NOT NULL DEFAULT now(),
  notified_at     timestamptz,
  resolved_at     timestamptz,
  resolved_reason text
);
CREATE UNIQUE INDEX mcp_dependency_alerts_open_idx
  ON mcp_dependency_alerts (version_id, ecosystem, package, package_version) WHERE resolved_at IS NULL;
CREATE INDEX mcp_dependency_alerts_version_idx ON mcp_dependency_alerts (version_id);
CREATE INDEX mcp_dependency_alerts_server_idx ON mcp_dependency_alerts (ecosystem, package, package_version) WHERE resolved_at IS NULL;

-- +goose Down
DROP TABLE mcp_dependency_alerts;
