-- +goose Up
-- MCP server vulnerability scanning.
--
-- mcp_server_scans is the registry of every declared MCP server version the
-- pipeline has looked up: one row per (ecosystem, package, version) with the
-- advisories OSV knew at last_checked_at. S7 reads it before asking OSV (a
-- version seen within 24 h is not re-queried) and the daily sweep refreshes
-- every row. "safe" means "no known advisories as of last_checked_at" — the
-- same honesty rule as the scan itself.
CREATE TABLE mcp_server_scans (
  ecosystem       text NOT NULL CHECK (ecosystem IN ('npm','pypi')),
  package         text NOT NULL,
  version         text NOT NULL,
  status          text NOT NULL CHECK (status IN ('safe','vulnerable','error')),
  max_severity    text CHECK (max_severity IN ('info','low','medium','high','critical')),
  advisories      jsonb NOT NULL DEFAULT '[]',
  first_seen_at   timestamptz NOT NULL DEFAULT now(),
  last_checked_at timestamptz NOT NULL DEFAULT now(),
  last_error      text,
  PRIMARY KEY (ecosystem, package, version)
);
CREATE INDEX mcp_server_scans_checked_idx ON mcp_server_scans (last_checked_at);

-- agent_version_mcp_servers says which versions declare which server
-- versions, so a server that turns vulnerable maps to the QuickAgents that
-- use it without re-reading every manifest. Written by the pipeline for
-- every scanned version; backfilled below from the manifests already here.
CREATE TABLE agent_version_mcp_servers (
  version_id uuid NOT NULL REFERENCES agent_versions(id) ON DELETE CASCADE,
  ecosystem  text NOT NULL,
  package    text NOT NULL,
  version    text NOT NULL,
  PRIMARY KEY (version_id, ecosystem, package, version)
);
CREATE INDEX agent_version_mcp_servers_server_idx ON agent_version_mcp_servers (ecosystem, package, version);

INSERT INTO agent_version_mcp_servers (version_id, ecosystem, package, version)
SELECT v.id,
       CASE WHEN e ? 'npm' THEN 'npm' ELSE 'pypi' END,
       COALESCE(e->>'npm', e->>'pypi'),
       e->>'version'
FROM agent_versions v,
     jsonb_array_elements(COALESCE(v.manifest->'capabilities'->'mcpServers', '[]'::jsonb)) e
WHERE COALESCE(e->>'npm', e->>'pypi') IS NOT NULL AND e->>'version' IS NOT NULL
ON CONFLICT DO NOTHING;

-- +goose Down
DROP TABLE agent_version_mcp_servers;
DROP TABLE mcp_server_scans;
