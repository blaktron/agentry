-- +goose Up
-- A declared MCP server version its package registry does not publish: S7
-- asks npm or PyPI before OSV, and records a version they do not have as
-- not-found, never safe. OSV answers "no advisories" for a version that does
-- not exist, which is how such a server read as safe and its release
-- published, to be refused by every run (mcp-not-resolved).
ALTER TABLE mcp_server_scans DROP CONSTRAINT mcp_server_scans_status_check;
ALTER TABLE mcp_server_scans ADD CONSTRAINT mcp_server_scans_status_check
  CHECK (status IN ('safe','vulnerable','error','not-found'));

-- +goose Down
DELETE FROM mcp_server_scans WHERE status = 'not-found';
ALTER TABLE mcp_server_scans DROP CONSTRAINT mcp_server_scans_status_check;
ALTER TABLE mcp_server_scans ADD CONSTRAINT mcp_server_scans_status_check
  CHECK (status IN ('safe','vulnerable','error'));
