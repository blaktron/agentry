-- +goose Up
-- BriefAgent run modes (DEV-088; agentry-notes/plans/briefagent-modes.md
-- §4.1). A release supports autonomous, interactive, or both. The kind
-- column stays until the API moves to modes (agentry#145); every row that
-- can still be created is an instruction package, so the default is
-- autonomous and only the withdrawn kind ends up with no modes at all.
ALTER TABLE agents ADD COLUMN modes text[] NOT NULL DEFAULT '{autonomous}';
ALTER TABLE agents ADD CONSTRAINT agents_modes_valid
  CHECK (modes <@ ARRAY['autonomous','interactive']::text[]);

-- The withdrawn kind: no modes, blocked, and an advisory that says why so
-- the agent page and the advisories feed explain the block.
UPDATE agents SET modes = '{}', quarantine_state = 'blocked', updated_at = now()
 WHERE kind = 'mcp-server';
INSERT INTO advisories (id, agent_id, affected_versions, severity, summary, detail, published_at)
SELECT gen_random_uuid(), id, '*', 'medium',
       'Package kind withdrawn: MCP server codebases are no longer BriefAgents',
       'The mcp-server package kind was withdrawn on 2026-09-05 (DEV-088). This agent is blocked. An agent that needs MCP servers declares them under capabilities.mcpServers in its own manifest.',
       now()
  FROM agents WHERE kind = 'mcp-server';

ALTER TABLE agents ADD CONSTRAINT agents_modes_nonempty_unless_blocked
  CHECK (cardinality(modes) > 0 OR quarantine_state = 'blocked');
CREATE INDEX agents_modes_idx ON agents USING gin (modes);

-- +goose Down
-- The block on the withdrawn kind's rows is left in place: lifting it is a
-- trust-and-safety decision, not a schema one.
DELETE FROM advisories WHERE summary = 'Package kind withdrawn: MCP server codebases are no longer BriefAgents';
DROP INDEX agents_modes_idx;
ALTER TABLE agents DROP CONSTRAINT agents_modes_nonempty_unless_blocked;
ALTER TABLE agents DROP CONSTRAINT agents_modes_valid;
ALTER TABLE agents DROP COLUMN modes;
