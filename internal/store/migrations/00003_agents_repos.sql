-- +goose Up
-- Agents + repos + per-agent grants. Versions and scan tables are created by
-- later migrations.

CREATE TABLE repos (
  id uuid PRIMARY KEY,                 -- immutable; storage path derives from this
  default_branch text NOT NULL DEFAULT 'main',
  size_bytes bigint NOT NULL DEFAULT 0,
  last_push_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE agents (
  id uuid PRIMARY KEY,
  namespace_id uuid NOT NULL REFERENCES handles(id),
  name citext NOT NULL CHECK (name ~ '^[a-z0-9](?:[a-z0-9-]{0,63}[a-z0-9])?$'),
  kind text NOT NULL CHECK (kind IN ('skill','prompt-agent','mcp-server')),
  visibility text NOT NULL DEFAULT 'private' CHECK (visibility IN ('public','private')),
  repo_id uuid NOT NULL REFERENCES repos(id),
  summary text NOT NULL DEFAULT '',
  latest_published_version_id uuid,    -- denormalized pointer (FK added with agent_versions)
  quarantine_state text NOT NULL DEFAULT 'none'
    CHECK (quarantine_state IN ('none','quarantined','blocked')),
  auto_publish_tags boolean NOT NULL DEFAULT true,   -- post-receive submission
  search_tsv tsvector,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (namespace_id, name)
);
CREATE INDEX agents_namespace_idx ON agents(namespace_id);
CREATE INDEX agents_search_idx ON agents USING gin(search_tsv);
CREATE INDEX agents_name_trgm_idx ON agents USING gin (name gin_trgm_ops);

-- +goose StatementBegin
CREATE FUNCTION agents_search_tsv_update() RETURNS trigger AS $$
BEGIN
  NEW.search_tsv :=
    setweight(to_tsvector('english', NEW.name::text), 'A') ||
    setweight(to_tsvector('english', coalesce(NEW.summary, '')), 'B');
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

CREATE TRIGGER agents_search_tsv_trg
  BEFORE INSERT OR UPDATE OF name, summary ON agents
  FOR EACH ROW EXECUTE FUNCTION agents_search_tsv_update();

-- Per-agent grants: read < write < maintain < publish.
CREATE TABLE agent_user_grants (
  agent_id uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users(id),
  role text NOT NULL CHECK (role IN ('read','write','maintain','publish')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (agent_id, user_id)
);
CREATE TABLE agent_team_grants (
  agent_id uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  team_id uuid NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  role text NOT NULL CHECK (role IN ('read','write','maintain','publish')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (agent_id, team_id)
);

-- +goose Down
DROP TABLE IF EXISTS agent_team_grants;
DROP TABLE IF EXISTS agent_user_grants;
DROP TRIGGER IF EXISTS agents_search_tsv_trg ON agents;
DROP FUNCTION IF EXISTS agents_search_tsv_update();
DROP TABLE IF EXISTS agents;
DROP TABLE IF EXISTS repos;
