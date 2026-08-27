-- +goose Up
-- Agent versions + publication state machine (PLAN §4.2, §7; M3/WG-E).
-- Scan/review/attestation tables land with the M4 migration.

CREATE TABLE agent_versions (
  id uuid PRIMARY KEY,
  agent_id uuid NOT NULL REFERENCES agents(id),
  version text NOT NULL,
  commit_sha text NOT NULL DEFAULT '',
  manifest jsonb NOT NULL,
  capabilities jsonb NOT NULL DEFAULT '{}',
  archive_digest text,
  archive_key text,
  archive_size bigint,
  status text NOT NULL DEFAULT 'submitted' CHECK (status IN
    ('submitted','scanning','needs_review','approved','published',
     'rejected','yanked','quarantined','blocked')),
  status_reason text,
  published_at timestamptz,
  yanked_at timestamptz,
  yank_reason text,
  channel text NOT NULL DEFAULT 'stable' CHECK (channel IN ('stable','beta')),
  submitted_by uuid NOT NULL REFERENCES users(id),
  source text NOT NULL CHECK (source IN ('git-tag','cli-upload')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (agent_id, version)
);
CREATE INDEX agent_versions_agent_idx ON agent_versions(agent_id, created_at DESC);
CREATE INDEX agent_versions_status_idx ON agent_versions(status);
CREATE INDEX agent_versions_capabilities_idx ON agent_versions USING gin(capabilities);

ALTER TABLE agents
  ADD CONSTRAINT agents_latest_version_fk
  FOREIGN KEY (latest_published_version_id) REFERENCES agent_versions(id);

-- +goose StatementBegin
-- §4.3: version rows are immutable once past 'submitted' except the state
-- machine fields. Enforced with a trigger, not just app code.
CREATE FUNCTION agent_versions_enforce_immutability() RETURNS trigger AS $$
BEGIN
  IF OLD.status <> 'submitted' THEN
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

CREATE TRIGGER agent_versions_immutability
  BEFORE UPDATE ON agent_versions
  FOR EACH ROW EXECUTE FUNCTION agent_versions_enforce_immutability();

-- +goose StatementBegin
-- Version rows are never deleted (§4.3): yank hides, block disables.
CREATE FUNCTION agent_versions_block_delete() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'agent_versions rows are never deleted (yank or block instead)';
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

CREATE TRIGGER agent_versions_no_delete
  BEFORE DELETE ON agent_versions
  FOR EACH ROW EXECUTE FUNCTION agent_versions_block_delete();

CREATE TABLE download_stats (
  agent_id uuid NOT NULL,
  version_id uuid NOT NULL,
  day date NOT NULL,
  installs int NOT NULL DEFAULT 0,
  PRIMARY KEY (agent_id, version_id, day)
);

-- +goose Down
DROP TABLE IF EXISTS download_stats;
DROP TRIGGER IF EXISTS agent_versions_no_delete ON agent_versions;
DROP FUNCTION IF EXISTS agent_versions_block_delete();
DROP TRIGGER IF EXISTS agent_versions_immutability ON agent_versions;
DROP FUNCTION IF EXISTS agent_versions_enforce_immutability();
ALTER TABLE agents DROP CONSTRAINT IF EXISTS agents_latest_version_fk;
DROP TABLE IF EXISTS agent_versions;
