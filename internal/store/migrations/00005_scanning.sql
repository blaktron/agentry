-- +goose Up
-- Security pipeline: scan runs, findings, review queue, attestations,
-- policies, ruleset releases, advisories, and the durable job queue.

CREATE TABLE ruleset_releases (
  id uuid PRIMARY KEY,
  semver text UNIQUE NOT NULL,
  bundle_digest text NOT NULL,
  notes text,
  published_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE policies (                     -- platform baseline row has org_id NULL
  id uuid PRIMARY KEY,
  org_id uuid REFERENCES orgs(id) UNIQUE,
  document jsonb NOT NULL,
  version int NOT NULL DEFAULT 1,
  updated_at timestamptz NOT NULL DEFAULT now()
);
-- Exactly one platform baseline (org_id NULL).
CREATE UNIQUE INDEX policies_baseline_idx ON policies ((org_id IS NULL)) WHERE org_id IS NULL;

CREATE TABLE scan_runs (
  id uuid PRIMARY KEY,
  version_id uuid NOT NULL REFERENCES agent_versions(id),
  trigger text NOT NULL CHECK (trigger IN ('publish','rescan','manual')),
  ruleset_release_id uuid NOT NULL REFERENCES ruleset_releases(id),
  policy_snapshot jsonb NOT NULL,
  judge_model text,
  judge_prompt_hash text,
  status text NOT NULL DEFAULT 'running'
    CHECK (status IN ('running','passed','findings','error')),
  started_at timestamptz NOT NULL DEFAULT now(),
  finished_at timestamptz,
  report_digest text
);
CREATE INDEX scan_runs_version_idx ON scan_runs(version_id, started_at DESC);

-- Stage results, keyed for idempotency: (scan_run_id, scanner).
CREATE TABLE scan_stage_results (
  scan_run_id uuid NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
  scanner text NOT NULL,
  status text NOT NULL CHECK (status IN ('ok','error')),
  detail jsonb NOT NULL DEFAULT '{}',
  finished_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (scan_run_id, scanner)
);

CREATE TABLE findings (
  id uuid PRIMARY KEY,
  scan_run_id uuid NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
  scanner text NOT NULL,
  severity text NOT NULL CHECK (severity IN ('info','low','medium','high','critical')),
  confidence text NOT NULL CHECK (confidence IN ('low','medium','high')),
  title text NOT NULL,
  file_path text,
  line_start int,
  line_end int,
  excerpt text,
  detail jsonb NOT NULL DEFAULT '{}',
  verdict text NOT NULL DEFAULT 'open' CHECK (verdict IN
    ('open','confirmed','dismissed_false_positive','dismissed_accepted_risk')),
  verdict_by uuid REFERENCES users(id),
  verdict_reason text,
  verdict_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX findings_scan_run_idx ON findings(scan_run_id);

CREATE TABLE review_items (
  id uuid PRIMARY KEY,
  version_id uuid NOT NULL REFERENCES agent_versions(id),
  queue text NOT NULL CHECK (queue IN ('platform','org')),
  org_id uuid REFERENCES orgs(id),
  state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','approved','rejected')),
  decided_by uuid REFERENCES users(id),
  decided_at timestamptz,
  rationale text,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX review_items_queue_idx ON review_items(queue, state, created_at);
CREATE UNIQUE INDEX review_items_open_version_idx ON review_items(version_id) WHERE state = 'pending';

CREATE TABLE attestations (
  id uuid PRIMARY KEY,
  version_id uuid NOT NULL REFERENCES agent_versions(id),
  predicate_type text NOT NULL,
  dsse_envelope jsonb NOT NULL,
  key_id text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (version_id)                        -- signed exactly once
);

CREATE TABLE advisories (
  id uuid PRIMARY KEY,
  agent_id uuid NOT NULL REFERENCES agents(id),
  affected_versions text NOT NULL,
  severity text NOT NULL CHECK (severity IN ('info','low','medium','high','critical')),
  summary text NOT NULL,
  detail text,
  published_at timestamptz
);
CREATE INDEX advisories_agent_idx ON advisories(agent_id);

-- Durable job queue. A minimal SKIP LOCKED queue behind the internal/queue
-- interface. Kept deliberately small.
CREATE TABLE jobs (
  id uuid PRIMARY KEY,
  kind text NOT NULL,
  queue text NOT NULL DEFAULT 'core',
  args jsonb NOT NULL DEFAULT '{}',
  state text NOT NULL DEFAULT 'available'
    CHECK (state IN ('available','running','completed','failed')),
  attempt int NOT NULL DEFAULT 0,
  max_attempts int NOT NULL DEFAULT 5,
  last_error text,
  run_at timestamptz NOT NULL DEFAULT now(),
  locked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  finished_at timestamptz
);
CREATE INDEX jobs_poll_idx ON jobs(queue, state, run_at) WHERE state = 'available';

-- +goose Down
DROP TABLE IF EXISTS jobs;
DROP TABLE IF EXISTS advisories;
DROP TABLE IF EXISTS attestations;
DROP TABLE IF EXISTS review_items;
DROP TABLE IF EXISTS findings;
DROP TABLE IF EXISTS scan_stage_results;
DROP TABLE IF EXISTS scan_runs;
DROP TABLE IF EXISTS policies;
DROP TABLE IF EXISTS ruleset_releases;
