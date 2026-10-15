-- +goose Up
-- Unscanned private agents. An organization's administrator may set
-- pipeline_skip on a private agent of the organization's, behind the tier's
-- UnscannedAgents switch; a submission to it takes the one edge submitted →
-- published without a scan run, and the version records that it was never
-- scanned. The flag is refused on a public agent and in a personal namespace,
-- and an agent keeps a version published unscanned cannot become public: only
-- a version that passed the gate is ever public.
ALTER TABLE agents ADD COLUMN pipeline_skip boolean NOT NULL DEFAULT false;
-- The flag and public never meet in a row: the handler refuses each under
-- the agent's row lock, and this is the wall behind it.
ALTER TABLE agents ADD CONSTRAINT agents_pipeline_skip_private
  CHECK (NOT pipeline_skip OR visibility = 'private');

-- scan_status says how the version was admitted: through the pipeline
-- (every version before this migration, and every version of an agent
-- without the flag), or skipped — no run, no findings, no attestation,
-- served everywhere with the verdict "unscanned".
ALTER TABLE agent_versions ADD COLUMN scan_status text NOT NULL DEFAULT 'pipeline'
  CHECK (scan_status IN ('pipeline', 'skipped'));

-- +goose Down
ALTER TABLE agent_versions DROP COLUMN scan_status;
ALTER TABLE agents DROP CONSTRAINT agents_pipeline_skip_private;
ALTER TABLE agents DROP COLUMN pipeline_skip;
