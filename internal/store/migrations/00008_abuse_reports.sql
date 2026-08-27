-- +goose Up
-- Abuse reports (§8.7 intake): the web "report" button and security@ intake
-- feed the platform review queue.
CREATE TABLE abuse_reports (
  id uuid PRIMARY KEY,
  agent_id uuid NOT NULL REFERENCES agents(id),
  version_id uuid REFERENCES agent_versions(id),
  reporter_id uuid REFERENCES users(id),
  category text NOT NULL CHECK (category IN
    ('malicious_content','hidden_instructions','credential_theft','typosquat','spam','license','other')),
  detail text NOT NULL,
  state text NOT NULL DEFAULT 'open' CHECK (state IN ('open','triaged','actioned','dismissed')),
  triaged_by uuid REFERENCES users(id),
  triaged_at timestamptz,
  resolution text,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX abuse_reports_agent_idx ON abuse_reports(agent_id, created_at DESC);
CREATE INDEX abuse_reports_open_idx ON abuse_reports(state, created_at) WHERE state = 'open';

-- +goose Down
DROP TABLE IF EXISTS abuse_reports;
