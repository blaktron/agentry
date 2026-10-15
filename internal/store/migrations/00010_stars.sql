-- +goose Up
-- Stars: `stars (user_id, agent_id, PRIMARY KEY (user_id, agent_id))`, plus
-- foreign keys and created_at. Star counts must never outlive the rows they
-- point at (a deleted agent's stars would otherwise inflate the count of a
-- later agent reusing the id) and the UI wants "starred at".
CREATE TABLE stars (
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  agent_id uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, agent_id)
);
-- Counting an agent's stars is the hot read (agent page, stats endpoint).
CREATE INDEX stars_agent_idx ON stars(agent_id);

-- +goose Down
DROP TABLE IF EXISTS stars;
