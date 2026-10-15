-- +goose Up
-- The jobs table was the SELECT … FOR UPDATE SKIP LOCKED queue's (00005).
-- River is the queue driver, so the table goes. Nothing writes it: the
-- recurring jobs' seeds count River's table. Any rows left behind are inert.
DROP TABLE jobs;

-- +goose Down
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
