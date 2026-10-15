-- +goose Up
-- Red-team reports: each scheduled run of the corpus rewrites against the
-- S3/S4 bundle stores its report here, report-only. Never a gate: nothing
-- reads this table on the publish path.
CREATE TABLE redteam_reports (
  id            uuid PRIMARY KEY,
  ruleset_semver text NOT NULL,
  bundle_digest text NOT NULL,
  fixtures      integer NOT NULL,
  cases         integer NOT NULL,
  evaded        integer NOT NULL,
  report        jsonb NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX redteam_reports_created_idx ON redteam_reports (created_at DESC);

-- +goose Down
DROP TABLE redteam_reports;
