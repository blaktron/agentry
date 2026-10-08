-- +goose Up
-- The report theme (plan scratch-and-pdf-reports.md §5 "Choosing the
-- theme", D13, D18, D21; agentry#989): the theme a person's PDF reports
-- take, a profile setting on the account, read by the desktop and the CLI
-- for a local run and carried by a hosted run's job. One row per user; no
-- row means the person never chose, which is not the same as choosing
-- Plain: a CLI run then falls to its own config, else Plain (D21). The
-- name is checked by the API against the built-in themes, not by a CHECK
-- here, so a later design standard is one more accepted value, not a
-- migration.
CREATE TABLE user_report_settings (
  user_id    uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  theme      text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE user_report_settings;
