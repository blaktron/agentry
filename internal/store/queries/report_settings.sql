-- The report design, a profile setting (agentry#989; since agentry#1024 the
-- whole theme document version 2, validated by pkg/reportdesign first).

-- name: GetUserReportSettings :one
SELECT * FROM user_report_settings WHERE user_id = $1;

-- name: UpsertUserReportSettings :one
INSERT INTO user_report_settings (user_id, design)
VALUES ($1, $2)
ON CONFLICT (user_id) DO UPDATE SET design = EXCLUDED.design, updated_at = now()
RETURNING *;

-- name: DeleteUserReportSettings :execrows
-- A PUT that carries no design, and clear-data (agentry#498): no row reads
-- as never chosen.
DELETE FROM user_report_settings WHERE user_id = $1;
