-- The report theme, a profile setting (agentry#989).

-- name: GetUserReportSettings :one
SELECT * FROM user_report_settings WHERE user_id = $1;

-- name: UpsertUserReportSettings :one
INSERT INTO user_report_settings (user_id, theme)
VALUES ($1, $2)
ON CONFLICT (user_id) DO UPDATE SET theme = EXCLUDED.theme, updated_at = now()
RETURNING *;

-- name: DeleteUserReportSettings :execrows
-- A PUT that names no theme, and clear-data (agentry#498): no row reads as
-- never chosen.
DELETE FROM user_report_settings WHERE user_id = $1;
