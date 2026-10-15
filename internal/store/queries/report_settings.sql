-- The report design, a profile setting: the whole theme document version 2,
-- validated by pkg/reportdesign first, with its logo beside it (a PNG
-- pkg/reportdesign wrote).

-- name: GetUserReportSettings :one
SELECT * FROM user_report_settings WHERE user_id = $1;

-- name: UpsertUserReportSettings :one
-- The design alone: a logo already stored stays, so a client that does not
-- know logos cannot drop one by saving.
INSERT INTO user_report_settings (user_id, design)
VALUES ($1, $2)
ON CONFLICT (user_id) DO UPDATE SET design = EXCLUDED.design, updated_at = now()
RETURNING *;

-- name: UpsertUserReportSettingsWithLogo :one
-- The design and its logo together, from a design that carried one.
INSERT INTO user_report_settings (user_id, design, logo)
VALUES ($1, $2, $3)
ON CONFLICT (user_id) DO UPDATE SET design = EXCLUDED.design, logo = EXCLUDED.logo, updated_at = now()
RETURNING *;

-- name: SetUserReportLogo :one
-- No row (no design saved) is no rows: a logo needs a design to travel with.
UPDATE user_report_settings SET logo = $2, updated_at = now()
WHERE user_id = $1
RETURNING *;

-- name: ClearUserReportLogo :execrows
UPDATE user_report_settings SET logo = NULL, updated_at = now()
WHERE user_id = $1 AND logo IS NOT NULL;

-- name: DeleteUserReportSettings :execrows
-- A PUT that carries no design, clear-data and the account's erasure: no row
-- reads as never chosen, and the logo goes with it.
DELETE FROM user_report_settings WHERE user_id = $1;
