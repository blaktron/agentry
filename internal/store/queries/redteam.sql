-- Red-team reports: written by the scheduled job, read by the staff console.
-- Report-only; nothing on the publish path reads it.

-- name: InsertRedTeamReport :one
INSERT INTO redteam_reports (id, ruleset_semver, bundle_digest, fixtures, cases, evaded, report)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: ListRedTeamReports :many
SELECT * FROM redteam_reports ORDER BY created_at DESC, id DESC LIMIT $1;

-- name: LatestRedTeamReportForBundle :one
SELECT * FROM redteam_reports WHERE bundle_digest = $1 ORDER BY created_at DESC LIMIT 1;
