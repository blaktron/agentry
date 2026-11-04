-- The report design library: up to ten designs per account, each a theme
-- document version 3 validated by pkg/reportdesign first, with its images
-- beside it, and one of them the default.

-- name: ListUserReportDesigns :many
-- The account's designs, oldest first, without their images: what the
-- library page lists.
SELECT id, user_id, document, is_default, created_at, updated_at,
       (logo IS NOT NULL)::boolean AS has_logo,
       (cover_image IS NOT NULL)::boolean AS has_cover_image,
       (custom_cover IS NOT NULL)::boolean AS has_custom_cover
FROM user_report_designs
WHERE user_id = $1
ORDER BY created_at, id;

-- name: CountUserReportDesigns :one
SELECT count(*) FROM user_report_designs WHERE user_id = $1;

-- name: LockUserForReportDesigns :exec
-- Serializes an account's creates and default moves, so the library's bound
-- and its one default hold under two at once.
SELECT 1 FROM users WHERE id = $1 FOR UPDATE;

-- name: GetUserReportDesign :one
-- One design of the account's, with its images; another account's id is no
-- rows.
SELECT * FROM user_report_designs WHERE user_id = $1 AND id = $2;

-- name: GetUserReportDesignDefault :one
-- The account's default design, with its images; none is no rows.
SELECT * FROM user_report_designs WHERE user_id = $1 AND is_default;

-- name: CreateUserReportDesign :one
INSERT INTO user_report_designs (user_id, document, logo, cover_image, cover_image_format, custom_cover, is_default)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: UpdateUserReportDesignDocument :one
-- The document alone: the images stay, so a client that sends a document
-- without them cannot drop them by saving.
UPDATE user_report_designs SET document = $3, updated_at = now()
WHERE user_id = $1 AND id = $2
RETURNING *;

-- name: SetUserReportDesignLogo :one
UPDATE user_report_designs SET logo = $3, updated_at = now()
WHERE user_id = $1 AND id = $2
RETURNING *;

-- name: ClearUserReportDesignLogo :one
UPDATE user_report_designs SET logo = NULL, updated_at = now()
WHERE user_id = $1 AND id = $2
RETURNING *;

-- name: SetUserReportDesignCoverImage :one
UPDATE user_report_designs SET cover_image = $3, cover_image_format = $4, updated_at = now()
WHERE user_id = $1 AND id = $2
RETURNING *;

-- name: ClearUserReportDesignCoverImage :one
UPDATE user_report_designs SET cover_image = NULL, cover_image_format = NULL, updated_at = now()
WHERE user_id = $1 AND id = $2
RETURNING *;

-- name: SetUserReportDesignCustomCover :one
UPDATE user_report_designs SET custom_cover = $3, updated_at = now()
WHERE user_id = $1 AND id = $2
RETURNING *;

-- name: ClearUserReportDesignCustomCover :one
UPDATE user_report_designs SET custom_cover = NULL, updated_at = now()
WHERE user_id = $1 AND id = $2
RETURNING *;

-- name: ClearUserReportDesignDefault :execrows
-- No design is the default: a run falls through to the CLI's own choice.
UPDATE user_report_designs SET is_default = false
WHERE user_id = $1 AND is_default;

-- name: SetUserReportDesignDefault :execrows
-- Run after ClearUserReportDesignDefault in the same transaction; zero rows
-- is an id that is not the account's.
UPDATE user_report_designs SET is_default = true
WHERE user_id = $1 AND id = $2;

-- name: DeleteUserReportDesign :execrows
DELETE FROM user_report_designs WHERE user_id = $1 AND id = $2;

-- name: DeleteUserReportDesigns :execrows
-- Clear-data and the account's erasure: every design and every image of
-- the account's go.
DELETE FROM user_report_designs WHERE user_id = $1;
