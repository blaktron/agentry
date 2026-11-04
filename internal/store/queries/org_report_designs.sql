-- An organization's house designs: up to ten report designs per
-- organization, each a theme document version 3 validated by
-- pkg/reportdesign first, with its images beside it, named uniquely within
-- the organization and with no default.

-- name: ListOrgReportDesigns :many
-- The organization's designs, oldest first, without their images: what a
-- console lists and a run's chooser reads.
SELECT id, org_id, document, created_at, updated_at,
       (logo IS NOT NULL)::boolean AS has_logo,
       (cover_image IS NOT NULL)::boolean AS has_cover_image,
       (custom_cover IS NOT NULL)::boolean AS has_custom_cover
FROM org_report_designs
WHERE org_id = $1
ORDER BY created_at, id;

-- name: CountOrgReportDesigns :one
SELECT count(*) FROM org_report_designs WHERE org_id = $1;

-- name: GetOrgReportDesign :one
-- One design of the organization's, with its images; another
-- organization's id is no rows.
SELECT * FROM org_report_designs WHERE org_id = $1 AND id = $2;

-- name: GetOrgReportDesignByName :one
-- The organization's design of a name, compared without regard to case,
-- with its images: what a run that names one reads.
SELECT * FROM org_report_designs WHERE org_id = $1 AND lower(document->>'name') = lower(sqlc.arg(name)::text);

-- name: CreateOrgReportDesign :one
INSERT INTO org_report_designs (org_id, document, logo, cover_image, cover_image_format, custom_cover)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: UpdateOrgReportDesignDocument :one
-- The document alone: the images stay, so a client that sends a document
-- without them cannot drop them by saving.
UPDATE org_report_designs SET document = $3, updated_at = now()
WHERE org_id = $1 AND id = $2
RETURNING *;

-- name: SetOrgReportDesignLogo :one
UPDATE org_report_designs SET logo = $3, updated_at = now()
WHERE org_id = $1 AND id = $2
RETURNING *;

-- name: ClearOrgReportDesignLogo :one
UPDATE org_report_designs SET logo = NULL, updated_at = now()
WHERE org_id = $1 AND id = $2
RETURNING *;

-- name: SetOrgReportDesignCoverImage :one
UPDATE org_report_designs SET cover_image = $3, cover_image_format = $4, updated_at = now()
WHERE org_id = $1 AND id = $2
RETURNING *;

-- name: ClearOrgReportDesignCoverImage :one
UPDATE org_report_designs SET cover_image = NULL, cover_image_format = NULL, updated_at = now()
WHERE org_id = $1 AND id = $2
RETURNING *;

-- name: SetOrgReportDesignCustomCover :one
UPDATE org_report_designs SET custom_cover = $3, updated_at = now()
WHERE org_id = $1 AND id = $2
RETURNING *;

-- name: ClearOrgReportDesignCustomCover :one
UPDATE org_report_designs SET custom_cover = NULL, updated_at = now()
WHERE org_id = $1 AND id = $2
RETURNING *;

-- name: DeleteOrgReportDesign :execrows
DELETE FROM org_report_designs WHERE org_id = $1 AND id = $2;

-- name: DeleteOrgReportDesigns :execrows
-- The organization's erasure: every design and every image of the
-- organization's go.
DELETE FROM org_report_designs WHERE org_id = $1;
