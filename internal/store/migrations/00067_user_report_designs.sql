-- +goose Up
-- The report design library: an account keeps up to ten named designs, each
-- a theme document version 3 that pkg/reportdesign validated before the API
-- wrote it, with one of them the default a run takes when the person picks
-- none. The design's images live beside the document, outside its byte cap:
-- the logo (a PNG the core wrote from the upload), the cover image (a PNG or
-- a JPEG the core wrote, its format beside it) and the custom cover (its
-- Typst source, its images and its thumbnail, as one JSON object the API
-- validated). No row for an account, or no default among its rows, reads as
-- never chosen, which is not Plain. The CHECKs are the API's own bounds
-- again, under its own.
CREATE TABLE user_report_designs (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id            uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  document           jsonb NOT NULL
    CHECK (jsonb_typeof(document) = 'object' AND octet_length(document::text) <= 24576),
  logo               bytea CHECK (logo IS NULL OR octet_length(logo) <= 524288),
  cover_image        bytea CHECK (cover_image IS NULL OR octet_length(cover_image) <= 2097152),
  cover_image_format text CHECK (cover_image_format IS NULL OR cover_image_format IN ('png', 'jpeg')),
  custom_cover       jsonb
    CHECK (custom_cover IS NULL OR (jsonb_typeof(custom_cover) = 'object' AND octet_length(custom_cover::text) <= 3670016)),
  is_default         boolean NOT NULL DEFAULT false,
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now(),
  CHECK ((cover_image IS NULL) = (cover_image_format IS NULL))
);
-- One default per account.
CREATE UNIQUE INDEX user_report_designs_default ON user_report_designs (user_id) WHERE is_default;
CREATE INDEX user_report_designs_user ON user_report_designs (user_id, created_at);

-- Every version-2 design becomes the account's one default design, named as
-- it was, with the version-3 defaults that keep its look: no secondary, no
-- brand block, no header, the footer's line in its left slot, a cover in the
-- band style for a band title block and the framed style otherwise, drawn
-- for a long report as before, regular heading scale and margins. The logo
-- moves with it. A row that holds no version-2 document is dropped.
INSERT INTO user_report_designs (user_id, document, logo, is_default, created_at, updated_at)
SELECT
  user_id,
  jsonb_build_object(
    'agentryTheme', 3,
    'name', design->'name',
    'basedOn', design->'basedOn',
    'version', design->'version',
    'paper', design->'paper',
    'fonts', design->'fonts',
    'accent', design->'accent',
    'secondary', '',
    'titleBlock', design->'titleBlock',
    'headings', design->'headings',
    'headingScale', 'regular',
    'margins', 'regular',
    'tables', design->'tables',
    'quotes', design->'quotes',
    'brand', jsonb_build_object('name', '', 'strapline', '', 'contact', '[]'::jsonb, 'website', '', 'confidentiality', ''),
    'header', jsonb_build_object('style', 'none', 'slots', jsonb_build_array('', '', '')),
    'footer', jsonb_build_object('pageNumbers', design->'footer'->'pageNumbers', 'slots', jsonb_build_array(coalesce(design->'footer'->>'text', ''), '', '')),
    'cover', jsonb_build_object(
      'style', CASE WHEN design->>'titleBlock' = 'band' THEN 'band' ELSE 'framed' END,
      'shows', '["title", "subtitle", "author", "date"]'::jsonb,
      'when', 'long')
  ),
  logo,
  true,
  updated_at,
  updated_at
FROM user_report_settings
WHERE design->>'agentryTheme' = '2';

DROP TABLE user_report_settings;

-- +goose Down
-- The library does not go back to one setting: the default design's
-- version-3 document is not a version-2 one.
CREATE TABLE user_report_settings (
  user_id    uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  updated_at timestamptz NOT NULL DEFAULT now(),
  design     jsonb NOT NULL
    CHECK (jsonb_typeof(design) = 'object' AND octet_length(design::text) <= 16384),
  logo       bytea CHECK (logo IS NULL OR octet_length(logo) <= 524288)
);
DROP TABLE user_report_designs;
