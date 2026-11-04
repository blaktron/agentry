-- +goose Up
-- An organization's house designs: up to ten report designs its admins keep
-- and its members pick for a run, each a theme document version 3 that
-- pkg/reportdesign validated before the API wrote it, with its images beside
-- it as a person's own design keeps them. A run picks one by the
-- organization's handle and the design's name, so names are unique within an
-- organization, compared without regard to case. There is no default: a
-- member picks a house design per run, and a run that picks none takes the
-- person's own default. The CHECKs are the API's own bounds again, under its
-- own.
CREATE TABLE org_report_designs (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id             uuid NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  document           jsonb NOT NULL
    CHECK (jsonb_typeof(document) = 'object' AND octet_length(document::text) <= 24576),
  logo               bytea CHECK (logo IS NULL OR octet_length(logo) <= 524288),
  cover_image        bytea CHECK (cover_image IS NULL OR octet_length(cover_image) <= 2097152),
  cover_image_format text CHECK (cover_image_format IS NULL OR cover_image_format IN ('png', 'jpeg')),
  custom_cover       jsonb
    CHECK (custom_cover IS NULL OR (jsonb_typeof(custom_cover) = 'object' AND octet_length(custom_cover::text) <= 3670016)),
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now(),
  CHECK ((cover_image IS NULL) = (cover_image_format IS NULL))
);
-- One design of a name per organization, since a run names one.
CREATE UNIQUE INDEX org_report_designs_name ON org_report_designs (org_id, lower(document->>'name'));
CREATE INDEX org_report_designs_org ON org_report_designs (org_id, created_at);

-- +goose Down
DROP TABLE org_report_designs;
