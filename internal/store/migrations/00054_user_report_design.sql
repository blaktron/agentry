-- +goose Up
-- The report design (agentry-notes plans/report-designs.md §4 "Storage and
-- travel", D11, D16, D20; agentry#1024): the account stores the whole
-- design, a theme document version 2 that pkg/reportdesign validates before
-- the API writes it, in place of a built-in theme's name. The old names go
-- with no mapping, and so do the rows that hold them (D16, D20): an account
-- that chose a theme reads back as never chosen. Still one row per user, and
-- still no row for never chosen (DEV-227). The document is stored as the
-- canonical JSON the API wrote; the CHECK is the 16 KB bound again, under
-- the API's own.
DELETE FROM user_report_settings;
ALTER TABLE user_report_settings DROP COLUMN theme;
ALTER TABLE user_report_settings
  ADD COLUMN design jsonb NOT NULL
  CHECK (jsonb_typeof(design) = 'object' AND octet_length(design::text) <= 16384);

-- +goose Down
DELETE FROM user_report_settings;
ALTER TABLE user_report_settings DROP COLUMN design;
ALTER TABLE user_report_settings ADD COLUMN theme text NOT NULL;
