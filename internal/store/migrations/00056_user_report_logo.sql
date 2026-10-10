-- +goose Up
-- The report design's logo (agentry-notes plans/report-designs.md §4 "The
-- logo", D9; agentry#1025): the PNG pkg/reportdesign wrote from a person's
-- upload, stored beside the design rather than in it, so the design keeps its
-- 16 KB bound (D11) and a client that does not know logos can still read and
-- replace the design without carrying or dropping the logo. NULL is no logo.
-- The CHECK is the API's 512 KB bound again.
ALTER TABLE user_report_settings
  ADD COLUMN logo bytea CHECK (logo IS NULL OR octet_length(logo) <= 524288);

-- +goose Down
ALTER TABLE user_report_settings DROP COLUMN logo;
