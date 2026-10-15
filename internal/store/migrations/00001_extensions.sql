-- +goose Up
-- Extensions the schema relies on: citext for case-insensitive
-- handles/emails, pg_trgm for fuzzy name search.
CREATE EXTENSION IF NOT EXISTS citext;
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- +goose Down
DROP EXTENSION IF EXISTS pg_trgm;
DROP EXTENSION IF EXISTS citext;
