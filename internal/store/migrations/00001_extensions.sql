-- +goose Up
-- Extensions the schema relies on (PLAN §4.2): citext for case-insensitive
-- handles/emails, pg_trgm for fuzzy name search (§10.4, D-20).
CREATE EXTENSION IF NOT EXISTS citext;
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- +goose Down
DROP EXTENSION IF EXISTS pg_trgm;
DROP EXTENSION IF EXISTS citext;
