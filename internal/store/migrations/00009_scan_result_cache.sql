-- +goose Up
-- Rescan results cache (§8.7): "skip unchanged rule↔digest pairs via a
-- results cache keyed (digest, scanner, ruleset)". A ruleset bump re-runs the
-- deterministic scanners over every published version; archives are
-- content-addressed, so the same bytes under the same scanner and the same
-- rule bundle can only produce the same findings. Caching that triple turns a
-- sweep of an unchanged catalogue into a table lookup.
--
-- The cached payload is the stage's findings as the pipeline models them
-- (scan.Finding JSON), not findings rows: rows belong to a scan_run, and a
-- cache hit means no stage ran for that run.
CREATE TABLE scan_result_cache (
  archive_digest text NOT NULL,
  scanner text NOT NULL,
  ruleset_release_id uuid NOT NULL REFERENCES ruleset_releases(id) ON DELETE CASCADE,
  findings jsonb NOT NULL DEFAULT '[]',
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (archive_digest, scanner, ruleset_release_id)
);
-- Eviction by ruleset generation (an old bundle's entries are dead weight).
CREATE INDEX scan_result_cache_ruleset_idx ON scan_result_cache(ruleset_release_id);

-- +goose Down
DROP TABLE IF EXISTS scan_result_cache;
