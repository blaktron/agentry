-- Ruleset releases (POST /platform/ruleset-releases). The insert lives in
-- scanning.sql (the pipeline owns it); this is the read side the platform
-- endpoint needs to make re-registration idempotent.

-- name: GetRulesetReleaseBySemver :one
SELECT * FROM ruleset_releases WHERE semver = $1;
