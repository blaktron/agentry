-- Agent versions + state machine.

-- name: CreateAgentVersion :one
INSERT INTO agent_versions (id, agent_id, version, commit_sha, manifest, capabilities, channel, submitted_by, source, submitter_ip_hash, draft_run)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
RETURNING *;

-- name: MarkVersionDrafterRevision :execrows
-- The scan proved the version's claimed draft: the source becomes
-- 'drafter-revision', with the S9 baseline it was proved against. Only once,
-- only while scanning, and only for a cli-upload that claimed a draft (the
-- immutability trigger holds the same edge).
UPDATE agent_versions SET source = 'drafter-revision', draft_baseline = $2, updated_at = now()
WHERE id = $1 AND status = 'scanning' AND source = 'cli-upload'
  AND draft_run IS NOT NULL AND draft_baseline IS NULL;

-- name: MarkVersionScanSkipped :execrows
-- The version was admitted without a scan: recorded in the same transaction
-- as the submitted → published edge, which refuses a version not so marked.
-- Only a submitted version is marked; the caller requires the one row, so a
-- version that has moved on is never marked.
UPDATE agent_versions SET scan_status = 'skipped', updated_at = now()
WHERE id = $1 AND status = 'submitted';

-- name: SetVersionArchive :exec
UPDATE agent_versions
SET archive_digest = $2, archive_key = $3, archive_size = $4, updated_at = now()
WHERE id = $1 AND status = 'submitted';

-- name: GetVersionForUpdate :one
SELECT * FROM agent_versions WHERE id = $1 FOR UPDATE;

-- name: GetVersion :one
SELECT * FROM agent_versions WHERE agent_id = $1 AND version = $2;

-- name: GetVersionByID :one
SELECT * FROM agent_versions WHERE id = $1;

-- name: SetVersionStatus :exec
UPDATE agent_versions
SET status = $2, status_reason = $3, updated_at = now(),
    published_at = CASE WHEN $2 = 'published' AND published_at IS NULL THEN now() ELSE published_at END,
    yanked_at   = CASE WHEN $2 = 'yanked' THEN now() ELSE yanked_at END,
    yank_reason = CASE WHEN $2 = 'yanked' THEN $4 ELSE yank_reason END
WHERE id = $1;

-- name: SetAgentLatestPublished :exec
UPDATE agents SET latest_published_version_id = $2, updated_at = now() WHERE id = $1;

-- name: RecomputeAgentLatestPublished :exec
UPDATE agents SET latest_published_version_id = (
  SELECT v.id FROM agent_versions v
  WHERE v.agent_id = agents.id AND v.status = 'published'
  ORDER BY v.published_at DESC LIMIT 1
), updated_at = now()
WHERE agents.id = $1;

-- name: ListVersions :many
SELECT * FROM agent_versions WHERE agent_id = $1 ORDER BY created_at DESC;

-- Resolution set: published resolves by range, yanked resolves only by exact
-- pin. quarantined and blocked are excluded here by construction — a version
-- the platform has disabled must never come back from a resolve.
-- name: ListResolvableVersions :many
SELECT * FROM agent_versions
WHERE agent_id = $1 AND status IN ('published','yanked')
ORDER BY created_at DESC;

-- name: ListVersionsByStatus :many
SELECT * FROM agent_versions
WHERE agent_id = $1 AND status = ANY(sqlc.arg('statuses')::text[])
ORDER BY created_at DESC;

-- name: CountVersionsToday :one
SELECT count(*) FROM agent_versions
WHERE agent_id = $1 AND created_at >= date_trunc('day', now());

-- name: CountPublishedVersions :one
SELECT count(*) FROM agent_versions WHERE agent_id = $1 AND status = 'published';

-- name: BumpDownloadStat :exec
INSERT INTO download_stats (agent_id, version_id, day, installs)
VALUES ($1, $2, current_date, 1)
ON CONFLICT (agent_id, version_id, day) DO UPDATE SET installs = download_stats.installs + 1;

-- name: SumDownloads :one
SELECT coalesce(sum(installs), 0)::bigint FROM download_stats WHERE agent_id = $1;
