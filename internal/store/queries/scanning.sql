-- Security pipeline persistence (M4/WG-H).

-- name: CreateRulesetRelease :one
INSERT INTO ruleset_releases (id, semver, bundle_digest, notes)
VALUES ($1, $2, $3, $4)
ON CONFLICT (semver) DO UPDATE SET bundle_digest = EXCLUDED.bundle_digest
RETURNING *;

-- name: GetRulesetBySemver :one
SELECT * FROM ruleset_releases WHERE semver = $1;

-- name: GetRulesetByID :one
SELECT * FROM ruleset_releases WHERE id = $1;

-- name: LatestRuleset :one
SELECT * FROM ruleset_releases ORDER BY published_at DESC LIMIT 1;

-- name: CreateScanRun :one
INSERT INTO scan_runs (id, version_id, trigger, ruleset_release_id, policy_snapshot, judge_model, judge_prompt_hash, status)
VALUES ($1, $2, $3, $4, $5, $6, $7, 'running')
RETURNING *;

-- name: FinishScanRun :exec
UPDATE scan_runs SET status = $2, finished_at = now(), report_digest = $3 WHERE id = $1;

-- name: GetScanRun :one
SELECT * FROM scan_runs WHERE id = $1;

-- name: LatestScanRunForVersion :one
SELECT * FROM scan_runs WHERE version_id = $1 ORDER BY started_at DESC LIMIT 1;

-- name: UpsertStageResult :exec
INSERT INTO scan_stage_results (scan_run_id, scanner, status, detail)
VALUES ($1, $2, $3, $4)
ON CONFLICT (scan_run_id, scanner) DO UPDATE SET status = EXCLUDED.status, detail = EXCLUDED.detail, finished_at = now();

-- name: InsertFinding :one
INSERT INTO findings (id, scan_run_id, scanner, severity, confidence, title, file_path, line_start, line_end, excerpt, detail)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
RETURNING *;

-- name: ListFindings :many
SELECT * FROM findings WHERE scan_run_id = $1 ORDER BY scanner, file_path, line_start;

-- name: ListOpenFindings :many
SELECT * FROM findings WHERE scan_run_id = $1 AND verdict = 'open' ORDER BY scanner;

-- name: GetFinding :one
SELECT * FROM findings WHERE id = $1;

-- name: SetFindingVerdict :exec
UPDATE findings SET verdict = $2, verdict_by = $3, verdict_reason = $4, verdict_at = now() WHERE id = $1;

-- name: CreateReviewItem :one
INSERT INTO review_items (id, version_id, queue, org_id, state)
VALUES ($1, $2, $3, $4, 'pending')
ON CONFLICT (version_id) WHERE state = 'pending' DO NOTHING
RETURNING *;

-- name: GetReviewItem :one
SELECT * FROM review_items WHERE id = $1;

-- name: GetReviewItemDetail :one
SELECT ri.*, av.version, a.name AS agent_name, h.handle AS namespace
FROM review_items ri
JOIN agent_versions av ON av.id = ri.version_id
JOIN agents a ON a.id = av.agent_id
JOIN handles h ON h.id = a.namespace_id
WHERE ri.id = $1;

-- name: GetPendingReviewItemForVersion :one
SELECT * FROM review_items WHERE version_id = $1 AND state = 'pending';

-- name: DecideReviewItem :exec
UPDATE review_items SET state = $2, decided_by = $3, decided_at = now(), rationale = $4 WHERE id = $1;

-- name: ListReviewQueue :many
SELECT ri.*, av.version, a.name AS agent_name, h.handle AS namespace
FROM review_items ri
JOIN agent_versions av ON av.id = ri.version_id
JOIN agents a ON a.id = av.agent_id
JOIN handles h ON h.id = a.namespace_id
WHERE ri.state = 'pending'
  AND (ri.queue = $1)
  AND (sqlc.narg('org_id')::uuid IS NULL OR ri.org_id = sqlc.narg('org_id'))
ORDER BY ri.created_at
LIMIT $2;

-- name: CreateAttestation :one
INSERT INTO attestations (id, version_id, predicate_type, dsse_envelope, key_id)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (version_id) DO NOTHING
RETURNING *;

-- name: GetAttestation :one
SELECT * FROM attestations WHERE version_id = $1;

-- name: CreateAdvisory :one
INSERT INTO advisories (id, agent_id, affected_versions, severity, summary, detail, published_at)
VALUES ($1, $2, $3, $4, $5, $6, now())
RETURNING *;

-- name: ListAdvisoriesForAgent :many
SELECT * FROM advisories WHERE agent_id = $1 ORDER BY published_at DESC;

-- name: ListPublishedVersionsForRescan :many
SELECT av.id, av.agent_id, av.archive_digest, av.archive_key, av.archive_size, av.manifest, av.capabilities, a.kind, a.visibility
FROM agent_versions av JOIN agents a ON a.id = av.agent_id
WHERE av.status = 'published'
ORDER BY av.published_at DESC
LIMIT $1 OFFSET $2;

-- name: GetPolicyForOrg :one
SELECT * FROM policies WHERE org_id = $1;

-- name: GetBaselinePolicy :one
SELECT * FROM policies WHERE org_id IS NULL;

-- name: UpsertBaselinePolicy :exec
INSERT INTO policies (id, org_id, document, version)
VALUES ($1, NULL, $2, 1)
ON CONFLICT ((org_id IS NULL)) WHERE org_id IS NULL
DO UPDATE SET document = EXCLUDED.document, version = policies.version + 1, updated_at = now();

-- name: UpsertOrgPolicy :exec
INSERT INTO policies (id, org_id, document, version)
VALUES ($1, $2, $3, 1)
ON CONFLICT (org_id) DO UPDATE SET document = EXCLUDED.document, version = policies.version + 1, updated_at = now();

-- name: GetPreviousPublishedVersion :one
SELECT * FROM agent_versions
WHERE agent_id = $1 AND status = 'published' AND id <> $2
ORDER BY published_at DESC LIMIT 1;

-- name: CountRecentVersionsBySubmitter :one
SELECT count(*) FROM agent_versions
WHERE submitted_by = $1 AND created_at >= now() - interval '7 days';

-- name: CreateAbuseReport :one
INSERT INTO abuse_reports (id, agent_id, version_id, reporter_id, category, detail)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: CountRecentAbuseReportsByReporter :one
SELECT count(*) FROM abuse_reports
WHERE reporter_id = $1 AND created_at >= now() - interval '1 hour';

-- name: ListAbuseReports :many
SELECT ar.*, a.name AS agent_name, h.handle AS namespace, av.version AS version
FROM abuse_reports ar
JOIN agents a ON a.id = ar.agent_id
JOIN handles h ON h.id = a.namespace_id
LEFT JOIN agent_versions av ON av.id = ar.version_id
WHERE ar.state = $1
ORDER BY ar.created_at
LIMIT $2;

-- name: GetAbuseReport :one
SELECT * FROM abuse_reports WHERE id = $1;

-- name: TriageAbuseReport :exec
UPDATE abuse_reports SET state = $2, triaged_by = $3, triaged_at = now(), resolution = $4 WHERE id = $1;
