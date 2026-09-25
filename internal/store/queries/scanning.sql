-- Security pipeline persistence (M4/WG-H).

-- `inserted` distinguishes a brand-new semver from a re-registration of one
-- we already know: a NEW ruleset semver is what triggers the §8.7 rescan
-- sweep, and every process restart re-registers the bundle it embeds.
-- name: CreateRulesetRelease :one
INSERT INTO ruleset_releases (id, semver, bundle_digest, notes)
VALUES ($1, $2, $3, $4)
ON CONFLICT (semver) DO UPDATE SET bundle_digest = EXCLUDED.bundle_digest
RETURNING *, (xmax = 0) AS inserted;

-- name: GetRulesetBySemver :one
SELECT * FROM ruleset_releases WHERE semver = $1;

-- name: GetRulesetByID :one
SELECT * FROM ruleset_releases WHERE id = $1;

-- name: LatestRuleset :one
SELECT * FROM ruleset_releases ORDER BY published_at DESC LIMIT 1;

-- name: ListRulesetReleases :many
-- The staff console's release history (agentry#63), newest first.
SELECT * FROM ruleset_releases ORDER BY published_at DESC LIMIT 100;

-- name: CreateScanRun :one
INSERT INTO scan_runs (id, version_id, trigger, ruleset_release_id, policy_snapshot, judge_model, judge_prompt_hash, status)
VALUES ($1, $2, $3, $4, $5, $6, $7, 'running')
RETURNING *;

-- judge_prompt_hash is written here rather than at CreateScanRun: the run row
-- must exist before stages run (stage results reference it), and S5 only
-- reports which rubric version it used once it has run (§8.4.4).
-- The judge's token use is written the same way: known only once S5 ran,
-- NULL when the provider reported none. judge_model is re-stated at finish
-- with the value the report and the attestation carry, so a row created by
-- an earlier binary and resumed after an upgrade ends up agreeing with them
-- (agentry#321).
-- name: FinishScanRun :exec
UPDATE scan_runs
SET status = $2, finished_at = now(), report_digest = $3,
    judge_model = coalesce(sqlc.narg('judge_model'), judge_model),
    judge_prompt_hash = coalesce(sqlc.narg('judge_prompt_hash'), judge_prompt_hash),
    judge_prompt_tokens = coalesce(sqlc.narg('judge_prompt_tokens'), judge_prompt_tokens),
    judge_completion_tokens = coalesce(sqlc.narg('judge_completion_tokens'), judge_completion_tokens)
WHERE id = $1;

-- name: GetScanRun :one
SELECT * FROM scan_runs WHERE id = $1;

-- name: LatestScanRunForVersion :one
SELECT * FROM scan_runs WHERE version_id = $1 ORDER BY started_at DESC LIMIT 1;

-- name: UpsertStageResult :exec
INSERT INTO scan_stage_results (scan_run_id, scanner, status, detail)
VALUES ($1, $2, $3, $4)
ON CONFLICT (scan_run_id, scanner) DO UPDATE SET status = EXCLUDED.status, detail = EXCLUDED.detail, finished_at = now();

-- name: CountFindingsBySeverity :many
-- The finding counts a report carries, without loading the findings.
SELECT severity, count(*)::bigint AS count
FROM findings WHERE scan_run_id = $1
GROUP BY severity;

-- name: InsertFinding :one
INSERT INTO findings (id, scan_run_id, scanner, severity, confidence, title, file_path, line_start, line_end, excerpt, detail)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
RETURNING *;

-- Re-persisting a stage's findings: delete then insert, so a stage that runs
-- again (a retried job, an errored stage re-attempted) replaces its findings
-- rather than adding a second copy to the report a reviewer reads. Matches
-- both the bare stage id and its rule-qualified children ("S4/inj-001").
-- name: DeleteFindingsForScanner :exec
DELETE FROM findings
WHERE scan_run_id = $1 AND (scanner = $2 OR scanner LIKE $2 || '/%');

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
SELECT ri.*, av.version, av.status AS version_status, a.name AS agent_name, h.handle AS namespace
FROM review_items ri
JOIN agent_versions av ON av.id = ri.version_id
JOIN agents a ON a.id = av.agent_id
JOIN handles h ON h.id = a.namespace_id
WHERE ri.id = $1;

-- name: GetPendingReviewItemForVersion :one
SELECT * FROM review_items WHERE version_id = $1 AND state = 'pending';

-- A decision lands only on a pending item: a second reviewer acting on a
-- stale page gets no row and a conflict, never an overwrite of the first
-- decision (agentry#479 made that reachable: a handed-off approval leaves
-- its version in needs_review for a moment).
-- name: DecideReviewItem :execrows
UPDATE review_items SET state = $2, decided_by = $3, decided_at = now(), rationale = $4 WHERE id = $1 AND state = 'pending';

-- name: SetReviewPublishPending :exec
UPDATE review_items SET publish_pending = $2 WHERE id = $1;

-- name: ListReviewQueue :many
SELECT ri.*, av.version, av.status AS version_status, a.name AS agent_name, h.handle AS namespace
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

-- A published version with no attestation row is the shape a signing
-- failure after the transition used to leave (agentry#407); the attest
-- sweep signs each from its latest finished scan run.
-- name: ListPublishedVersionsWithoutAttestation :many
-- A version published without a scan (M21) has no attestation to backfill:
-- it attests nothing, and is left out here as it is by every sweep.
SELECT av.*
FROM agent_versions av
LEFT JOIN attestations at ON at.version_id = av.id
WHERE av.status = 'published' AND at.id IS NULL AND av.scan_status <> 'skipped'
ORDER BY av.id
LIMIT $1;

-- name: CountPublishedVersionsWithoutAttestation :one
SELECT count(*)
FROM agent_versions av
LEFT JOIN attestations at ON at.version_id = av.id
WHERE av.status = 'published' AND at.id IS NULL AND av.scan_status <> 'skipped';

-- name: CreateAdvisory :one
INSERT INTO advisories (id, agent_id, affected_versions, severity, summary, detail, published_at)
VALUES ($1, $2, $3, $4, $5, $6, now())
RETURNING *;

-- name: ListAdvisoriesForAgent :many
SELECT * FROM advisories WHERE agent_id = $1 ORDER BY published_at DESC;

-- name: ListAdvisoriesFeed :many
-- The global feed (agentry#24): published advisories against PUBLIC agents,
-- newest first, keyset-paged on (published_at, id) so the cursor is stable
-- while new advisories arrive at the head.
SELECT adv.*, h.handle AS namespace, a.name AS agent_name
FROM advisories adv
JOIN agents a ON a.id = adv.agent_id
JOIN handles h ON h.id = a.namespace_id
WHERE a.visibility = 'public' AND adv.published_at IS NOT NULL
  AND (sqlc.narg('before_time')::timestamptz IS NULL
       OR (adv.published_at, adv.id) < (sqlc.narg('before_time')::timestamptz, sqlc.narg('before_id')::uuid))
ORDER BY adv.published_at DESC, adv.id DESC
LIMIT $1;

-- name: GetAdvisoryPublic :one
-- Permalink (agentry#24): only advisories against public agents resolve.
SELECT adv.*, h.handle AS namespace, a.name AS agent_name
FROM advisories adv
JOIN agents a ON a.id = adv.agent_id
JOIN handles h ON h.id = a.namespace_id
WHERE adv.id = $1 AND a.visibility = 'public' AND adv.published_at IS NOT NULL;

-- Keyset, not LIMIT/OFFSET: the sweep quarantines rows out of `published` as
-- it goes, so an offset-paged sweep would pass over one not-yet-rescanned
-- version per row it acted on. The cursor is the primary key, which no
-- sweep action changes.
-- name: ListPublishedVersionsForRescan :many
-- A version published without a scan, and every version of an agent whose
-- administrator has set pipeline_skip, is not rescanned (M21): a rescan
-- would put a report on a version whose verdict is "unscanned", and the
-- flag says the organization has taken the pipeline off this agent.
SELECT av.id, av.agent_id, av.archive_digest, av.archive_key, av.archive_size, av.manifest, av.capabilities, a.modes, a.visibility
FROM agent_versions av JOIN agents a ON a.id = av.agent_id
WHERE av.status = 'published'
  AND av.scan_status <> 'skipped' AND NOT a.pipeline_skip
  AND (sqlc.narg('after')::uuid IS NULL OR av.id < sqlc.narg('after'))
ORDER BY av.id DESC
LIMIT $1;

-- Versions stuck mid-scan past the §7 30-minute cap. The watchdog routes
-- these to review: a scan job that died terminally must never leave a version
-- parked in `scanning` forever.
-- name: ListStuckScanningVersions :many
SELECT * FROM agent_versions
WHERE status = 'scanning' AND updated_at < $1
ORDER BY updated_at
LIMIT $2;

-- name: ListStuckSubmittedVersions :many
-- A git-tag submission recorded by a role that hands the archive write to
-- a worker (agentry#508) stays `submitted` until the worker stores it; one
-- still there past the cap was never stored.
SELECT * FROM agent_versions
WHERE status = 'submitted' AND source = 'git-tag' AND updated_at < $1
ORDER BY updated_at
LIMIT $2;

-- name: ListStageResults :many
SELECT * FROM scan_stage_results WHERE scan_run_id = $1;

-- name: RunningScanRunForVersion :one
SELECT * FROM scan_runs
WHERE version_id = $1 AND trigger = $2 AND status = 'running'
ORDER BY started_at DESC LIMIT 1;

-- name: GetScanResultCache :one
SELECT * FROM scan_result_cache
WHERE archive_digest = $1 AND scanner = $2 AND ruleset_release_id = $3;

-- name: UpsertScanResultCache :exec
INSERT INTO scan_result_cache (archive_digest, scanner, ruleset_release_id, findings)
VALUES ($1, $2, $3, $4)
ON CONFLICT (archive_digest, scanner, ruleset_release_id)
DO UPDATE SET findings = EXCLUDED.findings, created_at = now();

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

-- name: CountIPClusterSubmissions :one
-- S8's cluster axis (agentry#27): how many distinct accounts and how many
-- versions share this submitting-address hash in the last 24 hours.
SELECT count(DISTINCT submitted_by)::bigint AS accounts, count(*)::bigint AS versions
FROM agent_versions
WHERE submitter_ip_hash = $1 AND created_at >= now() - interval '24 hours';

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

-- Approvals a keyless role handed to the worker (agentry#479) whose version
-- has not been published yet: marked publish_pending, still approved, the
-- version still in needs_review. The same conditions PublishApproved
-- checks; the watchdog publishes them, so a lost enqueue delays a publish.
-- name: ListApprovedReviewsAwaitingPublish :many
SELECT ri.id FROM review_items ri
JOIN agent_versions v ON v.id = ri.version_id
WHERE ri.publish_pending
  AND ri.state = 'approved'
  AND v.status = 'needs_review'
  AND ri.decided_at < now() - sqlc.arg('grace')::interval
ORDER BY ri.decided_at
LIMIT 100;
