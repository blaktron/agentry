-- Agents, repos, and per-agent grants.

-- name: CreateRepo :one
INSERT INTO repos (id) VALUES ($1) RETURNING *;

-- name: CreateRepoWithBranch :one
-- A fork's repository row, on the origin's default branch so the copied
-- history keeps its trunk's name.
INSERT INTO repos (id, default_branch) VALUES ($1, $2) RETURNING *;

-- name: GetRepo :one
SELECT * FROM repos WHERE id = $1;

-- name: UpdateRepoOnPush :exec
UPDATE repos SET size_bytes = $2, last_push_at = now() WHERE id = $1;

-- name: CreateAgent :one
INSERT INTO agents (id, namespace_id, name, visibility, repo_id, summary, modes)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: CreateForkAgent :one
-- A fork's row: private, with its origin and the version it was taken from,
-- copying until a worker has copied the repository and submitted the first
-- version.
INSERT INTO agents (id, namespace_id, name, visibility, repo_id, summary, modes,
                    forked_from_agent_id, forked_from_version_id, forked_by, fork_state)
VALUES (@id, @namespace_id, @name, 'private', @repo_id, @summary, @modes,
        @forked_from_agent_id, @forked_from_version_id, @forked_by, 'copying')
RETURNING *;

-- name: SetForkState :execrows
-- The copy's outcome, from copying only: a fork that is ready or failed
-- stays so.
UPDATE agents SET fork_state = @fork_state, fork_detail = @fork_detail, updated_at = now()
WHERE id = @id AND fork_state = 'copying';

-- name: MarkForkReady :exec
-- A fork whose first version is recorded is ready, from copying or from a
-- failure the watchdog declared while the copy was still running.
UPDATE agents SET fork_state = 'ready', fork_detail = '', updated_at = now()
WHERE id = @id AND fork_state IN ('copying', 'failed');

-- name: ListStuckForks :many
-- Forks whose copy never finished (a job out of retries, a worker without
-- the git volume), for the watchdog.
SELECT id FROM agents
WHERE fork_state = 'copying' AND created_at < @created_before
ORDER BY created_at LIMIT @row_limit;

-- name: GetForkOrigin :one
-- What a fork's read says of its origin: the origin's path and the version
-- the fork was taken from, and whether the origin can still be read by anyone
-- (public, not deleted and not blocked), which is when a page may link it.
SELECT oh.handle AS origin_namespace, oa.name AS origin_name, ov.version AS origin_version,
       (oa.visibility = 'public' AND oa.deleted_at IS NULL AND oa.quarantine_state <> 'blocked')::boolean AS origin_public
FROM agents f
JOIN agents oa ON oa.id = f.forked_from_agent_id
JOIN handles oh ON oh.id = oa.namespace_id
JOIN agent_versions ov ON ov.id = f.forked_from_version_id
WHERE f.id = @id;

-- name: CountForks :one
-- How many forks an agent has: a count only, never which. A fork deleted as a
-- tombstone is not counted.
SELECT count(*) FROM agents WHERE forked_from_agent_id = sqlc.arg(id)::uuid AND deleted_at IS NULL;

-- name: GetAgentByPath :one
-- A deleted agent's tombstone is absent from every read path that asks for it
-- by name; include_deleted is the platform staff's door to it, for the trust
-- & safety actions, and the advisories' door for a caller proved to hold a
-- release of it. A fork carries its origin's namespace (the origin's
-- publisher) for the extension seam.
SELECT a.*, h.handle AS namespace, h.kind AS namespace_kind, r.default_branch, r.size_bytes,
       oa.namespace_id AS origin_namespace_id, oh.kind AS origin_namespace_kind
FROM agents a
JOIN handles h ON h.id = a.namespace_id
JOIN repos r ON r.id = a.repo_id
LEFT JOIN agents oa ON oa.id = a.forked_from_agent_id
LEFT JOIN handles oh ON oh.id = oa.namespace_id
WHERE h.handle = $1 AND a.name = $2
  AND (a.deleted_at IS NULL OR sqlc.arg(include_deleted)::boolean);

-- name: UpdateAgentSettings :exec
UPDATE agents SET
  summary = coalesce(sqlc.narg('summary'), summary),
  visibility = coalesce(sqlc.narg('visibility'), visibility),
  auto_publish_tags = coalesce(sqlc.narg('auto_publish_tags'), auto_publish_tags),
  allow_force_push = coalesce(sqlc.narg('allow_force_push'), allow_force_push),
  pipeline_skip = coalesce(sqlc.narg('pipeline_skip'), pipeline_skip),
  builtin = coalesce(sqlc.narg('builtin'), builtin),
  modes = coalesce(sqlc.narg('modes')::text[], modes),
  updated_at = now()
WHERE id = $1;

-- name: GetAgentForUpdate :one
-- The agent row under the row lock, with its namespace, for a decision that
-- must not race another writer of the row: the flag's refusals and the
-- private → public change, and the gate-skipping edge.
SELECT a.*, h.handle AS namespace, h.kind AS namespace_kind
FROM agents a JOIN handles h ON h.id = a.namespace_id
WHERE a.id = $1
FOR UPDATE OF a;

-- name: CountUnscannedVersionsStanding :one
-- The versions of an agent that were admitted without a scan and could still
-- be, or return to being, published: published, quarantined or blocked — a
-- reinstate walks the last two back to published. While one stands the agent
-- cannot become public, since only a version that passed the gate is ever
-- public; yanking is what ends it.
SELECT count(*)::bigint FROM agent_versions
WHERE agent_id = $1 AND scan_status = 'skipped'
  AND status IN ('published', 'quarantined', 'blocked');

-- name: ListAgentsByNamespace :many
-- A suspended or erased organization's agents are absent; the handler answers
-- 404 for the namespace before this runs, and the predicate keeps the listing
-- honest on its own. A deleted agent's tombstone is never listed. The
-- publisher's page searches (query: name and summary, case-folded), filters
-- by state (active, retired; empty is both) and by origin (forks: only, none;
-- empty is both) and sorts (name, newest, installs, submitted — the last
-- submission of any version); the trailing keys keep every ordering total.
SELECT a.*, h.handle AS namespace,
       coalesce(d.installs, 0)::bigint AS installs,
       ls.created_at AS last_submitted_at,
       oh.handle AS origin_namespace, oa.name AS origin_name, ov.version AS origin_version,
       (oa.visibility = 'public' AND oa.deleted_at IS NULL AND oa.quarantine_state <> 'blocked') AS origin_public,
       (SELECT count(*) FROM agents fk WHERE fk.forked_from_agent_id = a.id AND fk.deleted_at IS NULL)::bigint AS fork_count
FROM agents a JOIN handles h ON h.id = a.namespace_id
LEFT JOIN agents oa ON oa.id = a.forked_from_agent_id
LEFT JOIN handles oh ON oh.id = oa.namespace_id
LEFT JOIN agent_versions ov ON ov.id = a.forked_from_version_id
LEFT JOIN orgs o ON o.id = a.namespace_id
LEFT JOIN (
  SELECT agent_id, sum(installs) AS installs
  FROM download_stats WHERE day >= current_date - 30 GROUP BY agent_id
) d ON d.agent_id = a.id
LEFT JOIN agent_versions ls ON ls.id = (
  SELECT av.id FROM agent_versions av
  WHERE av.agent_id = a.id ORDER BY av.created_at DESC, av.id DESC LIMIT 1
)
WHERE h.handle = $1
  AND a.deleted_at IS NULL
  AND (a.visibility = 'public' OR sqlc.arg(include_private)::boolean)
  AND (h.kind <> 'org' OR o.state IN ('active','decommissioning'))
  AND (sqlc.arg(state)::text = ''
       OR (sqlc.arg(state)::text = 'active' AND a.retired_at IS NULL)
       OR (sqlc.arg(state)::text = 'retired' AND a.retired_at IS NOT NULL))
  AND (sqlc.arg(forks)::text = ''
       OR (sqlc.arg(forks)::text = 'only' AND a.forked_from_agent_id IS NOT NULL)
       OR (sqlc.arg(forks)::text = 'none' AND a.forked_from_agent_id IS NULL))
  AND (sqlc.arg(query)::text = ''
       OR a.name::text ILIKE '%' || sqlc.arg(query)::text || '%'
       OR a.summary ILIKE '%' || sqlc.arg(query)::text || '%')
ORDER BY
  CASE WHEN sqlc.arg(sort)::text = 'newest' THEN a.created_at END DESC NULLS LAST,
  CASE WHEN sqlc.arg(sort)::text = 'installs' THEN coalesce(d.installs, 0) END DESC NULLS LAST,
  CASE WHEN sqlc.arg(sort)::text = 'submitted' THEN ls.created_at END DESC NULLS LAST,
  a.name, a.id;

-- LockNamespace serialises the per-namespace counts — the agent quota and the
-- private-agent cap — inside the transaction that inserts or flips: the count
-- and the write commit together, as the seat cap's do under the org row's
-- lock.
-- name: LockNamespace :exec
SELECT id FROM handles WHERE id = $1 FOR UPDATE;

-- name: CountAgentsInNamespace :one
-- A deleted agent's tombstone holds its name, not a place in the quota.
SELECT count(*) FROM agents WHERE namespace_id = $1 AND deleted_at IS NULL;

-- The private-agent cap a subscription tier sets: what a namespace holds
-- today, so one more can be refused.
-- name: CountPrivateAgentsInNamespace :one
-- A retired agent and a deleted one's tombstone are private but put away:
-- neither takes a submission or runs for anyone, so neither holds a place
-- under the cap.
SELECT count(*) FROM agents
WHERE namespace_id = $1 AND visibility = 'private'
  AND retired_at IS NULL AND deleted_at IS NULL;

-- name: UpsertAgentUserGrant :exec
INSERT INTO agent_user_grants (agent_id, user_id, role) VALUES ($1, $2, $3)
ON CONFLICT (agent_id, user_id) DO UPDATE SET role = EXCLUDED.role, updated_at = now();

-- name: DeleteAgentUserGrant :execrows
DELETE FROM agent_user_grants WHERE agent_id = $1 AND user_id = $2;

-- name: UpsertAgentTeamGrant :exec
INSERT INTO agent_team_grants (agent_id, team_id, role) VALUES ($1, $2, $3)
ON CONFLICT (agent_id, team_id) DO UPDATE SET role = EXCLUDED.role, updated_at = now();

-- name: DeleteAgentTeamGrant :execrows
DELETE FROM agent_team_grants WHERE agent_id = $1 AND team_id = $2;

-- name: ListAgentGrants :many
SELECT 'user' AS kind, h.handle AS grantee, g.role
FROM agent_user_grants g JOIN handles h ON h.id = g.user_id
WHERE g.agent_id = $1
UNION ALL
SELECT 'team' AS kind, t.slug::citext AS grantee, g.role
FROM agent_team_grants g JOIN teams t ON t.id = g.team_id
WHERE g.agent_id = $1
ORDER BY kind, grantee;

-- name: GetAgentUserGrant :one
SELECT role FROM agent_user_grants WHERE agent_id = $1 AND user_id = $2;

-- name: ListAgentTeamGrantsForUser :many
SELECT g.role
FROM agent_team_grants g
JOIN team_members tm ON tm.team_id = g.team_id
WHERE g.agent_id = $1 AND tm.user_id = $2;

-- name: GetAgentByID :one
SELECT a.*, h.handle AS namespace, h.kind AS namespace_kind
FROM agents a JOIN handles h ON h.id = a.namespace_id
WHERE a.id = $1;

-- name: SetAgentQuarantineState :exec
UPDATE agents SET quarantine_state = $2, updated_at = now() WHERE id = $1;

-- name: SetAgentReadmeText :exec
-- Denormalizes the published version's README onto the agent so the weight-C
-- index has something to index (the tsvector trigger fires on this column).
-- Written on publish only: an agent's searchable description should follow
-- what people can actually install, not whatever the last submission happened
-- to contain.
UPDATE agents SET readme_text = $2, updated_at = now()
WHERE id = $1 AND readme_text IS DISTINCT FROM $2;

-- name: SearchAgents :many
-- Public FTS search: weighted tsvector + trigram fuzzy fallback on name,
-- ranked by relevance × install popularity × recency decay. The facets
-- (capability, license, verified) filter on the LATEST PUBLISHED version's
-- manifest/capabilities, so an agent's facets always describe what someone
-- would actually install today. `sort` picks the primary ordering; the
-- trailing keys keep every ordering total (stable pages).
SELECT a.id, a.name, a.modes, a.visibility, a.summary, a.quarantine_state,
       a.created_at, a.builtin, h.handle AS namespace,
       -- The publishing organization's logo key, for the badge beside its
       -- name on a hit; NULL for a person's namespace.
       o.logo_object_key,
       coalesce(d.installs, 0)::bigint AS installs,
       ts_rank_cd(a.search_tsv, websearch_to_tsquery('english', sqlc.arg(query)::text)) AS rank,
       -- relevance × log(1+installs_30d) × recency_decay, as one score so
       -- the ordering below is a single comparison rather than a
       -- lexicographic tie-break chain (which would never combine the three
       -- factors at all — it would just fall through from one to the next).
       --
       --   relevance  ts_rank_cd over the weighted tsvector (A name, B
       --              summary, C readme), floored by trigram similarity so a
       --              fuzzy name match does not score zero and vanish. An
       --              empty query scores 1: browsing is not searching, and
       --              every row should then be ordered by popularity × recency.
       --   popularity 1 + ln(1 + installs_30d). log(1+installs) taken
       --              literally is 0 for a zero-install agent and
       --              multiplies its whole score away, burying every new agent
       --              beneath every old one no matter how well it matches.
       --              The leading 1 makes popularity a multiplier of at least
       --              1 — it can promote, never annihilate.
       --   recency    1 / (1 + age_days / 180): half weight at ~6 months.
       --              The catalogue turns over on a scale of seasons, so a
       --              decay measured in days would churn the front page.
       (CASE WHEN sqlc.arg(query)::text = '' THEN 1.0
             ELSE greatest(
               ts_rank_cd(a.search_tsv, websearch_to_tsquery('english', sqlc.arg(query)::text))::double precision,
               similarity(a.name::text, sqlc.arg(query)::text)::double precision,
               -- handle matches rank by handle similarity: ts_rank is 0 for
               -- them (the handle is not in the tsvector) and they must not
               -- score zero and vanish below the popularity floor.
               similarity(h.handle::text, sqlc.arg(query)::text)::double precision)
        END
        * (1.0 + ln(1.0 + coalesce(d.installs, 0)::double precision))
        * (1.0 / (1.0 + (extract(epoch FROM (now() - a.created_at)) / 86400.0) / 180.0))
       )::double precision AS score
FROM agents a
JOIN handles h ON h.id = a.namespace_id
LEFT JOIN orgs o ON o.id = a.namespace_id
LEFT JOIN agent_versions lv ON lv.id = a.latest_published_version_id
LEFT JOIN (
  SELECT agent_id, sum(installs) AS installs
  FROM download_stats WHERE day >= current_date - 30 GROUP BY agent_id
) d ON d.agent_id = a.id
WHERE a.visibility = 'public'
  AND a.quarantine_state <> 'blocked'
  -- Only agents with something installable: a public agent whose every
  -- version is still in review (or which has none) is not a search result,
  -- a trending row, or a tag entry yet — browsing surfaces what can be
  -- installed, and "most installed" must not list the uninstallable.
  AND a.latest_published_version_id IS NOT NULL
  AND (
    sqlc.arg(query)::text = ''
    OR a.search_tsv @@ websearch_to_tsquery('english', sqlc.arg(query)::text)
    OR a.name::text % sqlc.arg(query)::text
    -- The namespace handle is not in search_tsv (the weights cover
    -- name/summary/readme), but "search for acme" finding acme's agents is
    -- table-stakes for a registry, and cli.sh publishes into a random
    -- namespace and then looks itself up by handle.
    OR h.handle = lower(sqlc.arg(query)::text)::citext
    OR h.handle::text % sqlc.arg(query)::text
  )
  -- mode= means "supports this run mode": one of the array's values.
  AND (sqlc.narg('mode')::text IS NULL OR sqlc.narg('mode')::text = ANY(a.modes))
  -- capability= means "this agent actually asks for it", not merely "the key
  -- is present": a manifest that says `network: {egress: none}` serializes
  -- with the network key set, so key existence alone would match every agent
  -- ever published. A capability counts when its value is not null/none/empty
  -- and, for object-valued ones, when at least one member is not.
  AND (sqlc.narg('capability')::text IS NULL OR (
        lv.capabilities IS NOT NULL
        AND jsonb_exists(lv.capabilities, sqlc.narg('capability')::text)
        AND lv.capabilities -> sqlc.narg('capability')::text
            NOT IN ('"none"'::jsonb, 'null'::jsonb, '[]'::jsonb, '{}'::jsonb)
        AND (jsonb_typeof(lv.capabilities -> sqlc.narg('capability')::text) <> 'object'
             OR EXISTS (
               SELECT 1 FROM jsonb_each(lv.capabilities -> sqlc.narg('capability')::text) AS cap_member(k, v)
               WHERE cap_member.v NOT IN ('"none"'::jsonb, 'null'::jsonb, '[]'::jsonb, '{}'::jsonb)))))
  AND (sqlc.narg('license')::text IS NULL
       OR lower(lv.manifest ->> 'license') = lower(sqlc.narg('license')::text))
  AND (sqlc.arg(verified_only)::boolean = false
       OR (h.kind = 'org' AND EXISTS (SELECT 1 FROM domain_claims dc WHERE dc.org_id = o.id AND dc.verified_at IS NOT NULL)))
  -- An organization that is suspended or erased is absent everywhere, its
  -- listings included; one in its decommission hold is read.
  AND (h.kind <> 'org' OR o.state IN ('active','decommissioning'))
ORDER BY
  CASE WHEN sqlc.arg(sort)::text = 'installs' THEN coalesce(d.installs, 0) END DESC NULLS LAST,
  CASE WHEN sqlc.arg(sort)::text = 'newest' THEN a.created_at END DESC NULLS LAST,
  score DESC,
  a.created_at DESC,
  a.id DESC
LIMIT $1 OFFSET $2;

-- name: CountSearchAgents :one
-- The number of hits SearchAgents would return for the same predicate before
-- LIMIT/OFFSET, so a client can say "2 of 8" truthfully. The WHERE clause is
-- SearchAgents' verbatim and the two must move together; the installs join is
-- absent because nothing in the predicate reads it.
SELECT count(*)::bigint
FROM agents a
JOIN handles h ON h.id = a.namespace_id
LEFT JOIN orgs o ON o.id = a.namespace_id
LEFT JOIN agent_versions lv ON lv.id = a.latest_published_version_id
WHERE a.visibility = 'public'
  AND a.quarantine_state <> 'blocked'
  -- Only agents with something installable: a public agent whose every
  -- version is still in review (or which has none) is not a search result,
  -- a trending row, or a tag entry yet — browsing surfaces what can be
  -- installed, and "most installed" must not list the uninstallable.
  AND a.latest_published_version_id IS NOT NULL
  AND (
    sqlc.arg(query)::text = ''
    OR a.search_tsv @@ websearch_to_tsquery('english', sqlc.arg(query)::text)
    OR a.name::text % sqlc.arg(query)::text
    -- The namespace handle is not in search_tsv (the weights cover
    -- name/summary/readme), but "search for acme" finding acme's agents is
    -- table-stakes for a registry, and cli.sh publishes into a random
    -- namespace and then looks itself up by handle.
    OR h.handle = lower(sqlc.arg(query)::text)::citext
    OR h.handle::text % sqlc.arg(query)::text
  )
  -- mode= means "supports this run mode": one of the array's values.
  AND (sqlc.narg('mode')::text IS NULL OR sqlc.narg('mode')::text = ANY(a.modes))
  -- capability= means "this agent actually asks for it", not merely "the key
  -- is present": a manifest that says `network: {egress: none}` serializes
  -- with the network key set, so key existence alone would match every agent
  -- ever published. A capability counts when its value is not null/none/empty
  -- and, for object-valued ones, when at least one member is not.
  AND (sqlc.narg('capability')::text IS NULL OR (
        lv.capabilities IS NOT NULL
        AND jsonb_exists(lv.capabilities, sqlc.narg('capability')::text)
        AND lv.capabilities -> sqlc.narg('capability')::text
            NOT IN ('"none"'::jsonb, 'null'::jsonb, '[]'::jsonb, '{}'::jsonb)
        AND (jsonb_typeof(lv.capabilities -> sqlc.narg('capability')::text) <> 'object'
             OR EXISTS (
               SELECT 1 FROM jsonb_each(lv.capabilities -> sqlc.narg('capability')::text) AS cap_member(k, v)
               WHERE cap_member.v NOT IN ('"none"'::jsonb, 'null'::jsonb, '[]'::jsonb, '{}'::jsonb)))))
  AND (sqlc.narg('license')::text IS NULL
       OR lower(lv.manifest ->> 'license') = lower(sqlc.narg('license')::text))
  AND (sqlc.arg(verified_only)::boolean = false
       OR (h.kind = 'org' AND EXISTS (SELECT 1 FROM domain_claims dc WHERE dc.org_id = o.id AND dc.verified_at IS NOT NULL)))
  -- An organization that is suspended or erased is absent everywhere, its
  -- listings included; one in its decommission hold is read.
  AND (h.kind <> 'org' OR o.state IN ('active','decommissioning'));

-- name: SearchFacetModes :many
-- One row per run mode with the number of public, unblocked agents that
-- support it; an agent supporting both counts under each.
SELECT m.mode::text AS mode, count(*)::bigint AS n
FROM agents a
JOIN handles h ON h.id = a.namespace_id
LEFT JOIN orgs o ON o.id = a.namespace_id, unnest(a.modes) AS m(mode)
WHERE a.visibility = 'public' AND a.quarantine_state <> 'blocked'
  AND (h.kind <> 'org' OR o.state IN ('active','decommissioning'))
  AND (sqlc.arg(query)::text = '' OR a.search_tsv @@ websearch_to_tsquery('english', sqlc.arg(query)::text))
GROUP BY m.mode ORDER BY m.mode;

-- name: SearchFacetLicenses :many
-- License facet over the same public corpus, read from the latest published
-- manifest (V7 requires an SPDX id for public publish).
SELECT (lv.manifest ->> 'license')::text AS license, count(*)::bigint AS n
FROM agents a
JOIN handles h ON h.id = a.namespace_id
LEFT JOIN orgs o ON o.id = a.namespace_id
JOIN agent_versions lv ON lv.id = a.latest_published_version_id
WHERE a.visibility = 'public' AND a.quarantine_state <> 'blocked'
  AND (h.kind <> 'org' OR o.state IN ('active','decommissioning'))
  AND lv.manifest ->> 'license' IS NOT NULL
  AND (sqlc.arg(query)::text = '' OR a.search_tsv @@ websearch_to_tsquery('english', sqlc.arg(query)::text))
GROUP BY 1 ORDER BY n DESC, 1 LIMIT 20;

-- name: ListAgentsByTag :many
-- GET /tags/{tag}: public agents whose LATEST PUBLISHED manifest carries the
-- tag (V8 tags are lowercase [a-z0-9-]). Keyset-paged on (created_at, id) so
-- the cursor is stable across inserts.
SELECT a.id, a.name, a.modes, a.summary, a.quarantine_state, a.created_at, a.builtin,
       h.handle AS namespace,
       coalesce(d.installs, 0)::bigint AS installs
FROM agents a
JOIN handles h ON h.id = a.namespace_id
LEFT JOIN orgs o ON o.id = a.namespace_id
JOIN agent_versions lv ON lv.id = a.latest_published_version_id
LEFT JOIN (
  SELECT agent_id, sum(installs) AS installs
  FROM download_stats WHERE day >= current_date - 30 GROUP BY agent_id
) d ON d.agent_id = a.id
WHERE a.visibility = 'public'
  AND a.quarantine_state <> 'blocked'
  AND (h.kind <> 'org' OR o.state IN ('active','decommissioning'))
  AND lv.manifest -> 'tags' @> to_jsonb(sqlc.arg(tag)::text)
  AND (sqlc.narg('before_time')::timestamptz IS NULL
       OR a.created_at < sqlc.narg('before_time')
       OR (a.created_at = sqlc.narg('before_time') AND a.id < sqlc.narg('before_id')))
ORDER BY a.created_at DESC, a.id DESC
LIMIT $1;

-- name: CountAgentDeleteBlockers :one
-- What DELETE /agents/{ns}/{name} must know. Version rows can never be
-- deleted, so an agent with any is deleted as a tombstone rather than
-- outright. Advisories and abuse reports are trust & safety records: they
-- outlive the author's wish to remove the agent.
SELECT
  (SELECT count(*) FROM agent_versions av WHERE av.agent_id = $1)::bigint AS versions,
  -- Versions the pipeline or a reviewer has yet to decide: a tombstone waits
  -- for them, so nothing is published onto a deleted agent.
  (SELECT count(*) FROM agent_versions av3 WHERE av3.agent_id = $1
     AND av3.status IN ('submitted', 'scanning', 'needs_review', 'approved'))::bigint AS versions_in_flight,
  (SELECT count(*) FROM advisories adv WHERE adv.agent_id = $1)::bigint AS advisories,
  (SELECT count(*) FROM abuse_reports ab WHERE ab.agent_id = $1)::bigint AS abuse_reports;

-- name: DeleteAgentByID :execrows
DELETE FROM agents WHERE id = $1;

-- name: DeleteRepoByID :exec
DELETE FROM repos WHERE id = $1;

-- name: RetireAgent :execrows
-- Retire: private, the visibility it had kept for Restore. Already retired,
-- nothing moves.
UPDATE agents SET retired_at = now(), retired_visibility = visibility,
  visibility = 'private', updated_at = now()
WHERE id = $1 AND retired_at IS NULL AND deleted_at IS NULL;

-- name: RestoreAgent :execrows
-- Restore: the visibility the agent had when it was retired. The caller has
-- decided, under the row lock, that it may hold it.
UPDATE agents SET visibility = retired_visibility, retired_at = NULL,
  retired_visibility = NULL, updated_at = now()
WHERE id = $1 AND retired_at IS NOT NULL AND deleted_at IS NULL;

-- name: TombstoneAgent :execrows
-- Delete of an agent with version history: the row stays as a tombstone,
-- private, taking no tag-push submissions.
UPDATE agents SET deleted_at = now(), visibility = 'private',
  auto_publish_tags = false, updated_at = now()
WHERE id = $1 AND deleted_at IS NULL;

-- name: SetAgentNamespace :exec
-- Moves an agent between namespaces (deletion with transfer).
UPDATE agents SET namespace_id = $2, updated_at = now() WHERE id = $1;
