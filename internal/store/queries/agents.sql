-- Agents, repos, and per-agent grants (M2/WG-C; grows in M3).

-- name: CreateRepo :one
INSERT INTO repos (id) VALUES ($1) RETURNING *;

-- name: GetRepo :one
SELECT * FROM repos WHERE id = $1;

-- name: UpdateRepoOnPush :exec
UPDATE repos SET size_bytes = $2, last_push_at = now() WHERE id = $1;

-- name: CreateAgent :one
INSERT INTO agents (id, namespace_id, name, kind, visibility, repo_id, summary, modes)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING *;

-- name: GetAgentByPath :one
SELECT a.*, h.handle AS namespace, h.kind AS namespace_kind, r.default_branch, r.size_bytes
FROM agents a
JOIN handles h ON h.id = a.namespace_id
JOIN repos r ON r.id = a.repo_id
WHERE h.handle = $1 AND a.name = $2;

-- name: UpdateAgentSettings :exec
UPDATE agents SET
  summary = coalesce(sqlc.narg('summary'), summary),
  visibility = coalesce(sqlc.narg('visibility'), visibility),
  auto_publish_tags = coalesce(sqlc.narg('auto_publish_tags'), auto_publish_tags),
  allow_force_push = coalesce(sqlc.narg('allow_force_push'), allow_force_push),
  modes = coalesce(sqlc.narg('modes')::text[], modes),
  updated_at = now()
WHERE id = $1;

-- name: ListAgentsByNamespace :many
SELECT a.*, h.handle AS namespace
FROM agents a JOIN handles h ON h.id = a.namespace_id
WHERE h.handle = $1
  AND (a.visibility = 'public' OR sqlc.arg(include_private)::boolean)
ORDER BY a.name;

-- name: CountAgentsInNamespace :one
SELECT count(*) FROM agents WHERE namespace_id = $1;

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
-- Denormalizes the published version's README onto the agent so the §10.4
-- weight-C index has something to index (the tsvector trigger fires on this
-- column). Written on publish only: an agent's searchable description should
-- follow what people can actually install, not whatever the last submission
-- happened to contain.
UPDATE agents SET readme_text = $2, updated_at = now()
WHERE id = $1 AND readme_text IS DISTINCT FROM $2;

-- name: SearchAgents :many
-- Public FTS search (§10.4, D-20): weighted tsvector + trigram fuzzy fallback
-- on name, ranked by relevance × install popularity × recency decay. The
-- §9.2 facets (capability, license, verified) filter on the LATEST PUBLISHED
-- version's manifest/capabilities, so an agent's facets always describe what
-- someone would actually install today. `sort` picks the primary ordering;
-- the trailing keys keep every ordering total (stable pages).
SELECT a.id, a.name, a.kind, a.visibility, a.summary, a.quarantine_state,
       a.created_at, h.handle AS namespace,
       coalesce(d.installs, 0)::bigint AS installs,
       ts_rank_cd(a.search_tsv, websearch_to_tsquery('english', sqlc.arg(query)::text)) AS rank,
       -- §10.4: relevance × log(1+installs_30d) × recency_decay, as one
       -- score so the ordering below is a single comparison rather than the
       -- lexicographic tie-break chain this used to be (which never combined
       -- the three factors at all — it just fell through from one to the next).
       --
       --   relevance  ts_rank_cd over the weighted tsvector (A name, B
       --              summary, C readme), floored by trigram similarity so a
       --              fuzzy name match does not score zero and vanish. An
       --              empty query scores 1: browsing is not searching, and
       --              every row should then be ordered by popularity × recency.
       --   popularity 1 + ln(1 + installs_30d). §10.4 writes log(1+installs);
       --              taken literally that is 0 for a zero-install agent and
       --              multiplies its whole score away, burying every new agent
       --              beneath every old one no matter how well it matches.
       --              The leading 1 makes popularity a multiplier of at least
       --              1 — it can promote, never annihilate. (DEV-030)
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
    -- The namespace handle is not in search_tsv (§10.4 weights cover
    -- name/summary/readme), but "search for acme" finding acme's agents is
    -- table-stakes for a registry — the pre-FTS CLI stopgap behaved that
    -- way, and m3-cli.sh publishes into a random namespace and then looks
    -- itself up by handle.
    OR h.handle = lower(sqlc.arg(query)::text)::citext
    OR h.handle::text % sqlc.arg(query)::text
  )
  AND (sqlc.narg('kind')::text IS NULL OR a.kind = sqlc.narg('kind'))
  -- mode= means "supports this run mode" (DEV-088): one of the array's values.
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
       OR (h.kind = 'org' AND o.verified_domain IS NOT NULL))
ORDER BY
  CASE WHEN sqlc.arg(sort)::text = 'installs' THEN coalesce(d.installs, 0) END DESC NULLS LAST,
  CASE WHEN sqlc.arg(sort)::text = 'newest' THEN a.created_at END DESC NULLS LAST,
  score DESC,
  a.created_at DESC,
  a.id DESC
LIMIT $1 OFFSET $2;

-- name: SearchFacetKinds :many
SELECT a.kind, count(*)::bigint AS n
FROM agents a
WHERE a.visibility = 'public' AND a.quarantine_state <> 'blocked'
  AND (sqlc.arg(query)::text = '' OR a.search_tsv @@ websearch_to_tsquery('english', sqlc.arg(query)::text))
GROUP BY a.kind ORDER BY a.kind;

-- name: SearchFacetModes :many
-- One row per run mode with the number of public, unblocked agents that
-- support it; an agent supporting both counts under each.
SELECT m.mode::text AS mode, count(*)::bigint AS n
FROM agents a, unnest(a.modes) AS m(mode)
WHERE a.visibility = 'public' AND a.quarantine_state <> 'blocked'
  AND (sqlc.arg(query)::text = '' OR a.search_tsv @@ websearch_to_tsquery('english', sqlc.arg(query)::text))
GROUP BY m.mode ORDER BY m.mode;

-- name: SearchFacetLicenses :many
-- License facet over the same public corpus, read from the latest published
-- manifest (V7 requires an SPDX id for public publish).
SELECT (lv.manifest ->> 'license')::text AS license, count(*)::bigint AS n
FROM agents a
JOIN agent_versions lv ON lv.id = a.latest_published_version_id
WHERE a.visibility = 'public' AND a.quarantine_state <> 'blocked'
  AND lv.manifest ->> 'license' IS NOT NULL
  AND (sqlc.arg(query)::text = '' OR a.search_tsv @@ websearch_to_tsquery('english', sqlc.arg(query)::text))
GROUP BY 1 ORDER BY n DESC, 1 LIMIT 20;

-- name: ListAgentsByTag :many
-- GET /tags/{tag} (§9.2): public agents whose LATEST PUBLISHED manifest
-- carries the tag (V8 tags are lowercase [a-z0-9-]). Keyset-paged on
-- (created_at, id) so the cursor is stable across inserts.
SELECT a.id, a.name, a.kind, a.summary, a.quarantine_state, a.created_at,
       h.handle AS namespace,
       coalesce(d.installs, 0)::bigint AS installs
FROM agents a
JOIN handles h ON h.id = a.namespace_id
JOIN agent_versions lv ON lv.id = a.latest_published_version_id
LEFT JOIN (
  SELECT agent_id, sum(installs) AS installs
  FROM download_stats WHERE day >= current_date - 30 GROUP BY agent_id
) d ON d.agent_id = a.id
WHERE a.visibility = 'public'
  AND a.quarantine_state <> 'blocked'
  AND lv.manifest -> 'tags' @> to_jsonb(sqlc.arg(tag)::text)
  AND (sqlc.narg('before_time')::timestamptz IS NULL
       OR a.created_at < sqlc.narg('before_time')
       OR (a.created_at = sqlc.narg('before_time') AND a.id < sqlc.narg('before_id')))
ORDER BY a.created_at DESC, a.id DESC
LIMIT $1;

-- name: CountAgentDeleteBlockers :one
-- Everything that makes DELETE /agents/{ns}/{name} unsafe (§9.2, §4.3).
-- Version rows can never be deleted, so ANY version row blocks the delete;
-- versions_past_submitted separates "never published" from "in flight" for
-- the error message. Advisories and abuse reports are trust & safety
-- records: they outlive the author's wish to remove the agent.
SELECT
  (SELECT count(*) FROM agent_versions av WHERE av.agent_id = $1)::bigint AS versions,
  (SELECT count(*) FROM agent_versions av2 WHERE av2.agent_id = $1 AND av2.status <> 'submitted')::bigint AS versions_past_submitted,
  (SELECT count(*) FROM advisories adv WHERE adv.agent_id = $1)::bigint AS advisories,
  (SELECT count(*) FROM abuse_reports ab WHERE ab.agent_id = $1)::bigint AS abuse_reports;

-- name: DeleteAgentByID :execrows
DELETE FROM agents WHERE id = $1;

-- name: DeleteRepoByID :exec
DELETE FROM repos WHERE id = $1;

-- name: SetAgentNamespace :exec
-- Moves an agent between namespaces (§12.7 deletion-with-transfer).
UPDATE agents SET namespace_id = $2, updated_at = now() WHERE id = $1;
