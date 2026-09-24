# Runbooks

The procedures an on-call operator needs. Each one opens with its trigger,
then the steps, and ends with the check that proves it worked.

Conventions: `agentryd` is the server binary; `$DB` is the database URL;
`psql "$DB"` assumes the app role. Anything destructive says so in bold.

---

## 1. Deploy and roll back

**Trigger:** a release is ready, or a release is misbehaving.

**Deploy.** Migrations run before the new code, and every migration in this
project is additive-or-compatible so old and new code can run side by side
during a rollout:

1. Review the infrastructure change first (`helm diff`, `docker compose
   config`, or the deployment's own plan step — the hosted service's
   Terraform lives with its site); a change that touches the database, the
   repo storage or the signing key stops here and gets a second pair of
   eyes.
2. Apply migrations: `agentryd migrate` (idempotent; takes a session lock, so
   a second concurrent run waits instead of racing).
3. Roll the services one at a time: `worker` first (it is the least
   user-visible), then `api`, `git`. A site in front rolls last, from its
   own repository.
4. Watch: 5xx rate, publish→verdict p95, queue age. Give it ten minutes.

**Roll back.** Code rolls back freely; **migrations do not**. Redeploy the
previous image tag and leave the schema alone. If a migration itself is the
problem, write a new forward migration. Never `goose down` in production.

**Verify:** `/readyz` green on every task, `publish→verdict` p50 back under
10 minutes, no new `S0/pipeline-error` findings.

---

## 2. Migration failure mid-deploy

**Trigger:** `agentryd migrate` exits non-zero, or tasks crash-loop on boot.

1. Read the goose error. It names the migration and the failing statement.
2. Check whether it partially applied:
   `psql "$DB" -c "select version_id, is_applied, tstamp from goose_db_version order by id desc limit 5"`.
3. If the failed migration did not apply, fix it forward and redeploy. If it
   partially applied (possible only for migrations with multiple statements
   outside a transaction), reconcile by hand in a transaction, then mark it:
   `psql "$DB" -c "insert into goose_db_version (version_id, is_applied) values (N, true)"`.
4. Old code keeps serving throughout. Do not scale to zero to "get a clean
   slate".

**Verify:** `agentryd migrate` is a no-op, tasks boot, `/readyz` green.

---

## 3. Queue stuck or poison job

**Trigger:** page on queue age > 15 minutes, or versions sitting in `scanning`.

The queue is River (`queue.driver: river`, the default) on the `river_job`
table; the `jobs` table belongs to the legacy `pg` driver and is empty on a
River deployment.

1. Depth and age by queue:
   ```sql
   select queue, state, count(*), min(scheduled_at) from river_job group by 1,2;
   ```
2. Are workers alive? `agentryd worker` logs a `worker started` line and then
   claims jobs; no claims for minutes with `available` rows means the workers
   are gone, not slow. Restart them.
3. Orphaned claims (a worker died holding jobs): River's rescuer returns a
   job whose worker stopped reporting to `available` on its own after the
   rescue interval; a job stuck in `running` past that is one to look at,
   not to edit.
4. Poison job (same job failing repeatedly):
   ```sql
   select id, kind, attempt, errors from river_job where state='discarded' order by finalized_at desc limit 20;
   ```
   Capture the last error, open a bug. A discarded scan job leaves its
   version in `scanning`. That is **fail-closed and correct**; the version is
   not published. The `scan.reconcile` job then moves any version older than
   30 minutes in `scanning` to review with an `S0/pipeline-error` finding, so
   a person decides; after the fix, re-submit the version rather than
   transitioning it by hand.

**Never** move a version to `published` in SQL to clear a backlog. The gate is
the product.

**Verify:** queue age falling, `available` count draining, no version older
than 30 minutes in `scanning`.

---

## 4. Quarantine wave (mass malicious publish)

**Trigger:** an abuse report cluster, an S8 publisher-anomaly spike, or a
rescan sweep surfacing many new high findings at once. The ClawHavoc pattern
is hundreds of malicious agents from a handful of accounts, so assume the
blast radius is an *account cluster*, not one agent.

**A rescan sweep is now the most likely way you find out.** Registering a new
ruleset release enqueues the §8.7 catalogue sweep automatically; you do not
schedule it. Shipping detection for a live technique surfaces every
already-published version that trips it, all at once. Expect a wave of
quarantines after a rule that matters lands, and read it as the system
working rather than as an incident of its own. (Sweeps used to need
triggering by hand, which meant new detection sat unapplied; the 2026-08-29
remediation fixed that.)

S8's publisher-behaviour signal covers **account age × publish velocity**
and, since DEV-026.1, the **IP cluster** half of §8.3 (`S8/ip-cluster`: three
or more accounts, or ten or more versions, publishing from one keyed IP hash
within 24 hours). The actual ClawHavoc incident (1,184 skills from 12
accounts) turned on that axis; the finding narrows step 1 below, it does not
replace it.

1. **Scope it before acting.** Find the cluster:
   ```sql
   -- recent publishes by account, newest first
   select u.id, h.handle, count(*) as versions, min(av.created_at) as first_seen
   from agent_versions av
   join users u on u.id = av.submitted_by
   join handles h on h.id = u.id
   where av.created_at > now() - interval '48 hours'
   group by 1,2 order by versions desc limit 50;
   ```
   Look for shared signals: account age, IP, naming pattern, identical
   findings.
2. **Stop the inflow first.** Suspend the accounts (`update users set
   state='suspended' where id in (…)`). This kills sessions and PATs on next
   use. New publishes stop; existing content is untouched.
3. **Quarantine, then block.** Quarantine is reversible: it stops resolution
   and refuses direct downloads with `409`. Block is for confirmed malware and
   returns **`410 Gone`** on every download of that agent or version, which
   is now true in fact and not only on paper. Work through the API
   (`POST /platform/agents/{ns}/{name}/quarantine`, then `.../block`) so every
   action is audited with a reason, not in SQL. Until the 2026-08-29
   remediation, `block` set the agent's quarantine state and nothing else, so
   a blocked agent kept serving `200`s and its archive stayed downloadable;
   the `410` branch was unreachable code. If you ran this runbook before that
   fix, **re-check anything you blocked**; it may still be downloadable.
4. **Publish one advisory per affected agent** (or one covering the cluster,
   referenced from each). Consumers who already installed are reached by
   advisory + webhook, not by any push we control.
5. **Write the timeline as you go.** Who, what, when, and what signal caught
   it. This becomes the postmortem and, usually, the next S8 rule.

**Dual control:** `blocked` should be set by a second platform admin, not the
one who quarantined. If you are alone, block anyway and get review after.

**Verify:** no new versions from the cluster; quarantined/blocked states
reflected on the agent pages; **an actual `curl` of a blocked version's
download URL returns `410`** (verify the effect, not the state column;
that is the exact failure that hid here once); advisories visible; audit
trail complete.

---

## 5. Signing-key rotation

**Trigger:** scheduled rotation, suspected exposure, or a KMS `Sign` anomaly
alert.

Clients pin what they have seen (TOFU), so a rotation is visible to every
installed client: at its next login it is told the advertised key ids
changed. What a rotation does **not** do any more is orphan what the old key
signed. The registry records the public part of every key it signs with
(`signing_keys`); the outgoing key stays in
`/.well-known/agentry/signing-keys.json` with `status: retired` for as long
as an attestation carries its signature; and a start on a key that some
attestation lacks queues `scan.reattest_sweep`, which appends the new key's
countersignature to each of those attestations (the statement is checked
against its release first and never changed). A client that pins today
verifies everything; a client that pinned the old key keeps verifying the
original signatures.

1. Create the new key (your KMS or a new file key; on the hosted deployment
   the site's Terraform, `modules/kms`). Keep the old key material: an
   attestation it signed stays verifiable through its own signature for
   clients that pinned it, and **never schedule deletion of a key that
   signed a published version**.
2. Point signing at the new key (`AGENTRY_SIGNING_KMS_KEY_ARN`, or the file
   key) and roll the role that holds it: the worker (`all`, on compose). The
   api and git roles hold no key and need no restart: they read the active
   key and the ruleset attestation from what the worker recorded at start
   (agentry#479), within the key set's five-minute cache. At start the log
   reads `attestations
   lack the signing key; re-attestation sweep enqueued` with the count; the
   worker then logs `re-attestation sweep complete` with how many it signed.
   A start on a key every attestation already carries logs nothing.
3. Check: the key set lists the new key as `active` and the old one as
   `retired` with its date (`curl -s …/.well-known/agentry/signing-keys.json`);
   `SELECT count(*) FROM attestations WHERE NOT (dsse_envelope->'signatures'
   @> '[{"keyid":"<new key id>"}]')` is zero. A count that stays above zero
   after the sweep names rows the sweep would not sign — the log line
   `re-attest: not signed` says why for each (a statement that does not
   describe its release is a corrupted row, not something to vouch for).
   The next start queues the sweep again for whatever is still pending.
4. `signing.additionalKeys` is still honoured for a key the registry has no
   record of (one that signed before the record existed, or a verification
   key from elsewhere); a configured key the registry also has on record
   carries the record's status. Nothing needs removing later: a retired key
   drops out of the set by itself once no attestation carries its signature.

**If the key is suspected compromised:** rotate immediately as above, then
audit `kms:Sign` calls against the pipeline's own signing and the sweep, and
diff the `attestations` table against `agent_versions` where
`status='published'`. Any attestation without a matching published version
is a forgery signal; so is a signature by the compromised key dated after
the rotation. Publish a security advisory; do not quietly rotate. A
compromised key stays advertised as retired — its old signatures are still
what clients that pinned it verify against — and the advisory is what tells
them to re-pin.

**Verify:** `agentry verify` succeeds against a pre-rotation version from a
freshly logged-in client (pins the new set), and against both a pre- and a
post-rotation version from a client that pinned the old key and re-pinned
after the warning.

---

## 6. Database restore (point in time)

**Trigger:** data loss or corruption. RPO 15 minutes, RTO 4 hours (§13.6).

1. Stop writes: scale `api`, `git`, and `worker` to zero. Leave the edge (and
   a site in front) up: it will show errors, which is better than silent
   divergence.
2. Restore to a new instance at the chosen timestamp — from your Postgres
   backups, or on the AWS reference deployment `aws rds
   restore-db-instance-to-point-in-time`. Never restore over the live one.
3. Point the app at the restored endpoint, run `agentryd migrate` (no-op if
   the restore is post-migration), scale `api`/`worker` back up.
4. Reconcile object storage: S3 release archives are content-addressed and
   write-once, so they are ahead of, never behind, the database. Any archive
   whose version row vanished in the restore is unreferenced garbage.
   Leave it. Conversely, a version row referencing a missing archive means the
   restore went *back past* a publish: those versions are broken and must be
   quarantined, not silently served:
   ```sql
   -- versions whose archive key no longer resolves need checking by hand
   select id, agent_id, version, archive_key from agent_versions
   where status='published' order by published_at desc limit 100;
   ```
5. Announce the restore window on the status page; publishes inside it were
   lost and authors must re-publish (version strings are burned, so they need
   a new version number; say so explicitly).

**Verify:** `/readyz` green, a test publish reaches `published`, `agentry
verify` passes on a pre-incident version.

**On the Vultr production** (Vultr Managed Databases, plan
`production-on-vultr.md` D7/D13; agentry-web#212): the point-in-time history
is the managed service's own, and the call that restores from it to a new
cluster is its **fork**. Give it the source database, a label, the plan, the
region, `type: pitr`, and a date and time; the result is a new cluster with
production's roles and passwords. Allowlist it before anything connects.
Point the DSN (terraform's `agentry-app` Secret) at the fork, or restore in
place with the service's restore call once the fork has shown that the
chosen time is right. The history covers two days on the Startup plan and
fourteen on Business. It lives in the same region as the database, so it
does not survive the loss of that region. Two scripts, both in agentry-web:
- `scripts/dr/pitr-fork.sh` proves the recovery. It forks to a chosen second
  between two audited requests and checks that the fork holds the first and
  not the second.
- `scripts/dr/drill.sh` runs the whole restore beside production. Its runs
  and times are in agentry-web's `docs/ops/deployment.md`, "Production on
  Vultr: backups and the restore drill".

---

## 7. Repo storage restore

**Trigger:** git repos missing or corrupt.

1. Repos are keyed by immutable UUID (`repos.id`), so a restore never has to
   guess ownership.
2. Restore the storage snapshot (the volume's own snapshot; on the AWS
   reference deployment the EFS recovery point from AWS Backup) to a new
   file system, mount it read-only alongside, and copy only the affected
   `{uuid[0:2]}/{uuid}.git` directories back.
3. A missing repo is recoverable from any clone: `git push --mirror`. Release
   archives are **not** affected by EFS loss; they live in S3 and are what
   consumers download. Published versions keep working through a total repo
   loss; only pushes and new git-tag publishes break.

**Verify:** `git clone` of an affected agent works; `agentry install` of its
published version was never affected.

**On the Vultr production** the repositories are on a Vultr File System
claim, of which Vultr states no snapshot. The nightly `backup-git` job
(agentry-web's umbrella chart) copies each repository to the backup bucket in
a second region, as a `git bundle --all` with the repository's `config`,
`HEAD` and pre-receive shim beside it, and the git role's SSH host key. To
restore a repository, stop the git role and run agentry-web's
`scripts/dr/restore-git.yaml` Job pointed at the claim. It makes each
repository as `InitBare` would (`git init --bare`, then the saved config,
`HEAD` and shim), fetches the bundle and checks connectivity. The copy is
nightly, so the RPO is a day: pushes since the last bundle come back only
from a clone.

---

## 8. Abuse and DDoS response

**Trigger:** WAF block spike, anonymous rate-limit saturation, or a report
flood.

1. Identify the shape: per-IP flood (WAF rate rules), distributed scraping of
   `/search` (cache and raise the anonymous limit), or targeted publish abuse
   (see §4 quarantine wave).
2. Cheap levers first: WAF rate rule threshold, `AGENTRY_LIMITS_*` anonymous
   limits, CloudFront caching on public GETs. Release downloads are
   content-addressed and CDN-cached, so they should never be the bottleneck;
   if they are, check that `Cache-Control: immutable` is surviving.
3. Do not disable authentication rate limits to "reduce load"; login is the
   endpoint you least want unthrottled.

**Verify:** 5xx back to baseline, publish pipeline unaffected, no legitimate
publisher locked out (check `user.login_failed` audit volume by handle).

---

## 9. GDPR erasure request

**Trigger:** a verified account-owner request.

1. The self-service path is `POST /api/v1/user/delete`. Prefer it; it is
   audited and transactional.
2. It purges PII, pseudonymizes the account, retires the handle (reserved, not
   recycled), revokes every credential, and disposes of published public
   versions **without ever deleting them**: consumers who already installed
   keep a verifiable artifact, which is the §5.5 contract. Explain this to the
   requester; it is a lawful-interest position, not an oversight.
3. **The requester must choose a disposition.** If the account has any
   published public versions, the call requires `publishedContent=yank` or
   `publishedContent=transfer` (the latter also needs
   `transferOrg=<org handle>`, and the caller must be an owner or admin
   there); without it the request is refused with `400` naming the count.
   There is no default. It used to silently default to `yank`, so nobody
   asked the requester. Ask before you run it, and record the answer.
4. If they insist published bytes be removed, that is a `blocked` decision by
   trust & safety with a written rationale, not an erasure step.
5. Audit events keep the opaque user id. Do not delete audit rows; the table
   rejects it at the database level anyway.
6. The directory half (the sign-in account in authentik) follows the
   registry erasure. When the directory is unreachable the response says
   `"directoryErasure": "pending"` and a worker job retries for about four
   and a half hours. A `failopen.directory_erasure` line (or a
   `FailOpenEvents{path="directory_erasure"}` increment, or a
   `user.directory_erase` audit row with `abandoned`) means it gave up:
   delete the authentik user with the account's former address by hand
   (the requester supplies it; the registry no longer holds it), and never
   a superuser or a service account.

**Verify:** the account cannot log in, the handle shows as retired, published
versions read `yanked` (or are owned by the destination org, if the requester
chose `transfer`), and a `user.delete` audit event exists recording the
disposition.

---

## 10. Security disclosure intake

**Trigger:** a report to `security@`.

1. Acknowledge within 2 business days (SECURITY.md promises it).
2. Reproduce on a scratch instance, never production. Never paste reporter
   proof-of-concept content into a production publish.
3. Severity by what it bypasses: publication gate, authorization, or signing
   are automatically high or critical.
4. Fix forward with a regression test. For scanner evasion, that means a new
   fixture pair in `testdata/attack-corpus/` so it can never silently return.
5. Ship, then publish the advisory with credit.

**Verify:** the regression test fails on the old code and passes on the new.

---

## 11. Directory service unavailable or misconfigured

**Trigger:** sign-in fails or loops, `/ui/login?error=…` (or the site's
`/login?error=…`), sign-out lands on a second login screen, or the
account page's password/authenticator actions error.
Existing registry sessions and PATs keep working throughout — the directory
is consulted at sign-in, not per request — so the API is not down; people
cannot sign in.

1. Is authentik up? `curl -fsS https://auth.<site>/-/health/ready/` and
   `docker compose ps authentik-server authentik-worker`. A crash loop
   after an upgrade that says "Major version skips are not allowed" is the
   release-line rule in the self-hosting guide: step through each line.
2. Did the blueprint apply? Authentik's admin console → Customisation →
   Blueprints: "Agentry - Account flows" must be *successful*, and
   the `agentry-invalidation` flow must exist. A blueprint that fails to
   apply names the offending entry in the worker log.
3. Is the registry's OIDC client still what authentik has? Re-run
   `scripts/dev/authentik-bootstrap.sh` (idempotent): it restores the
   provider's redirect URIs (authorization *and* logout), the scope
   mappings, its one grant (the authorization code; a provider with none
   answers every sign-in with `invalid_request`, agentry#494), the
   application's launch URL, and the brand's default
   application and unset user-settings flow — everything a deployment that
   predates agentry#164 lacks. It needs `AGENTRY_PUBLIC_WEB_URL` and the
   bootstrap token from `.env`; read individual keys from that file rather
   than `source`-ing it (values with spaces are not shell-quoted).
4. Do the containers know where to return? `AGENTRY_PUBLIC_WEB_URL` (sign-out)
   and `AGENTRY_ACCOUNT_URL` (password and authenticator changes) must reach
   the `authentik-*` containers (compose passes them through, defaulting to
   the server's own `/ui/` pages; a site's overlay sets its own); the
   account-flows blueprint formats them into sign-out's redirect stage and
   the settings flows' return-to-settings policy (DEV-118). After changing
   them, recreate the authentik containers, not the registry alone.
5. A user who cannot complete MFA is an operator action in the authentik
   admin console (`/if/admin/` still serves); email alone never resets both
   factors.

**Verify:** `GET https://<host>/api/v1/auth/oidc/authentik/start?next=%2Fui%2Faccount`
(or the site's dashboard path) in a browser ends on that page with no
directory screen in between; `https://auth.<host>/` answers 302 to the
registry's home (`/ui/`, or the site); the provider's end-session URL lands
in the `agentry-invalidation` flow whose first challenge (the executor API)
is a redirect to the same home.

---

## 12. Dependency alert wave (a popular MCP server gets a CVE)

**Trigger:** `McpDependencyAlertsOpened` jumps in one sweep, authors write in
about the "Package issue" banner, or a `mcp sweep: done … alertsOpened=N`
log line with a large N.

This is the system working: the daily sweep (`scan.mcp_sweep`) re-checked
every scanned MCP server version, one of them gained a high or critical
advisory, and every published BriefAgent version declaring it got a
dependency alert — banner and dashboard for the author, one email, an
`agent.dependency_alert` audit event, and the org webhook. Nothing was
quarantined: the versions stay installable, and the alert closes on its
own when the author yanks the version or the advisory is withdrawn.

1. **Confirm the advisory is real.** `GET /api/v1/mcp-servers/scan?ecosystem=&package=&version=`
   shows what the registry recorded (ids, severity, fixed versions); the
   ids resolve at osv.dev. A withdrawn or re-scored advisory clears itself
   at the next sweep; do not edit `mcp_server_scans` by hand.
2. **Scope it.** How many published versions, how many authors:
   ```sql
   select a.ecosystem, a.package, a.package_version, a.severity, count(*) versions,
          count(distinct v.submitted_by) authors
   from mcp_dependency_alerts a join agent_versions v on v.id = a.version_id
   where a.resolved_at is null group by 1,2,3,4 order by versions desc;
   ```
3. **Decide whether it is also a trust-and-safety matter.** A server with a
   remote-code-execution advisory that a BriefAgent runs against its declared
   secrets may deserve quarantine of the affected versions (runbook 4) and an
   advisory; an alert alone is right for the ordinary case. The runner
   refuses to *run* a BriefAgent whose declared server the registry marks
   high or critical — the check is `agentry run`'s, before the plan
   executes, and the receipt's vulnerability line says what it found — unless
   the person passes `--allow-vulnerable-mcp` or the operator policy sets
   `mcpServers.allowVulnerable`, either of which the receipt names
   (`agentry-cli`: `vulnerabilityVerdict` in `cmd/agentry/cmd_run_mcp.go`,
   `VulnStatus.Refuses` in `pkg/runner/mcpinstall/vulncheck.go`; `agentry
   doctor` warns on the same status). The install step itself is not
   refused, and copies already installed keep the server until their next
   run meets the check.
4. **Watch the sweep itself.** A `mcp sweep: vulnerability lookup failed
   for a batch` line (and a non-zero `lookupErrors` on the `mcp sweep: done`
   line) means the vulnerability database was unreachable: rows keep their
   last answer and are retried tomorrow; check egress from the worker to
   `AGENTRY_SCAN_OSV_URL`. `McpSweepRuns{outcome="error"}` counts a sweep
   that stopped on the registry's own database (listing, recording or
   opening alerts); the job is retried like any other.
5. **Tell people once.** Authors already got one mail per alert; a status
   note is for consumers, who see the alert on the agent page but get no
   mail.

**Verify:** the alert count stops growing after one sweep, affected authors'
new versions pin a fixed server (their S7 result is clean), and old versions
are yanked (their alerts show `resolved_reason = version-yanked`).
