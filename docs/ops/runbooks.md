# Runbooks

The procedures an on-call operator needs, written to be followed at 3am by
someone who did not write the code. Each one states the trigger, the checks,
the action, and how you know it worked.

Conventions: `agentryd` is the server binary; `$DB` is the database URL;
`psql "$DB"` assumes the app role. Anything destructive says so in bold.

---

## 1. Deploy and roll back

**Trigger:** a release is ready, or a release is misbehaving.

**Deploy.** Migrations run before the new code, and every migration in this
project is additive-or-compatible so old and new code can run side by side
during a rollout:

1. `terraform plan` in the target env; a plan that touches RDS, EFS, or the
   KMS signing key stops here and gets a second pair of eyes.
2. Apply migrations: `agentryd migrate` (idempotent; takes a session lock, so
   running it twice concurrently is safe).
3. Roll the services one at a time: `worker` first (it is the least
   user-visible), then `api`, `git`, `web`.
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

1. Depth and age by queue:
   ```sql
   select queue, state, count(*), min(run_at) from jobs group by 1,2;
   ```
2. Are workers alive? `agentryd worker` logs a `worker started` line and then
   claims jobs; no claims for minutes with `available` rows means the workers
   are gone, not slow. Restart them.
3. Orphaned claims (a worker died holding jobs) self-heal after 30 minutes;
   force it now:
   ```sql
   update jobs set state='available', locked_at=null
   where state='running' and locked_at < now() - interval '5 minutes';
   ```
4. Poison job (same job failing repeatedly):
   ```sql
   select id, kind, attempt, last_error from jobs where state='failed' order by finished_at desc limit 20;
   ```
   Capture `last_error`, open a bug, then park it: `update jobs set state='failed' where id='…'`.
   A parked scan job leaves its version in `scanning`. That is **fail-closed
   and correct**; the version is not published. Re-run it after the fix with
   a `manual` scan trigger rather than transitioning the version by hand.

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
ruleset release enqueues the §8.7 catalogue sweep automatically. You do not
schedule it, and shipping detection for a live technique will surface every
already-published version that trips it, all at once. Expect a wave of
quarantines within a sweep of publishing a rule that matters, and read that
as the system working rather than as an incident of its own. (Sweeps used to
need triggering by hand, which meant new detection sat unapplied; that was
fixed in the 2026-08-29 remediation.)

S8's publisher-behaviour signal also covers **account age ×
publish velocity** but does **not** correlate publisher IPs across accounts
(the "or IP cluster" half of §8.3). The actual ClawHavoc incident (1,184 skills
from 12 accounts) turned on exactly that axis, so step 1 below is manual work
the scanner will not do for you.

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
   is now true in fact and not only on paper. Until the 2026-08-29
   remediation, `block` set the agent's quarantine state and nothing else, so
   a blocked agent kept serving `200`s and its archive stayed downloadable;
   the `410` branch was unreachable code. If you ran this runbook before that
   fix, **re-check anything you blocked**; it may still be being served.
   Work through the API (`POST /platform/agents/{ns}/{name}/quarantine`, then
   `.../block`) so every action is audited with a reason, not in SQL.
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

Keys rotate with **overlapping validity windows** because clients pin what
they have seen (TOFU). A hard swap makes every installed client report a key
mismatch.

1. Create the new key (Terraform, `modules/kms`). Do not delete the old one.
2. Publish both at `/.well-known/agentry/signing-keys.json` (new key first).
   Clients now accept either.
3. Point signing at the new key (`AGENTRY_SIGNING_KMS_KEY_ARN`), roll the
   workers. New attestations use the new key; old ones still verify.
4. Leave the old key published for at least one CLI release cycle, then remove
   it from the key set. Keep the key material itself (old attestations must
   stay verifiable). **Never schedule deletion of a key that signed a
   published version.**

**If the key is suspected compromised:** rotate immediately as above, then
audit `kms:Sign` calls against the pipeline's own signing job and diff the
`attestations` table against `agent_versions` where `status='published'`. Any
attestation without a matching published version is a forgery signal. Publish
a security advisory; do not quietly rotate.

**Verify:** `agentry verify` succeeds against both a pre- and post-rotation
version from a client that pinned the old key.

---

## 6. Database restore (RDS PITR)

**Trigger:** data loss or corruption. RPO 15 minutes, RTO 4 hours (§13.6).

1. Stop writes: scale `api`, `git`, and `worker` to zero. Leave `web` up (it
   will show errors, which is better than silent divergence).
2. Restore to a new instance at the chosen timestamp (`aws rds
   restore-db-instance-to-point-in-time`). Never restore over the live one.
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

---

## 7. Repo storage (EFS) restore

**Trigger:** git repos missing or corrupt.

1. Repos are keyed by immutable UUID (`repos.id`), so a restore never has to
   guess ownership.
2. Restore the EFS recovery point (AWS Backup) to a new file system, mount it
   read-only alongside, and copy only the affected `{uuid[0:2]}/{uuid}.git`
   directories back.
3. A missing repo is recoverable from any clone: `git push --mirror`. Release
   archives are **not** affected by EFS loss; they live in S3 and are what
   consumers download. Published versions keep working through a total repo
   loss; only pushes and new git-tag publishes break.

**Verify:** `git clone` of an affected agent works; `agentry install` of its
published version was never affected.

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
   There is no default. It used to silently default to `yank`, which meant
   nobody was being asked. Ask before you run it, and record the answer.
4. If they insist published bytes be removed, that is a `blocked` decision by
   trust & safety with a written rationale, not an erasure step.
5. Audit events keep the opaque user id. Do not delete audit rows; the table
   rejects it at the database level anyway.

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

**Trigger:** sign-in fails or loops, `/login?error=…`, sign-out lands on a
second login screen, or Settings' password/authenticator actions error.
Existing registry sessions and PATs keep working throughout — the directory
is consulted at sign-in, not per request — so the API is not down; people
just cannot sign in.

1. Is authentik up? `curl -fsS https://auth.<site>/-/health/ready/` and
   `docker compose ps authentik-server authentik-worker`. A crash loop
   after an upgrade that says "Major version skips are not allowed" is the
   release-line rule in the self-hosting guide: step through each line.
2. Did the blueprint apply? Authentik's admin console → Customisation →
   Blueprints: "SecureAgentry - Account flows" must be *successful*, and
   the `agentry-invalidation` flow must exist. A blueprint that fails to
   apply names the offending entry in the worker log.
3. Is the registry's OIDC client still what authentik has? Re-run
   `scripts/dev/authentik-bootstrap.sh` (idempotent): it restores the
   provider's redirect URIs (authorization *and* logout), the scope
   mappings, the application's launch URL, and the brand's default
   application and unset user-settings flow — everything a deployment that
   predates agentry#164 lacks. It needs `AGENTRY_PUBLIC_WEB_URL` and the
   bootstrap token from `.env`; read individual keys from that file rather
   than `source`-ing it (values with spaces are not shell-quoted).
4. Do the containers know the site? `AGENTRY_PUBLIC_WEB_URL` must reach the
   `authentik-*` containers (compose passes it through); the account-flows
   blueprint formats it into the redirect stages. After changing it,
   recreate the authentik containers, not just the registry.
5. A user who cannot complete MFA is an operator action in the authentik
   admin console (`/if/admin/` still serves); email alone never resets both
   factors.

**Verify:** `GET https://<site>/api/v1/auth/oidc/authentik/start?next=%2Fdashboard`
in a browser ends on the dashboard with no directory screen in between;
`https://auth.<site>/` answers 302 to the site; the provider's end-session
URL lands in the `agentry-invalidation` flow whose first challenge (the
executor API) is a redirect to the site.

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
   already refuses to install a server the registry marks high/critical, so
   new runs are protected either way; installed copies are not.
4. **Watch the sweep itself.** `McpSweepRuns{outcome="error"}` or a
   `mcp sweep: vulnerability lookup failed` line means the database was
   unreachable: rows keep their last answer and are retried tomorrow; check
   egress from the worker to `AGENTRY_SCAN_OSV_URL`.
5. **Tell people once.** Authors were emailed per alert already; a status
   note is for consumers, who see the alert on the agent page but get no
   mail.

**Verify:** the alert count stops growing after one sweep, affected authors'
new versions pin a fixed server (their S7 result is clean), and old versions
are yanked (their alerts show `resolved_reason = version-yanked`).
