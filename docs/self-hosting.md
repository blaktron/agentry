# Self-hosting Agentry

The whole registry is open source: the scanners, the review queue, SSO and
SCIM, signing with your own key, and the server's own browser pages. There
is no "community edition" with the security features removed; a registry you
cannot audit is one you have to take on faith. What is *not* in this
repository is the hosted service's site — a closed front end that runs in
front of this same server; a registry does not need one, and
[the last section](#fronting-it-with-a-site) says how one plugs in.

**Target: a working private registry in under 15 minutes.**

## What you need

- PostgreSQL 16 (the only hard dependency)
- Somewhere to put files. A local disk is fine to start; S3 for production
- The `git` binary on the host running the git role
- Optionally: an LLM provider for automated adjudication. Without one, the
  pipeline does **not** skip that step. It routes every version to human
  review instead (fail toward review, never toward skip).

## Quickstart with Docker Compose

```bash
git clone https://github.com/blaktron/agentry.git
cd agentry
docker compose -f deploy/compose/docker-compose.yaml up -d   # postgres, minio, mailpit
docker compose -f deploy/compose/docker-compose.yaml --profile server up -d
```

The server's own pages are at http://localhost:8080/ui/ — sign-in, your
account, tokens and SSH keys, the review queue, the staff console and
organization administration. `agentry login` opens `/ui/authorize` there.

Then create the first account:

```bash
curl -sX POST http://localhost:8080/api/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"handle":"you","email":"you@example.com","password":"a-long-passphrase"}'
```

Email verification is required before publishing. In a dev setup the token is
logged at debug level and mailpit (http://localhost:8025) catches the message;
in production configure real SMTP.

If you enable the directory service below with
`AGENTRY_AUTH_EXTERNAL_ONLY=true`, this curl answers `410 Gone` by design —
accounts are then created on the sign-up page the directory service serves,
not through the native register endpoint.

## Quickstart from source

```bash
brew install go postgresql@16       # or your platform's equivalent
make db-up                          # private Postgres cluster on :5477
make build
./bin/agentryd migrate
./bin/agentryd all                  # every role in one process
```

Point the CLI at it (the CLI lives in its own repo,
[blaktron/agentry-cli](https://github.com/blaktron/agentry-cli); the helper
clones and builds it, using a sibling checkout when one exists):

```bash
CLI=$(./scripts/dev/cli-bin.sh)
$CLI login --registry http://localhost:8080
$CLI init my-first-agent
cd my-first-agent && $CLI validate
```

`validate` runs the same manifest rules and the same hidden-content and
injection-signature scanners the server runs at publish time, offline.

## Deployment shapes

| Shape | What runs | Who it is for |
|---|---|---|
| **Single process** | `agentryd all` + Postgres | evaluation, small teams |
| **HA** | Helm chart: `api`×N, `git`×N (shared RWX volume), `worker`×N; a site in front is its own deployment | production self-host |
| **AWS reference** | the hosted service's Terraform, kept with the site (not in this repository) | mirrors how the hosted service runs |

The same binary serves every role; `agentryd api|git|worker|all` selects it.
The `git` role is the only one that needs repo storage mounted, and the
`worker` role is the only one that needs to reach the LLM provider. That is
what lets you give the scanning workers a no-egress security group.

## Configuration

`agentry.yaml` (copy `agentry.yaml.example`) plus `AGENTRY_*` environment
overrides; environment always wins. The authoritative list is
`internal/config/config.go`. The settings that matter most:

```yaml
env: prod
devMode: false          # refused in prod anyway

database:
  url: postgres://…

storage:
  kind: s3              # or local
  s3Bucket: my-agentry-releases
  s3Region: us-east-1

auth:
  sealingKey: "<base64 32 bytes>"   # required outside dev; encrypts TOTP seeds
  cookieSecure: true

signing:
  kind: file            # file | kms, 'none' is refused in prod
  keyFile: /etc/agentry/signing-key.pem

# How the server presents itself and where browsers land (DEV-091).
web:
  url: ""               # a site fronting this server; unset = the server's own /ui/ pages
ui:
  mode: full            # full | authorize | off — the server's own browser surface
brand:
  name: ""              # emails, authenticator apps and /ui/ call it this (default: the public host)
  logoURL: ""           # optional; the /ui/ pages and the directory show it
  cssURL: ""            # optional stylesheet the /ui/ pages load
  supportEmail: ""      # shown where people need help
  securityEmail: ""     # shown on the security notes

judge:
  provider: none        # none | static | openai | anthropic | bedrock | classifier
  # For openai/anthropic, point at any endpoint speaking that protocol:
  # baseUrl: https://api.openai.com   # AGENTRY_JUDGE_BASE_URL
  # apiKey: sk-...                    # AGENTRY_JUDGE_API_KEY
  # model: gpt-4o                     # AGENTRY_JUDGE_MODEL (optional)
  # bedrock uses the AWS default credential chain (task role, profile, env):
  # region: us-east-1                 # AGENTRY_JUDGE_REGION (or AWS_REGION)
  # model: anthropic.claude-3-5-sonnet-20241022-v2:0   # Bedrock model id
  # classifier is a PromptGuard-class text classifier (Hugging Face
  # text-classification wire shape: {"inputs": text} → [[{label, score}]]).
  # It scores ONLY the injection axis, so it always routes to human review —
  # a cheap pre-screen that adds evidence, not a substitute for the rubric.
  # baseUrl: http://prompt-guard:8080/classify   # AGENTRY_JUDGE_BASE_URL
  # apiKey: ...                       # optional bearer token

scan:
  # The one external scanner tool behind the §8.3 seam. Optional: unset,
  # the native Go secret detectors run alone.
  gitleaksBin: /usr/bin/gitleaks      # AGENTRY_SCAN_GITLEAKS_BIN ("auto" = PATH lookup); shipped in the image
  # toolTimeout: 2m                   # AGENTRY_SCAN_TOOL_TIMEOUT per invocation
  # The vulnerability database S7 asks about the MCP servers a manifest
  # declares. Default api.osv.dev; point it at a mirror, or set "none" to
  # switch the lookup off (S7 then reports "not checked" and routes nothing).
  # osvUrl: https://api.osv.dev       # AGENTRY_SCAN_OSV_URL
```

The scanning role needs egress to that database (one host); a worker that
cannot reach it leaves an `S7/osv-error` finding, which routes the version
to review rather than through. The answers are kept per package version in
the `mcp_server_scans` table, so a server version is looked up live the
first time any manifest declares it and served from that table for the
next 24 hours.

**The daily sweep.** The worker re-checks every row of that table once
a day (the `scan.mcp_sweep` job, enqueued a minute after start-up and every
24 hours after). A server version that was clean and now carries a high or
critical advisory opens a **dependency alert** on every published version
that declares it; the author is told by email (`AGENTRY_NOTIFY_KIND=smtp`),
the audit trail records `agent.dependency_alert`, and an org's webhooks
receive `agent.dependency_alert`. The alert closes on its own when the
version is yanked, quarantined or blocked, or when the advisory is
withdrawn; publishing a fixed version does not close the old version's
alert, because the old version stays installable until it is yanked.

Git-tag publishes also have their **git history** scanned for secrets (§8.3):
S2 walks the added lines of every commit reachable from the tag, so a key
committed and later removed still surfaces as `S2/history-<rule>`. That needs
the scanning role to see the repository data directory — the compose stack's
single `all` role does; a separate worker without shared git storage reports
`S2/history-not-scanned` instead of implying a clean history.

A configured tool that cannot be found is a startup error, never a silent
fallback. A tool that fails mid-scan leaves an `S2/tool-error` finding on
the report, so "gitleaks did not run" is distinguishable from "no
secrets". The code-analysis stages that once ran opengrep and an OSV
dependency check were retired with the package kinds they served:
BriefAgents carry no tool code, and the MCP servers one declares are
resolved and pinned by the runner instead. Both ids are in use again — S6
is the support-scripts stage that reads a package's shell, Python and
JavaScript files against the manifest, and S7 the MCP server lookup above.

Generate a signing key:

```bash
openssl ecparam -name prime256v1 -genkey -noout -out signing-key.pem
chmod 600 signing-key.pem
```

Your public key is served at `/.well-known/agentry/signing-keys.json`, and
clients pin it on first use. **Back this key up**: it is what makes your
already-published attestations verifiable, and losing it means every installed
copy stops verifying.

Generate a sealing key:

```bash
openssl rand -base64 32
```

### Object storage and KMS signing

`storage.kind: local` keeps release archives on disk under `storage.localDir`.
The quickstart uses it, and a single-node deployment can keep using it
indefinitely; archives are content-addressed and write-once.

For S3, and for signing with a KMS key instead of a file:

```yaml
storage:
  kind: s3
  s3Bucket: my-agentry-releases
  s3Region: us-east-1

signing:
  kind: kms
  kmsKeyARN: arn:aws:kms:us-east-1:111122223333:key/…
```

Env equivalents: `AGENTRY_STORAGE_KIND`, `AGENTRY_STORAGE_S3_BUCKET`,
`AGENTRY_STORAGE_S3_REGION`, `AGENTRY_SIGNING_KIND`,
`AGENTRY_SIGNING_KMS_KEY_ARN`. Credentials come from the ambient AWS chain:
an instance or task role, not keys in this file. The hosted service's
Terraform provisions both the bucket and a key whose `kms:Sign` permission
is restricted to the worker task role.

**Honest caveat:** these two backends have **not yet been exercised against a
live AWS account**. The Terraform is validated but never applied, and the
build environment has no AWS credentials, so the first real deployment is
also the first integration test. `local` + `file` are the paths with mileage
on them. If you are standing up production on S3 and KMS, publish a throwaway
version first and confirm the archive round-trips and `agentry verify`
passes before you trust it with anything.

### Social login

Individual accounts can sign in with Google, GitHub, Microsoft, OpenAI, or
Claude (§12.1). All are optional and independent: **a provider with no
client id is not offered at all**. Its start endpoint returns 404, so
probing cannot distinguish "misconfigured" from "not enabled".

```yaml
social:
  google:
    clientId: "…apps.googleusercontent.com"
    clientSecret: "…"
  github:
    clientId: "Iv1.…"
    clientSecret: "…"
  microsoft:
    clientId: "…"
    clientSecret: "…"
  openai:
    clientId: "…"
    clientSecret: "…"
    issuer: "https://your-oidc-issuer.example"   # required for openai/claude
  claude:
    clientId: "…"
    clientSecret: "…"
    issuer: "https://your-oidc-issuer.example"
```

Env: `AGENTRY_SOCIAL_<PROVIDER>_CLIENT_ID` and `_CLIENT_SECRET` per provider
(`AGENTRY_SOCIAL_MICROSOFT_CLIENT_ID`, …), plus `_ISSUER` for the OIDC
providers.

Register the callback with each provider as
`{baseURL}/api/v1/auth/oidc/{provider}/callback`, so `baseURL` must be
set correctly for social login to work at all.

Two behaviours worth knowing before you enable this (DEV-019, DEV-055):

- **Google and Microsoft are real OIDC**: discovery, issuer pinning, PKCE,
  ID-token signature and nonce verification. Google uses
  `accounts.google.com`; Microsoft uses the multi-tenant `common` endpoint
  by default (override `issuer` for a single tenant). **GitHub is an
  OAuth 2.0 shim**: there is no ID token to verify, so the trust anchor is
  TLS to `api.github.com` plus your client secret. There is no PKCE; a
  sealed single-use state cookie is what binds a callback to the browser
  that started it. An email is recorded only when GitHub reports it both
  primary *and* verified. **OpenAI and Claude publish no fixed consumer
  sign-in endpoints**, so they need an `issuer` pointing at an
  OIDC-compatible endpoint you operate or trust; without one they stay
  unoffered.
- **Social login is not a way around 2FA.** A redirect callback has nowhere
  to carry a TOTP code, so an account with 2FA enrolled receives a sealed
  five-minute challenge instead of a session, completed at
  `POST /api/v1/auth/2fa/totp/challenge`.

### Audit archive and retention

Every audit event is written to the `audit_events` table. It is partitioned
monthly and carries an append-only trigger: rows cannot be updated or
deleted, by anyone, including you. §12.6 additionally wants a
continuous NDJSON stream. It is **off by default**:

```yaml
audit:
  streamKind: file            # none (default) | file | s3
  streamDir: /var/lib/agentry/audit-stream
  streamFlush: 30s
  retentionDays: 400          # 0 disables pruning
```

Env: `AGENTRY_AUDIT_STREAM_KIND`, `AGENTRY_AUDIT_STREAM_DIR`,
`AGENTRY_AUDIT_STREAM_FLUSH`, `AGENTRY_AUDIT_STREAM_S3_BUCKET`,
`AGENTRY_AUDIT_RETENTION_DAYS`.

- `file` appends one `audit-YYYY-MM-DD.ndjson` per UTC day to `streamDir`.
  Rotate and ship those with whatever you already use.
- `s3` is **not implemented**. The constructor refuses at startup and names
  the bucket it was asked for, rather than silently dropping records
  (DEV-020). Use `file` plus your log shipper.
- An unavailable sink degrades to a no-op plus an error log; it does not stop
  the server from booting.
- Two deliberate trade-offs: the stream is fed by the audit writer
  immediately after the insert, so a transaction that rolls back afterwards
  leaves an "attempted" line in the archive with no matching row; and when
  the buffer fills (a wedged disk) records are **dropped with an error log**
  rather than blocking the request path. An archive that can stall writes is
  a denial-of-service surface, and an extra line is auditable where a missing
  one is not.

**Retention is month-granular.** Pruning works by dropping whole monthly
partitions, the only way to prune a table whose trigger refuses `DELETE`,
and O(1) rather than a 400-day scan. A partition is dropped only once *all*
of its rows are outside the window, so effective retention rounds **up** to a
month boundary: with `retentionDays: 400` you will hold up to ~430 days.
Size your storage for the upper bound.

### Notification email

Verification emails, review notifications and advisory notices go out over
SMTP:

```yaml
smtp:
  host: smtp.example.com
  port: 587
  username: agentry
  password: "…"
  from: "Agentry <noreply@example.com>"
```

Env: `AGENTRY_SMTP_HOST`, `AGENTRY_SMTP_PORT`, `AGENTRY_SMTP_USER`,
`AGENTRY_SMTP_PASS`, `AGENTRY_SMTP_FROM`, `AGENTRY_SMTP_STARTTLS`
(plus `AGENTRY_NOTIFY_KIND=smtp` to switch the notifier on).

In dev the compose stack's **mailpit** (http://localhost:8025) is the default
target and catches everything, so nothing leaves the machine. The compose
file reads all of these (and the directory service's `AUTHENTIK_EMAIL_*`
set) from `.env`, so switching both senders to a real provider is an `.env`
edit plus recreating the `server` and `authentik-*` containers. With
Postmark, the server token is both SMTP username and password, and until
the account is approved it only delivers to recipients on the sending
domain. With no SMTP configured at all, email verification tokens are
logged at debug level. That is usable for a single-operator instance, not
for anything with real users.

### Limits and quotas

The §19 quotas are configuration (`limits.*`, or `AGENTRY_LIMITS_*` in the
environment) and an organization on a larger plan can be raised above them
through the entitlements resolver. The defaults:

| Key | Default | What |
|---|---|---|
| `limits.repoQuotaBytes` | 100 MiB | a push that would take the repository past it is refused |
| `limits.repoWarnBytes` | 25 MiB | past it the push succeeds and the pusher sees `remote: agentry: warning: repository is N MB of the M MB quota` |
| `limits.repoMaxBlobBytes` | 25 MiB | no single object in a pushed tree may exceed it |
| `limits.archiveMaxBytes` | 10 MiB | the release archive, after `publish.include` |
| `limits.archiveMaxFiles` | 2000 | files in the archive |
| `limits.archiveMaxFileBytes` / `archiveMaxImageFileBytes` | 2 MiB / 5 MiB | any one file, images by extension |
| `limits.archiveMaxTextBytes` | 1 MiB | the text files in total — the prose the scanners read in full; a package cannot spread an oversized instruction set across many files (V8) |
| `limits.gitPushesPerHour` | 60 | per repository |
| `limits.agentsPerUserNamespace` / `agentsPerOrgNamespace` | 200 / 500 | |
| `limits.versionsPerDay` | 20 | per agent |
| `limits.webhookEndpointsPerOrg` / `webhookDeliveriesPerSecond` | 20 / 5 | |
| `limits.authedPerHour`, `authedBurstPerMin`, `anonymousPerMin`, `loginPerMin` | 5000, 100, 60, 10 | the API rate buckets (also enforced at the edge) |

The archive quotas are checked by the manifest rules (V8) both on the server
at submission and by `agentry validate` offline, so a package learns it is
over before it is uploaded.

### The job queue

Async work (scans, webhook deliveries, audit exports, repository
bookkeeping, the watchdog and MCP sweeps) rides a queue in the same
Postgres database. The driver is [River](https://riverqueue.com)
(`queue.driver: river`, `AGENTRY_QUEUE_DRIVER`); its tables (`river_job`,
`river_queue`, `river_leader`, `river_notification`, `river_migration`) are
created by the migrator on start beside the core schema, so nothing extra
runs. `queue.workers` (`AGENTRY_QUEUE_WORKERS`, default 1) is how many jobs
one worker process runs at once per queue: 1 keeps the serial behaviour of
earlier releases; raise it on a worker with the memory for parallel scans.
A job that fails retries with exponential backoff up to five attempts, a
job a crashed worker held is rescued after 30 minutes, and every outcome is
counted (see Metrics). `queue.driver: pg` selects the earlier `SELECT … FOR
UPDATE SKIP LOCKED` implementation on the `jobs` table; it stays for one
release as a fallback and is not for new installs.

### Metrics

The API exposes Prometheus metrics at **`/metrics`**: HTTP request counts and
latencies by route and status, queue depth and job outcomes, scan stage
durations, and the Go runtime collectors. Scrape it from your own Prometheus;
there is no push path and no external dependency.

`/metrics` is unauthenticated and carries route-level operational data. There
is no agent content and no user identifiers, but you should still keep it off
the public internet. Bind the API's metrics exposure behind your ingress, or
scrape over the cluster network only.

`/healthz` (liveness) and `/readyz` (readiness, checks the database) are
separate and are what your load balancer should use.

### What the stack exposes

`/ui/` is the server's own browser surface (DEV-091): the device authorize
page `agentry login` and the desktop app open, and, on a server without a
site in front, sign-in, the account pages and the review, staff and
organization pages. The edge sends it to the API like `/api/`. The handle
`ui` (and the other root paths of the server and the site) cannot be
registered.

Docker publishes ports by inserting its own firewall rules ahead of the
host's (firewalld and ufw zones do not apply to a published port), so a
plain `"5432:5432"` on a machine with a public address is Postgres — with
the compose file's development password — on the internet. The stack
therefore publishes every service **except the edge** on `AGENTRY_BIND`,
default `127.0.0.1`: Postgres (5432), MinIO (9000/9001), mailpit
(1025/8025) and agentryd (8080). A site overlay publishes its own services
the same way. The acceptance
scripts, `agentry` on the host, and the quickstart above all use
`localhost`, so nothing changes for them.

```bash
# .env — reach the direct ports from another machine on a private network
AGENTRY_BIND=100.64.0.7        # e.g. this host's Tailscale address
# .env — the edge is public by default; bind it privately when a tunnel
# (below) is the only intended entry point
AGENTRY_EDGE_BIND=100.64.0.7
```

Whatever you bind, confirm it from outside: `ss -ltn` on the host lists
what is listening and on which address, and a request to each port from
a machine that should *not* reach it should fail. If a public address ever
served these ports, treat the compose defaults (`agentry` / `agentry`,
`agentry-dev-secret`) as disclosed and change them.

The Postgres and MinIO passwords come from `.env` — `AGENTRY_PG_PASSWORD`
and `AGENTRY_MINIO_SECRET`, defaulting to the development values — and
reach every place they are used (the services, agentryd's DSN, authentik's
database, the bucket bootstrap). Set both before the first `up` on any
stack that is not a throwaway; on a stack that already has data, change
the stored password first (`ALTER USER agentry PASSWORD …` in Postgres,
`mc admin user` for MinIO) and then `.env`, since the volumes keep what
they were initialised with.

### Rate limits at the edge

agentryd applies the §19 per-IP limits to the API; the edge adds `limit_req`
zones (keyed on the resolved visitor address) for the routes that do work for
strangers: the sign-in page `/ui/login` and `/api/v1/auth/*` (30/min, burst
30), and the git endpoints (120/min, burst 60). Over the limit is `429` with
`Retry-After`. Tune the zones in `edge/nginx.conf`; a site's overlay adds
zones for its own forms; behind Cloudflare, mirror the same paths with a
rate-limiting rule so the edge is the second line, not the first.

### Running behind a proxy

Rate limiting (§19) buckets anonymous traffic per client IP. Behind a load
balancer, every request appears to come from the balancer unless you say
otherwise:

```yaml
http:
  trustedProxies: 2   # number of reverse-proxy hops in front of agentryd
```

Env: `AGENTRY_TRUSTED_PROXIES` (an integer hop count, not a CIDR list).

`X-Forwarded-For` is honoured **only** up to that many proxy hops: behind
CloudFront → ALB set `2`; behind a single load balancer set `1`. Leave it at
`0` (the default) if the server is directly exposed. The header is then
ignored entirely. Setting it higher than the real hop count lets any client
choose its own rate-limit bucket and forge audit IPs, which is worse than
having no per-IP limiting at all.

The compose stack ships its own proxy, the `edge` service
(`deploy/compose/edge/nginx.conf`): nginx on 80/443 that terminates TLS and
serves the server's own `/ui/` pages, `/api`, `/scim`, `/.well-known`,
`/downloads/` and `/<ns>/<name>.git` from one origin (the same split the
Helm ingress makes; a site in front replaces this config with its own, see
the last section). **Use it even in dev.** Browsers send no `Sec-Fetch-Site`
and — under a `Referrer-Policy: no-referrer` — an `Origin` of `null` to any
origin that is not https or localhost, so on a plain-http hostname every
form post to the `/ui/` pages (or a site's) is refused as cross-origin.
Point `AGENTRY_EDGE_CERT_DIR` at a directory holding `edge.crt` and
`edge.key`; on a Tailscale host

```bash
sudo tailscale cert --cert-file edge.crt --key-file edge.key <host>.<tailnet>.ts.net
```

issues a certificate browsers trust, and a self-signed pair works for a
first boot. Then in `deploy/compose/.env`: `AGENTRY_TRUSTED_PROXIES=1`,
`AGENTRY_PUBLIC_WEB_URL=https://<host>`, and once clients trust the
certificate, `AGENTRY_PUBLIC_URL=https://<host>` (clone, install and
download URLs render from it) and `AGENTRY_COOKIE_SECURE=true`.

### Cloudflare Tunnel

The compose stack can publish the edge through a Cloudflare Tunnel — an
outbound-only connector, so the host needs no inbound port at all. The
connector reaches the edge over the compose network, not through the
published ports, so with the tunnel as the only intended entry point set
`AGENTRY_EDGE_BIND` to a private address (or `127.0.0.1`) as well. A
Cloudflare-fronted site whose origin also answers on its public IP gets
none of the WAF, rate limiting, or Access rules configured at the edge,
and the address is only ever one stale DNS record away from being known.

```bash
# .env (git-ignored, mode 600)
CLOUDFLARE_TUNNEL_TOKEN=…          # Zero Trust → Networks → Tunnels → your tunnel → token
COMPOSE_PROFILES=server,tunnel     # so a plain `docker compose up -d` includes it
```

Visitors' addresses survive the tunnel: cloudflared forwards Cloudflare's
`CF-Connecting-IP`, the edge trusts that header only when the peer is a
container of this stack (docker's `172.16.0.0/12` pools), and it writes
the resolved address as the single `X-Forwarded-For` entry agentryd and
authentik read. Keep `AGENTRY_TRUSTED_PROXIES=1`; a direct connection to
the edge cannot forge the header because the edge replaces it rather than
appending to it.

The `cloudflared` service is behind the `tunnel` profile so a stack without
a token still starts. The token reaches the connector only as the
`TUNNEL_TOKEN` environment variable — not as a command-line argument, so it
does not appear in `ps` or `docker inspect`'s command — and the container
runs read-only with every capability dropped. The tunnel is remotely
managed: configure the public hostnames in the dashboard, each with origin
`https://edge:443` and the **origin server name** set to that hostname so
TLS to the edge verifies (see the beta readiness notes for the full list of
hostnames and the caching, WAF, and Access settings that matter). Running
`docker run … --token …` by hand holds the terminal because cloudflared runs
in the foreground; the service is the way to run it.

### The directory service (DEV-057)

The compose stack ships Authentik as the account directory: passwords,
MFA, recovery, and sign-up live there, and the registry consumes it as
the `authentik` OIDC provider while keeping sessions, PATs, and RBAC
native. The edge serves it as `auth.<your-domain>` and, when no such DNS
name exists (dev), on `https://<host>:8443`.

First boot, in `deploy/compose/.env`:

```bash
AUTHENTIK_SECRET_KEY=…        # openssl rand -base64 48
AUTHENTIK_BOOTSTRAP_PASSWORD=…   # akadmin's password
AUTHENTIK_BOOTSTRAP_TOKEN=…      # API token for the bootstrap script
AUTHENTIK_BOOTSTRAP_EMAIL=akadmin@example.com
```

then bring the stack up and run `scripts/dev/authentik-bootstrap.sh`
(idempotent — creates the OAuth2 provider `agentry-registry` and the
`agentry` application), and point the registry at the result:

```bash
AGENTRY_AUTH_EXTERNAL_ONLY=true
AGENTRY_SOCIAL_AUTHENTIK_CLIENT_ID=agentry-registry
AGENTRY_SOCIAL_AUTHENTIK_CLIENT_SECRET=…   # what you gave the bootstrap script
AGENTRY_SOCIAL_AUTHENTIK_ISSUER=https://<host>:8443/application/o/agentry/
AGENTRY_IDP_LOGOUT_URL=https://<host>:8443/application/o/agentry/end-session/
```

The bootstrap script attaches the `openid`, `profile`, and `email`
scope mappings to the provider — without them authentik issues an ID
token carrying `sub` alone and the registry can only create a placeholder
account (`<handle>@authentik.social.local`) instead of linking to the
existing one. For `email` it installs its own mapping, "Agentry:
OpenID 'email' (directory-verified)", asserting `email_verified: true`:
authentik's managed mapping hard-codes `false` (2026.8), and the
registry's auto-link rule (T-12) only links an IdP identity to an
existing account when *both* sides' addresses are verified. That
assertion is sound exactly when authentik is your directory of record —
accounts are created by operators, provisioned from an upstream
directory, or enrolled through a flow with an email-verification stage.
If you allow self-enrollment without one, drop that mapping and accept
that such accounts start as new registry users.

**Platform staff comes from a directory group.** The groups blueprint
creates `agentry-platform-staff`; the registry reads the ID token's
`groups` claim at every `authentik` sign-in and sets the account's
`platform_staff` flag to "is a member" (`AGENTRY_IDP_STAFF_GROUP`, compose
defaults it to that group; empty disables the sync). Add and remove staff
in the directory, never in SQL: leaving the group revokes staff at the
person's next sign-in, and the change is audited as `user.staff_sync`.
Only the `authentik` provider's claim counts — a Google or GitHub token
carrying the same group name is ignored.

**Provisioning org members from Authentik (SCIM).** The registry's SCIM
endpoint is per organisation and authenticated by a token the org owner
mints (`POST /api/v1/orgs/{org}/scim/tokens`, or the org admin console).
In Authentik create a *SCIM provider* with URL
`https://<host>/scim/v2` and that token, attach it to the `agentry`
application as a backchannel provider, and scope it to the group(s) that
should become org members. Users then arrive as members and Authentik
groups as teams; the registry keeps ownership of roles. A single Authentik
instance can provision several orgs — one SCIM provider per org, each
with its own token. This is deliberately not a blueprint: the token is
org-scoped and minted by the org, not by the platform.

The Helm chart carries the same knobs (`config.auth.externalOnly`,
`config.social.authentik`, `config.auth.idpStaffGroup`,
`config.idp.logoutUrl`, `secret.authentikClientSecret`,
`secret.idpAdminToken`); the hosted service's Terraform (kept with the
site) carries them as `idp_client_id`, `idp_issuer`, `idp_logout_url` and
`idp_staff_group`, with the client secret in Secrets Manager.

**Account flows.** `deploy/compose/authentik/blueprints/agentry-account-flows.yaml`
is mounted into authentik as a blueprint and applied automatically on
boot. It defines both self-service routes and the controls on them, and
adds the "Sign up" and "Forgot username or password?" links to the login
page:

- **Sign-up** — CAPTCHA, then a form (username, display name, email,
  password), then the account written **inactive**, then an emailed
  confirmation link that activates it, then sign-in. Writing the account
  inactive is what makes the directory-verified `email` assertion above
  honest for self-enrolled users: no account is active, and so none
  reaches the registry, before its address is confirmed.
- **Password recovery** — identification, an emailed reset link, then a
  new password. The identification stage runs with `pretend_user_exists`,
  so an unknown address gets the same answer a real one does and the form
  cannot be used to discover who has an account. Recovery deliberately
  does **not** activate an inactive account, unlike the confirmation
  above: an operator-deactivated user must not be able to reactivate
  themselves by requesting a reset.
- Both forms enforce the **same password policy** (12 characters minimum
  plus a zxcvbn strength score), because a password chosen during a reset
  should be held to the same bar as one chosen at sign-up. There is no
  Have I Been Pwned lookup: it needs egress from the container, and an
  outage there would block sign-ups and resets outright.

To run invite-only instead, delete the blueprint file (or disable its
instance in authentik's admin UI); operator-created accounts are
unaffected. Both mails go through authentik's own SMTP settings
(`AUTHENTIK_EMAIL__*` — mailpit on the dev stack), which are separate from
the registry's `AGENTRY_SMTP_*`.

**Abuse controls on those flows.** Two layers, and the defaults are not
production values:

- A **CAPTCHA** stage guards sign-up. It ships configured for Cloudflare
  Turnstile using Cloudflare's published *test* keys, which always pass —
  that keeps a dev stack working out of the box and stops nobody. Set
  `AUTHENTIK_CAPTCHA_SITE_KEY` and `AUTHENTIK_CAPTCHA_SECRET_KEY` (compose
  passes both through) before opening sign-up to the internet;
  `AUTHENTIK_CAPTCHA_JS_URL` / `_API_URL` point it at a different provider.
- A **per-IP rate limit** caps how much work one address can cause: at most
  10 accounts created plus mails sent per hour, counted from authentik's
  own event log. Ordinary use costs 2 (an account and its confirmation
  mail) to sign up and 1 to reset a password, so the budget is generous for
  a shared office address while ending bulk account creation. Raise or
  lower `MAX_PER_HOUR` in the blueprint to suit your users. Recovery also
  keeps authentik's own per-user control on the email stage
  (`recovery_max_attempts`, `recovery_cache_timeout`); the per-IP limit is
  what stops one source mailing a thousand different victims.
  The policy **fails open** on an unexpected error (a broken counter must
  not become an outage on the only route into the product); the failure
  shows up in authentik's event log as a `policy_exception` event, which
  is the thing to alert on — the registry's `FailOpenEvents` metric covers
  the registry's own fail-open paths, not this one.

`AUTHENTIK_ACCOUNT_FLOW_MAX_PER_HOUR` sets that budget (default 10):
compose passes it through, and the blueprint formats it into the policy at
apply time. Enrollment ends with authenticator (TOTP) setup, and recovery
verifies the authenticator before the password may change — a user who has
none is sent through the same setup stage. Lost-authenticator recovery is an
operator action in the Authentik admin UI; email alone never resets both
factors.

Sign-in from a browser runs in the API's browser mode: the server's
`/ui/login` (or a site's own sign-in page) forwards to
`/api/v1/auth/oidc/authentik/start?next=<path>` and the callback answers
a 303 back to that path (or to the sign-in page with `?error=…`) once the
session cookie is set; without `next` the same callback returns the JSON
result the CLI and tests consume.

With `AGENTRY_AUTH_EXTERNAL_ONLY=true` the native register, password
login, email-verify, and TOTP endpoints answer 410 Gone, and the web
login page offers the directory service only. Turning the flag off (the
default) restores the native flows — nothing was removed.

**Account erasure spans both systems.** `DELETE /user` pseudonymizes the
registry account (§12.7); the sign-in account — email, display name,
password hash — lives in authentik. Set `AGENTRY_IDP_ADMIN_URL` (the API
origin as the server reaches it: `http://authentik-server:9000` on the
compose stack) and `AGENTRY_IDP_ADMIN_TOKEN` (an authentik API token with
rights over users; the bootstrap token works) and erasure also deletes the
directory account with the same email — never a superuser or a service
account. The outcome is recorded on the `user.delete` audit event
(`directoryErasure`: `deleted`, `not-found`, `failed`, or `not-configured`);
a failure does not undo the registry erasure and is logged for the
operator to finish by hand. Leave the variables unset and the privacy
policy's promise that deletion removes personal information is one you
have to keep manually.

**Two-factor authentication and public publishing.** Outside dev mode the
registry normally refuses to publish to a public namespace until the
account has a TOTP factor (§12.1, §19). With the directory service in
charge no account can enrol one — the native TOTP endpoints are the ones
answering 410 — so that gate is **off under `externalOnly`** and the
requirement is yours to enforce in authentik. Bind an MFA policy (or an
authenticator-validation stage) to the authentication flow or to the
`agentry` application, which also covers sign-in itself rather than only
publishing.

To turn trust back into evidence, set `AGENTRY_AUTH_REQUIRE_IDP_MFA=true`.
The gate is then on under `externalOnly`, and it is satisfied when the
account has signed in at least once with an ID token whose `amr` claim (RFC 8176)
names a second factor — `mfa`, `otp`, `hwk`, `webauthn` and the like, never
`pwd` alone — which the registry records as `users.idp_mfa_at`. authentik
emits `amr` on its ID tokens; check one sign-in's token (or the
`user.login` audit row) before enabling the flag, because with it on and a
directory that never asserts a factor, nobody can publish publicly.

The directory's flows are unbranded here and call the deployment
`AGENTRY_BRAND_NAME`; a site that fronts the registry applies its own
brand (title, wordmark, favicon, flow background, custom CSS) through the
directory's API — the hosted site's repository carries that script and
stylesheet (DEV-091).

**Upgrading the directory service.** Authentik refuses to skip a release
line: every `YYYY.M` line between the running version and the target
must be passed through in order, and the check runs before any migration
(a refused container crash-loops with "Major version skips are not
allowed" and leaves the database untouched). So to move, say, 2025.6 →
2026.8 the path is 2025.12 → 2026.2 → 2026.5 → 2026.8: `pg_dump` the
`authentik` database first, then for each hop set the image tag in
`docker-compose.yaml`, `docker compose --profile server up -d
authentik-server authentik-worker`, and wait for the server container to
report healthy before the next hop. Finish by restoring the committed
tag+digest pin (bump it when the target is new) and `docker image prune
-a` — each hop's image is ~1.4 GB and a full chain has filled a small
root volume. The registry needs no restart: the OIDC issuer, client, and
brand ride the database.

**The directory stays behind the scenes.** Nobody browses it directly:
the edge sends `auth.<site>/` and the directory's user panel
(`/if/user/…`) back to the site, and the registry's Settings page is
where a person changes their password, adds an authenticator app or
security key, or removes one — each is one short step in the directory
that returns to Settings. For that the directory needs to know the site.
Two variables tell it where its flows return (DEV-091): sign-out lands on
`AGENTRY_PUBLIC_WEB_URL` and a password change or an authenticator
enrolment on `AGENTRY_ACCOUNT_URL`. Both default to the server's own pages
(`<AGENTRY_PUBLIC_URL>/ui/` and `…/ui/account/directory`); a site in front
sets them to its home and its Settings → Authentication page. The flows'
titles and mail subjects call the deployment `AGENTRY_BRAND_NAME`
(default `Agentry`). `AGENTRY_PUBLIC_WEB_URL` (the same value the registry
uses) is passed to the `authentik-*` containers and read by the
account-flows blueprint.
`scripts/dev/authentik-bootstrap.sh` points the application's launch
URL at the registry's sign-in start and the brand's default application
at it, so a sign-in, sign-up or recovery that ends without a return lands
in the app signed in. Sign-out goes through the blueprint's
`agentry-invalidation` flow, which ends the directory session and
redirects to the site; keep `AGENTRY_IDP_LOGOUT_URL` on the provider's
`end-session/` endpoint. The blueprint also unsets the brand's
user-settings flow. Re-run the bootstrap script after upgrading a
deployment that predates this (agentry#164).

## Hosting the downloads

The edge serves whatever is in the downloads directory
(`AGENTRY_DOWNLOADS_DIR`; unset, an empty named volume `downloads`) at
`/downloads/`, so publishing a build for your users is a file copy. The
CLI and the desktop app build from their own repositories (`agentry-cli`,
`agentry-desktop`); the hosted site's repository has the script that
builds the whole matrix and writes the `manifest.json` its download page
renders. A registry without a site hosts the files and links to
them from wherever it tells its users about the clients:

```bash
scp agentry-*-linux-amd64 host:/srv/agentry/downloads/
```

`AGENTRY_DEFAULT_REGISTRY` bakes the registry these binaries talk to when
the user configures nothing — set it to the registry (or the site in front
of it) that serves them, so a downloaded client connects back there by
default (`--registry` and the config file still override). Left empty, the
source defaults apply.

The script cross-compiles the CLI for macOS (arm64, amd64), Linux (amd64,
arm64) and Windows (amd64) — it is pure Go — and builds the desktop app
for the host's own platform when the GTK/WebKit dev headers are present
(Linux only, today; macOS and Windows desktop builds need their own
machines). It writes `SHA256SUMS` and `manifest.json`; the page renders
from the manifest, shows every target on the release matrix, and marks the
ones without an artifact as not yet available instead of linking to
nothing. Point `AGENTRY_DOWNLOADS_DIR` in `.env` at the directory — the
edge serves it at `/downloads/`, and a site's `web` container reads the
manifest from it — and re-create the `edge` service (and the site's `web`,
when one is in front) once so the mount exists. Versions come from
`git describe` in each repo, so tag releases
(`v0.1.0`) to get readable file names.

## Choosing your publication policy

The platform baseline lives in the `policies` table (`org_id IS NULL`) and is
readable at `/api/v1/platform/policy`. Defaults: findings up to `low`
auto-publish, `medium`/`high` go to review, `critical` is rejected, wildcard
network egress goes to review.

A stricter starting point for an internal registry, where everything gets a
human look:

```json
{
  "requireHumanReview": "always",
  "maxAutoPublishSeverity": "info",
  "wildcardEgress": "reject",
  "allowedLicenses": ["Apache-2.0", "MIT"]
}
```

Organizations can tighten this for their own namespace but never loosen it:
`blockedCapabilities` unions, `allowedLicenses` intersects, severity
thresholds only move down.

Three notes on the knobs:

- `blockedMcpServers` rejects a submission whose manifest declares one of the
  listed MCP servers (`npm:<package>` / `pypi:<package>`, `path.Match` globs
  such as `npm:@evil/*`); it unions across baseline and org like
  `blockedCapabilities`.
- `blockedCapabilities` rejects a submission that *declares* the capability;
  it is a gate on the manifest, not a runtime restriction. Combine it with
  `requireHumanReview: {"whenCapabilities": [...]}` if you want a look rather
  than a refusal.
- `allowedLicenses` lists SPDX identifiers; the registry validates against
  the full SPDX license list (embedded, refreshed with
  `scripts/dev/spdx-sync.sh`) and accepts expressions — `MIT OR Apache-2.0`,
  `GPL-2.0-or-later WITH Classpath-exception-2.0`. An expression passes the
  policy only when every identifier in it is allowed. Custom `LicenseRef-`
  identifiers are refused for public publish.

## Operating it

- **Backups:** Postgres is the system of record. Back it up. Release archives
  are content-addressed and write-once; repos are recoverable from any clone.
  Losing the repo store breaks pushes, not published installs.
- **The worker matters.** With no worker running, versions sit in `scanning`
  and never publish. That is the fail-closed design working, but it looks like
  a hang. Check the worker first when publishes stall.
- **A new ruleset rescans the catalogue.** Registering a ruleset semver for the
  first time enqueues the §8.7 sweep automatically; the rescan sweep quarantines
  versions that newly trip a high or critical finding.
- Runbooks for the failure modes above: [docs/ops/runbooks.md](ops/runbooks.md).

## What you are responsible for

Running your own registry means you own the trust decisions:

- the signing key and its backups;
- who has platform-staff rights (they can quarantine, block, and read
  everything on your instance);
- whether an LLM judge is configured, and therefore whether adjudication is
  automated or entirely human;
- keeping the ruleset current; a scanner from a year ago is a scanner that
  has not seen this year's techniques.

None of that is different from the hosted service; self-hosting makes it
visible.

## SSH git transport

Besides smart HTTP, the `git` and `all` roles serve `ssh://git@<host>:<port>/<ns>/<name>.git`
when `AGENTRY_GIT_SSH_ADDR` is set (the compose stack sets `:2222` and publishes it on the
host as `${AGENTRY_SSH_PORT:-2222}`; unset it to switch the transport off). Only
`git-upload-pack` and `git-receive-pack` are served — no shell, no forwarding — through the
same authorization, hooks and quotas as HTTPS.

- **Credential:** a user's SSH public key, registered on the settings page (or
  `POST /user/ssh-keys`). A key is worth repository read/write and the release tag the
  user's role allows; it never reaches the API. There is no anonymous mode over SSH.
- **Host key:** generated under the git data directory on first start
  (`ssh_host_ed25519_key`; `AGENTRY_GIT_SSH_HOST_KEY` points elsewhere). The SHA256
  fingerprint is logged at startup (`git ssh listening … hostkey=…`) — publish it so users
  can pin it in `known_hosts`.
- **Advertising:** set `AGENTRY_GIT_SSH_PUBLIC_URL` (for example
  `ssh://git@git.example.com:2222`) and agent pages show the SSH clone URL next to HTTPS.
- **Enforced SSO:** an organization that requires SSO takes pushes only over HTTPS with an
  org-bound token; over SSH the push is refused with that message.

## Fronting it with a site

Everything above is a complete registry. The hosted service puts a site in
front of the same server — a closed front end that renders the catalogue,
the report cards, the Builder and the account pages in its own brand — and
so can you. The contract between a front end and this server is small and
entirely configuration:

- **`web.url` / `AGENTRY_WEB_URL`** — the site's origin. When it is set,
  every browser destination the API writes (where a failed sign-in lands,
  where a signed-in browser goes, where an email link points, where sign-out
  ends) is a page of that site instead of the server's `/ui/` pages. The
  site's paths are fixed by convention (`/login`, `/dashboard`,
  `/settings/…`, `/verify-email`); `internal/api/webpaths.go` is the one
  table that knows them.
- **`ui.mode` / `AGENTRY_UI_MODE`** — `full` serves every `/ui/` page,
  `authorize` keeps only the device-authorize page the CLI and the desktop
  app open (the site provides the rest), `off` serves none. A site in front
  normally runs `authorize`.
- **`brand.*` / `AGENTRY_BRAND_NAME`, `AGENTRY_BRAND_LOGO_URL`,
  `AGENTRY_BRAND_CSS_URL`, `AGENTRY_SUPPORT_EMAIL`, `AGENTRY_SECURITY_EMAIL`**
  — what the server calls the deployment in emails, in the directory's flow
  titles and authenticator names, and on the `/ui/` pages that remain; the
  stylesheet and logo the remaining pages load. `GET /api/v1/meta` reports
  `brand` and `ui` (with `authorizeUrl`) so clients need no other
  configuration.
- **The directory's returns** — `AGENTRY_PUBLIC_WEB_URL` (where sign-out
  lands) and `AGENTRY_ACCOUNT_URL` (where a password or authenticator change
  returns) default to the server's own pages; a site sets them to its home
  and its settings page, and applies its own brand object to the directory
  through the directory's API (the flows stay the core's blueprint).
  `AGENTRY_IDP_LOGOUT_URL` stays on the provider's end-session endpoint.
- **The edge** — a site replaces `edge/nginx.conf` with one that sends
  `/api/`, git, `/ui/` and `/downloads/` to the server and everything else to
  the site, and adds rate-limit zones for its own forms.

In compose that is one overlay file: a second `-f` that adds the site's
services, replaces the edge config, and sets the variables above; the core
stack is untouched. The site talks to the same API as the CLI, with the
browser's session cookie, under the same authorization matrix — a front end
cannot do anything the API refuses, and the server's own `/ui/` pages are the
proof that the API is enough.

A closed build can also extend the server itself: `pkg/extension` lets an
outside Go module mount routes under `/api/v1/x/<name>/`, run its own
migrations in its own schema, replace the entitlements resolver, subscribe to
committed events and add worker jobs, with `GET /api/v1/meta` listing what is
loaded. The core carries no extension and behaves identically with none.
