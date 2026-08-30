# Self-hosting Agentry

The whole product is open source: the scanners, the review queue, SSO and
SCIM, signing with your own key. There is no "community edition" with the
security features removed; a registry you cannot audit is not trust
infrastructure.

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

Then create the first account:

```bash
curl -sX POST http://localhost:8080/api/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"handle":"you","email":"you@example.com","password":"a-long-passphrase"}'
```

Email verification is required before publishing. In a dev setup the token is
logged at debug level and mailpit (http://localhost:8025) catches the message;
in production configure real SMTP.

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
$CLI init --kind=skill my-first-agent
cd my-first-agent && $CLI validate
```

`validate` runs the same manifest rules and the same hidden-content and
injection-signature scanners the server runs at publish time, offline.

## Deployment shapes

| Shape | What runs | Who it is for |
|---|---|---|
| **Single process** | `agentryd all` + Postgres | evaluation, small teams |
| **HA** | Helm chart: `api`×N, `git`×N (shared RWX volume), `worker`×N, `web`×N | production self-host |
| **AWS reference** | the Terraform modules in `deploy/terraform` | mirrors how the hosted service runs |

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

judge:
  provider: none        # none | bedrock | anthropic
```

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
an instance or task role, not keys in this file. The Terraform in
`deploy/terraform` provisions both the bucket and a key whose `kms:Sign`
permission is restricted to the worker task role.

**Honest caveat:** these two backends have **not yet been exercised against a
live AWS account**. The Terraform is validated but never applied, and the
build environment has no AWS credentials, so the first real deployment is
also the first integration test. `local` + `file` are the paths with mileage
on them. If you are standing up production on S3 and KMS, publish a throwaway
version first and confirm the archive round-trips and `agentry verify`
passes before you trust it with anything.

### Social login

Individual accounts can sign in with Google or GitHub (§12.1). Both are
optional and independent: **a provider with no client id is not offered at
all**. Its start endpoint returns 404, so probing cannot distinguish
"misconfigured" from "not enabled".

```yaml
social:
  google:
    clientId: "…apps.googleusercontent.com"
    clientSecret: "…"
  github:
    clientId: "Iv1.…"
    clientSecret: "…"
```

Env: `AGENTRY_SOCIAL_GOOGLE_CLIENT_ID`, `AGENTRY_SOCIAL_GOOGLE_CLIENT_SECRET`,
`AGENTRY_SOCIAL_GITHUB_CLIENT_ID`, `AGENTRY_SOCIAL_GITHUB_CLIENT_SECRET`.

Register the callback with each provider as
`{baseURL}/api/v1/auth/oidc/{google|github}/callback`, so `baseURL` must be
set correctly for social login to work at all.

Two behaviours worth knowing before you enable this (both are DEV-019):

- **Google is real OIDC**: discovery, issuer pinning, PKCE, ID-token
  signature and nonce verification. **GitHub is an OAuth 2.0 shim**: there is
  no ID token to verify, so the trust anchor is TLS to `api.github.com` plus
  your client secret. There is no PKCE; a sealed single-use state cookie
  is what binds a callback to the browser that started it. An email is
  recorded only when GitHub reports it both primary *and* verified.
- **Social login is not a way around 2FA.** A redirect callback has nowhere
  to carry a TOTP code, so an account with 2FA enrolled receives a sealed
  five-minute challenge instead of a session, completed at
  `POST /api/v1/auth/2fa/totp/challenge`.

### Audit archive and retention

Every audit event is written to the `audit_events` table. It is partitioned
monthly and protected by an append-only trigger: rows cannot be updated or
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
target and catches everything, so nothing leaves the machine. With no SMTP
configured at all, email verification tokens are logged at debug level.
That is usable for a single-operator instance, not for anything with real
users.

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

### Running behind a proxy

Rate limiting (§19) buckets anonymous traffic per client IP. Behind a load
balancer, every request appears to come from the balancer unless you say
otherwise:

```yaml
http:
  trustedProxies: 2   # number of reverse-proxy hops in front of agentryd
```

Env: `AGENTRY_TRUSTED_PROXIES` (an integer hop count, not a CIDR list).

`X-Forwarded-For` is honoured **only** up to that many trusted hops: behind
CloudFront → ALB set `2`; behind a single load balancer set `1`. Leave it at
`0` (the default) if the server is directly exposed. The header is then
ignored entirely. Setting it higher than the real hop count lets any client
choose its own rate-limit bucket and forge audit IPs, which is worse than
having no per-IP limiting at all.

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

Two notes on the knobs:

- `blockedCapabilities` rejects a submission that *declares* the capability;
  it is a gate on the manifest, not a runtime restriction. Combine it with
  `requireHumanReview: {"whenCapabilities": [...]}` if you want a look rather
  than a refusal.
- `allowedLicenses` intersects with the platform's SPDX allowlist, which is a
  curated set of 60 common identifiers rather than the full SPDX list. A
  valid but uncommon identifier will be refused for public publish even if
  you list it (DEV-042). Check `pkg/manifest/spdx.go` before standardising
  your org on something unusual.

## Operating it

- **Backups:** Postgres is the system of record. Back it up. Release archives
  are content-addressed and write-once; repos are recoverable from any clone.
  Losing the repo store breaks pushes, not published installs.
- **The worker matters.** With no worker running, versions sit in `scanning`
  and never publish. That is the fail-closed design working, but it looks like
  a hang. Check the worker first when publishes stall.
- **Rescan after ruleset updates.** New detection only protects you if you
  apply it to what you already published; the rescan sweep quarantines
  versions that newly trip a high finding.
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

None of that is different from the hosted service; it is just visible.
