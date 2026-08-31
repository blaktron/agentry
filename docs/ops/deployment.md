# Deployment (WG-K)

How Agentry is deployed in its three shapes, and the operational targets.
Infra-as-code lives in `deploy/terraform/` (SaaS reference + reusable
modules) and `deploy/helm/agentry/` (self-host HA). Authoritative design:
[PLAN.md](https://github.com/blaktron/agentry-notes/blob/main/agentry/PLAN.md) §2.4, §13, §16.

## The three deployment shapes (§2.4)

| Shape | What runs | Where it's defined |
|---|---|---|
| **Dev / small self-host** | `agentryd all` (every role in-process, **including the queue worker**) + Postgres; Redis/S3 optional | `deploy/compose/` (M0) |
| **Self-host HA** | Helm: api ×N, git ×N (shared RWX volume), worker ×N, web ×N; Postgres + object store operator-supplied | `deploy/helm/agentry/` |
| **SaaS (Agentry Cloud)** | ECS Fargate per role, RDS, EFS, S3, Redis, Bedrock judge | `deploy/terraform/` |

Same binary throughout; the shape only changes how the roles are split and what
backs Postgres / object storage.

`agentryd all` runs the queue worker in-process, so webhook deliveries, audit
exports and queue-driven scans are claimed on a single-process install. Do not
also run a separate `agentryd worker` against the same database in this shape;
it is harmless (the queue claims `FOR UPDATE SKIP LOCKED`) but doubles the poll
traffic for no gain.

### Container images

Two images per release, built and signed by `.github/workflows/release.yaml`:

| Image | Dockerfile | Contents |
|---|---|---|
| `agentryd` | `deploy/compose/Dockerfile` | The server, **all four roles**, on debian-slim with `git` |
| `web` | `deploy/compose/Dockerfile.web` | The Next.js app, production deps only |

One agentryd image rather than a separate git image: the `git` role needs a git
binary, and so does `all`, which mounts the git routes in-process. Splitting
would have fixed one and left the other broken, and would mean two tags per
commit to keep in step. The base is debian-slim rather than distroless because
git needs a real userland. See DEV-030.

## SaaS topology (Terraform)

Region: single-region v1, `us-east-1` by default (**Q8**, set per env in
`terraform.tfvars`). Accounts (§13.1): `prod`, `nonprod` (dev + staging as
separate VPCs), `security` (org CloudTrail + audit-archive replication target).
Humans use IAM Identity Center; **no IAM users**. GitHub Actions deploys via an
OIDC role.

```
Route53 ─┬─ CloudFront ── WAF(web) ── ALB(app) ─┬─ ECS web
         │        └── OAC ── S3 releases         └─ ECS api
         └─ git.* ─────────── WAF(git) ── ALB(git) ── ECS git ── EFS
                                     VPC 10.0.0.0/16 (3 AZ)
   private-app:  web · api · git · worker-core · worker-sandbox · worker-judge
   private-data: RDS Postgres 16 (Multi-AZ) · ElastiCache Redis · EFS
   VPC endpoints: S3(gw) · ECR · Logs · Secrets · KMS · Bedrock · SES
```

### Module map (`deploy/terraform/`)

| Module | Provisions |
|---|---|
| `modules/network` | VPC, 3 subnet tiers × AZ, IGW, NAT, route tables, S3 gateway + interface endpoints, tier/identity SGs |
| `modules/ecs-service` | Reusable Fargate service: task def, service, autoscaling, SG + **egress profile**, log group, optional EFS mount, optional ALB target group, ADOT sidecar |
| `modules/rds` | Postgres 16 db.r6g.large Multi-AZ, gp3, PI, PITR, encrypted; publishes the DSN to Secrets Manager |
| `modules/elasticache` | Redis 7 (2× cache.t4g.small); publishes `rediss://` URL to Secrets Manager |
| `modules/efs` | EFS elastic, uid-scoped access points, mount targets, AWS Backup daily/35d |
| `modules/s3-suite` | `releases` (object-lock 2y, deny-delete, OAC, EventBridge), `evidence` (IA 90d), `audit-archive` (compliance 400d, cross-account replication) |
| `modules/cloudfront` | Distribution: S3 releases via OAC + ALB origin (cache off), security headers, TLS 1.2+ |
| `modules/waf` | web/API ACL (core + known-bad + rate) and git ACL (core minus packfile body rules + rate) |
| `modules/kms` | Data key (rotating) + ECDSA P-256 signing key restricted to worker-core (D-16) |
| `modules/observability` | ADOT config param, dashboards (API/git/pipeline/security), §16.3 alarms, SNS page/ticket |
| `global/{accounts,dns,ecr}` | Org + OIDC deploy role · Route53 + ACM · ECR repos (scan-on-push, lifecycle) |

### The six services (all from `modules/ecs-service`)

| Service | Command | LB | Egress profile | Extra |
|---|---|---|---|---|
| web | (Next.js) | app ALB | full (NAT) | none |
| api | `agentryd api` | app ALB | full (NAT) + S3/RDS/Redis | task role: read releases, r/w evidence |
| git | `agentryd git` | git ALB | **no NAT**; endpoints + RDS + EFS | EFS mount `/data/git`; no S3-releases write |
| worker-core | `agentryd worker --queues=core` | none | full (NAT) + S3/RDS/Redis/EFS | **only** role with `kms:Sign` + SES |
| worker-sandbox | `agentryd worker --queues=sandbox` | none | **no NAT**; endpoints + S3 + RDS | read-only rootfs; read releases, findings via DB only |
| worker-judge | `agentryd worker --queues=judge` | none | **no NAT**; endpoints + S3 + RDS | read-only rootfs; `bedrock:InvokeModel` |

The sandbox/judge jails (§8.2) are expressed in `modules/ecs-service` by setting
`allow_all_egress = false`: with no `0.0.0.0/0` route, the only egress rules that
exist are the scoped `egress_*` allowances. Sandbox reaches S3 (archives) + RDS
(findings) + the interface endpoints (ECR/Logs/KMS to start & log); judge adds
Bedrock (via the shared endpoints SG). Data-tier ingress (RDS/Redis/EFS) is
restricted to the app-tier / git-tier identity SGs, so "only app SGs" holds
without SG cycles.

### App configuration wiring

`agentryd` reads `AGENTRY_*` (see `internal/config/config.go`). The env sets:

- Non-secret (task env): `AGENTRY_ENV`, `AGENTRY_BASE_URL`, `AGENTRY_STORAGE_KIND=s3`,
  `AGENTRY_STORAGE_S3_BUCKET/REGION`, `AGENTRY_SIGNING_KIND=kms` +
  `AGENTRY_SIGNING_KMS_KEY_ARN`, `AGENTRY_JUDGE_PROVIDER=bedrock` + model/region,
  `AGENTRY_OTEL_ENDPOINT=http://localhost:4318` (the sidecar), and
  `AGENTRY_TRUSTED_PROXIES` (`2` for api/web behind CloudFront→ALB, `1` for git).
- Secret (Secrets Manager → container `secrets`): `AGENTRY_DATABASE_URL` (RDS DSN),
  `AGENTRY_REDIS_URL` (api/worker-core only), `AGENTRY_AUTH_SEALING_KEY` (random 32B).
  Add `AGENTRY_SMTP_PASS` here if SMTP notifications are turned on.

`AGENTRY_SIGNING_KIND=kms` is set on every agentryd service so config validation
passes, but only worker-core's task role is granted `kms:Sign` (IAM) and the KMS
key policy further restricts Sign to that exact role ARN by condition. The KMS
signer fetches its public key once at startup, so serving
`signing-keys.json` never turns into `kms:Sign` volume and cannot muddy the
T-09 anomaly signal.

Config is validated at boot and **refuses to start** on a contradiction rather
than degrading: `storage.kind=s3` with no bucket, `signing.kind=kms` with no
key ARN, `notify.kind=smtp` with no host or sender, an SMTP username without
STARTTLS outside dev, an inverted signing validity window, or a session/PAT TTL
above the §12.3/§12.4 maxima (24 h session, 1 y PAT, 90 d org-bound PAT).

## Self-host HA (Helm)

`helm install agentry deploy/helm/agentry`. Deploys `api`, `git` (shared RWX
PVC at `/data/git`), `worker` (all queues by default), and `web`, with Services,
Ingress (web + git hosts), HPAs, a ConfigMap (`agentry.yaml`), and a Secret.

Operator-supplied (NOT bundled; see `values.yaml`): PostgreSQL 16
(`secret.databaseUrl`), object storage (`config.storage.*` + IRSA/creds), and
optional Redis (`secret.redisUrl`). Provide a `ReadWriteMany` StorageClass for
the git volume (EFS CSI, Filestore, NFS).

## Deploy pipeline (`.github/workflows/terraform.yaml`)

1. **Every PR / push**: `terraform fmt -check`, `init -backend=false` +
   `validate` for each module and env, `tflint`, `helm lint`, and
   `scripts/acceptance/m7.sh`.
2. **Plan on PR**: `terraform plan` per env, via OIDC role assumption
   (no long-lived keys). Requires `AWS_DEPLOY_ROLE_ARN` repo var.
3. **Apply on merge to `main`**: dev + staging apply automatically; **prod apply
   is gated by the `prod` GitHub Environment**. Add required reviewers there for
   the §13.7 manual approval.

State is S3 + DynamoDB lock, one key per env (`backend.tf`, placeholders; create
the bucket/table out-of-band, then `terraform init`).

### First-time bring-up order

1. `global/` (org, OIDC role, Route53 zones + ACM certs, ECR repos).
2. Delegate the registrar to the Route53 name servers; wait for ACM validation.
3. Populate each env `terraform.tfvars` from `global` outputs (cert ARNs, image
   URIs, zone id, security-account bucket ARN).
4. `envs/dev` → `envs/staging` → `envs/prod`.
5. Push images to ECR; ECS rolls out.

## Backup / DR targets (§13.6)

| Target | Value | Mechanism |
|---|---|---|
| **RPO** | 15 min | RDS PITR (`backup_retention_period`); EFS/S3 near-real-time durable |
| **RTO** | 4 h | Runbook-driven in-region restore; infra is `terraform apply`-reproducible |

- RDS: automated backups + PITR (prod 35d), Multi-AZ standby; failover raises a
  page alarm (EventBridge → SNS).
- EFS: AWS Backup daily, 35d retention.
- S3: `releases` object-lock governance 2y + deny-delete; `audit-archive`
  object-lock compliance 400d + replication to the security account.
- **Quarterly restore drill** is an operational acceptance criterion (M8); the
  RDS restore + EFS restore runbooks (§16.4) are the procedure. Multi-region is
  explicitly out of v1.

## Observability (§16)

`agentryd` emits metrics two ways from one instrument set (`internal/metrics`):

- **OTLP/HTTP** when `AGENTRY_OTEL_ENDPOINT` is set. The terraform envs set it
  to `http://localhost:4318`, the ADOT sidecar every agentryd service runs. The
  collector ships traces to X-Ray and metrics to CloudWatch as EMF under the
  `Agentry` namespace. Unset (the default) disables OTLP entirely: no
  exporter, no connection attempts.
- **Prometheus** at `GET /metrics`, always on, for self-host (D-25). See the
  bind-address note below.

### Metrics actually emitted

These are the exact instrument names, and they are the names the dashboards and
alarms in `modules/observability` reference. The Prometheus exposition uses the
same names, so a CloudWatch alarm and a self-hosted scrape describe the same
series.

| Metric | Type | Attributes | Used by |
|---|---|---|---|
| `HttpRequests` | counter | route, method, status_class | RED |
| `HttpRequestDurationSeconds` | histogram | route, method | RED latency |
| `QueueDepth` | gauge | queue | pipeline dashboard, worker autoscaling |
| `QueueAgeSeconds` | gauge | queue | **PAGE**: queue age > 15 min |
| `QueueJobs` | counter | queue, kind, outcome | job outcome mix |
| `ScanStageRuns` | counter | stage | **PAGE**: scan error rate > 5% (denominator) |
| `ScanStageErrors` | counter | stage | **PAGE**: scan error rate > 5% (numerator) |
| `ScanStageDurationSeconds` | histogram | stage | pipeline dashboard |
| `ScanStageHits` | counter | stage | security dashboard (an S3 spike is an attack-wave signal) |
| `PublishSubmitted` | counter | none | publish funnel |
| `PublishVerdictClean` / `…Review` / `…Blocked` | counter | none | publish funnel, verdict mix |
| `JudgeCostCents` | counter | none | budget anomaly (ticket); **not yet emitted, see below** |
| `GitOps` | counter | op, outcome | git dashboard |
| `GitOpDurationSeconds` | histogram | op | git dashboard |
| `GitOpConcurrency` | gauge | op | git dashboard, git autoscaling signal |
| `GitCloneFirstByteSeconds` | histogram | none | §16.1 SLI: p95 < 2 s |
| `WebhookDeliveries` | counter | outcome (`ok`/`error`/`throttled`) | delivery health |

`route` is the **matched route pattern** (`/agents/{ns}/{name}`), never the
concrete path; a per-path metric would let any caller mint unbounded series.
`status_class` is `2xx`/`4xx`/`5xx` for the same reason.

An instrument with no observations yet is absent from a scrape; the
alarms are configured `treat_missing_data = "notBreaching"` to match.

**`JudgeCostCents` carries no data today.** The instrument exists and the
pipeline dashboard plots it, but no judge provider reports a cost:
`bedrock`, `anthropic` and `classifier` all resolve to `UnconfiguredProvider`,
and `scan.JudgeVerdict` has no cost field to carry one. The recording seam is
`metrics.RecordJudgeCost`, one call from the S5 stage away. Whoever
implements a real provider should populate it; until then that dashboard
panel is empty rather than zero. Do not read an empty panel as "no spend".

**Dimension rollup.** The §16.3 alarms address `QueueAgeSeconds`,
`ScanStageErrors` and `ScanStageRuns` with no dimensions, while the app emits
them with `queue` / `stage` attributes for the dashboards. The collector is
therefore set to `ZeroAndSingleDimensionRollup`, which publishes the
zero-dimension aggregate alongside the per-attribute series. Under the previous
`NoDimensionRollup` the zero-dimension series would not exist and those three
page alarms would never fire, while looking correctly configured.

### `/metrics` is unauthenticated, so bind it accordingly

`/metrics` is mounted outside `/api/v1` next to `/healthz` and `/readyz`, and
like them it has no auth: a scraper is infrastructure, not a principal, and the
§12.2 RBAC chokepoint has no way to express one.

It exposes no user content (request rates, queue depth, stage timings) but it
does describe traffic shape and catalogue activity. On SaaS the ALB listener
rules only forward `/api/*`, `/.well-known/*` and `/scim/*` to the api service,
so `/metrics` is not reachable from the internet. Self-hosting: either bind
`AGENTRY_HTTP_ADDR` to a private interface, or block `/metrics` at your ingress
(the chart's `ingress.apiPaths` does not include it).

### Alarms and routing

Page: availability burn, queue age > 15 min, scan error rate > 5%, RDS
failover, KMS Sign anomaly (T-09, from CloudTrail data events), WAF block
spike. Wire `page_subscriptions` / `ticket_subscriptions` (PagerDuty, email)
per env.

## Notifications / email (§13.4)

`AGENTRY_NOTIFY_KIND` selects the transport:

| Kind | Behaviour |
|---|---|
| `log` (default) | Writes what it *would* have sent to the log. A fresh install never silently fails to deliver; the line says the mail was not sent. |
| `smtp` | Real delivery via `AGENTRY_SMTP_{HOST,PORT,USER,PASS,FROM}` + `AGENTRY_SMTP_STARTTLS`. |

Sent on: email verification, review verdict decided, quarantine after rescan,
advisory published, and org membership granted. Bodies are plain text and
follow §1.6.3: they say "scanned, N findings, signed", never "safe".

There is no separate invite object in v1: org membership is granted by an
admin rather than offered and accepted, so the "invite" mail rides the same
transition that fires the `member.added` webhook.

**Dev.** The compose stack runs mailpit; `deploy/compose/docker-compose.yaml`
points the server service at `mailpit:1025` with STARTTLS off, and every message
lands in the web UI on `:8025`. Plaintext SMTP is correct for mailpit and wrong
for anything else; config validation refuses `smtp.username` without STARTTLS
outside dev mode.

**AWS.** Point SMTP at **SES's SMTP endpoint**
(`email-smtp.<region>.amazonaws.com:587`, STARTTLS on) using SES SMTP
credentials, which are IAM credentials converted to an SMTP username/password.
The terraform already grants `ses:SendEmail` to worker-core and provisions the
SES VPC endpoint. There is deliberately **no SES-SDK integration and no SES
terraform**: domain identity, DKIM keys, and the SPF/DMARC DNS records are
operator setup that depends on the unresolved **Q8** region/domain decision.
See DEV-028.

Put the SMTP password in Secrets Manager (SaaS) or `secret.smtpPassword` /
`existingSecret` (Helm), never in the ConfigMap.

## Signing keys and rotation (§8.8)

`GET /.well-known/agentry/signing-keys.json` publishes `keyId`, `algorithm`,
`publicKeyPem`, and an optional `notBefore` / `notAfter` validity window per
key. The window is what makes §8.8's "rotation = overlapping validity windows"
expressible: the document can list more than one key at a time.

To rotate:

1. Create the new key; publish it as `signing.additionalKeys[]` with a
   `notBefore`, while the current key keeps signing.
2. Switch `signing.kmsKeyARN` to the new key and give the outgoing key a
   `notAfter`, moving it into `additionalKeys`.
3. Drop the outgoing key from `additionalKeys` once nothing needs to verify
   attestations it signed. Attestations are signed once and never re-issued
   (§7), so old envelopes stay verifiable only while their key is published.

Windows are optional; a key with neither bound is unbounded, which is the
correct description of a deployment that has never rotated.

## Quotas (§19)

The §19 limits are resolved through `internal/entitlements`, whose OSS
implementation reads them from config, so an operator raises a limit by
setting a value, not by patching a constant. Chart: `config.limits.*`. Env:
`AGENTRY_LIMITS_*` (see `internal/config/config.go`).

Two of them are enforced with in-process token buckets and are therefore
**approximate across replicas**: an N-replica fleet allows roughly N× the
budget:

- webhook deliveries, 5/s per org (over budget, the delivery is deferred back
  onto the queue, not dropped)
- git pushes, 60/h per repo (over budget, `429` before git is even started)

D-06 makes Redis the answer for exact multi-node limits; that swap goes behind
the same `internal/ratelimit` interface.

### Client IP behind a proxy

Per-IP rate limits and audit records key on `AGENTRY_TRUSTED_PROXIES`, the
number of reverse-proxy hops in front of agentryd:

| Deployment | Value |
|---|---|
| Direct (default, `0`) | X-Forwarded-For ignored entirely |
| Behind one ingress/ALB | `1` |
| CloudFront → ALB → task | `2` (what the terraform envs set for api/web; git is `1`; no CDN in front of `git.*`) |

X-Forwarded-For is client-supplied. Setting this **higher** than the real hop
count lets a caller choose which rate-limit bucket to spend, including someone
else's, and forge the address the audit log records. It must match the
deployment exactly.

## Open questions this IaC leaves as tfvars (§20)

- **Q8 region / data residency**: `aws_region` (default `us-east-1`) in each env
  and in `global`; `backend.tf` region comment.
- **Q3 judge model**: `judge_model` (default Sonnet-class Bedrock id).
- Cross-account audit replication + T-09 alarm source:
  `audit_replication_destination_bucket_arn` / `..._account_id`,
  `cloudtrail_log_group_name` (empty ⇒ feature off).
- Domains + certs: `apex_domain`, `git_domain`, `acm_*_certificate_arn`,
  `route53_zone_id` (all placeholder; empty zone id skips DNS records).
- Image URIs, alert subscriptions, and the state bucket/table names.
