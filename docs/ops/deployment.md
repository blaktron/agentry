# Deployment (WG-K)

How Agentry is deployed, the three shapes it runs in, and the operational
targets. Infra-as-code lives in `deploy/terraform/` (SaaS reference + reusable
modules) and `deploy/helm/agentry/` (self-host HA). Authoritative design:
[PLAN.md](../../PLAN.md) §2.4, §13, §16.

## The three deployment shapes (§2.4)

| Shape | What runs | Where it's defined |
|---|---|---|
| **Dev / small self-host** | `agentryd all` (every role in-process) + Postgres; Redis/S3 optional | `deploy/compose/` (M0) |
| **Self-host HA** | Helm: api ×N, git ×N (shared RWX volume), worker ×N, web ×N; Postgres + object store operator-supplied | `deploy/helm/agentry/` |
| **SaaS (Agentry Cloud)** | ECS Fargate per role, RDS, EFS, S3, Redis, Bedrock judge | `deploy/terraform/` |

Same binary throughout; the shape only changes how the roles are split and what
backs Postgres / object storage.

## SaaS topology (Terraform)

Region: single-region v1, `us-east-1` by default (**Q8**, set per env in
`terraform.tfvars`). Accounts (§13.1): `prod`, `nonprod` (dev + staging as
separate VPCs), `security` (org CloudTrail + audit-archive replication target).
Humans use IAM Identity Center; **no IAM users** — GitHub Actions deploys via an
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
| web | (Next.js) | app ALB | full (NAT) | — |
| api | `agentryd api` | app ALB | full (NAT) + S3/RDS/Redis | task role: read releases, r/w evidence |
| git | `agentryd git` | git ALB | **no NAT**; endpoints + RDS + EFS | EFS mount `/data/git`; no S3-releases write |
| worker-core | `agentryd worker --queues=core` | — | full (NAT) + S3/RDS/Redis/EFS | **only** role with `kms:Sign` + SES |
| worker-sandbox | `agentryd worker --queues=sandbox` | — | **no NAT**; endpoints + S3 + RDS | read-only rootfs; read releases, findings via DB only |
| worker-judge | `agentryd worker --queues=judge` | — | **no NAT**; endpoints + S3 + RDS | read-only rootfs; `bedrock:InvokeModel` |

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
  `AGENTRY_SIGNING_KMS_KEY_ARN`, `AGENTRY_JUDGE_PROVIDER=bedrock` + model/region.
- Secret (Secrets Manager → container `secrets`): `AGENTRY_DATABASE_URL` (RDS DSN),
  `AGENTRY_REDIS_URL` (api/worker-core only), `AGENTRY_AUTH_SEALING_KEY` (random 32B).

`AGENTRY_SIGNING_KIND=kms` is set on every agentryd service so config validation
passes, but only worker-core's task role is granted `kms:Sign` (IAM) and the KMS
key policy further restricts Sign to that exact role ARN by condition.

## Self-host HA (Helm)

`helm install agentry deploy/helm/agentry`. Deploys `api`, `git` (shared RWX
PVC at `/data/git`), `worker` (all queues by default), and `web`, with Services,
Ingress (web + git hosts), HPAs, a ConfigMap (`agentry.yaml`), and a Secret.

Operator-supplied (NOT bundled — see `values.yaml`): PostgreSQL 16
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
   is gated by the `prod` GitHub Environment** — add required reviewers there for
   the §13.7 manual approval.

State is S3 + DynamoDB lock, one key per env (`backend.tf`, placeholders — create
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

OTel → ADOT sidecar → CloudWatch (traces to X-Ray, RED/queue/scan/judge metrics
as EMF). Dashboards: API, git, pipeline (submit→verdict funnel), security
(S-stage hit rates — an S3 spike is an attack-wave signal). Page alarms:
availability burn, queue age > 15 min, scan error rate > 5%, RDS failover, KMS
Sign anomaly (T-09, from CloudTrail data events), WAF block spike. Wire
`page_subscriptions` / `ticket_subscriptions` (PagerDuty, email) per env.

## Open questions this IaC leaves as tfvars (§20)

- **Q8 region / data residency** — `aws_region` (default `us-east-1`) in each env
  and in `global`; `backend.tf` region comment.
- **Q3 judge model** — `judge_model` (default Sonnet-class Bedrock id).
- Cross-account audit replication + T-09 alarm source —
  `audit_replication_destination_bucket_arn` / `..._account_id`,
  `cloudtrail_log_group_name` (empty ⇒ feature off).
- Domains + certs — `apex_domain`, `git_domain`, `acm_*_certificate_arn`,
  `route53_zone_id` (all placeholder; empty zone id skips DNS records).
- Image URIs, alert subscriptions, and the state bucket/table names.
