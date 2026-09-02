# Environment composition (PLAN §13). Thin: it wires the modules and the edge
# (ALBs + WAF associations + CloudFront + DNS). Sizes come from tfvars so the
# same file serves dev/staging/prod.
#
# The six §13.3 services are six instantiations of modules/ecs-service. Their
# egress profiles below are where §8.2 lives: worker-sandbox and worker-judge
# set allow_all_egress=false (no 0.0.0.0/0), so their ONLY routes are the
# scoped allowances — sandbox = S3 + RDS (+ control plane); judge adds Bedrock.

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

data "aws_ec2_managed_prefix_list" "cloudfront" {
  name = "com.amazonaws.global.cloudfront.origin-facing"
}

locals {
  name       = "agentry-${var.environment}"
  account_id = data.aws_caller_identity.current.account_id
  base_url   = "https://${var.apex_domain}"

  # Constructed worker-core task role ARN — used in the KMS signing key policy
  # WITHOUT depending on the ECS module (breaks the cycle; the role is created
  # later with exactly this name by modules/ecs-service).
  worker_core_task_role_arn = "arn:${data.aws_partition.current.partition}:iam::${local.account_id}:role/${local.name}-worker-core-task"

  bedrock_model_arn = "arn:${data.aws_partition.current.partition}:bedrock:${var.aws_region}::foundation-model/*"

  # Common non-secret env for the agentryd services (§ internal/config).
  agentryd_env = {
    AGENTRY_ENV                 = var.environment
    AGENTRY_LOG_LEVEL           = "info"
    AGENTRY_BASE_URL            = local.base_url
    AGENTRY_DEV_MODE            = "false"
    AGENTRY_AUTH_COOKIE_SECURE  = "true"
    AGENTRY_HTTP_ADDR           = ":8080"
    AGENTRY_STORAGE_KIND        = "s3"
    AGENTRY_STORAGE_S3_BUCKET   = module.s3_suite.releases_bucket
    AGENTRY_STORAGE_S3_REGION   = var.aws_region
    AGENTRY_SIGNING_KIND        = "kms"
    AGENTRY_SIGNING_KMS_KEY_ARN = module.kms.signing_key_arn
    AGENTRY_JUDGE_PROVIDER      = "bedrock"
    AGENTRY_JUDGE_MODEL         = var.judge_model
    AGENTRY_JUDGE_REGION        = var.aws_region
    # External scanner tools (§8.3, agentry#40). gitleaks ships in the
    # image; OSV lookups are the scanner's one egress and stay opt-in.
    AGENTRY_SCAN_GITLEAKS_BIN = "/usr/bin/gitleaks"
    AGENTRY_SCAN_OSV_URL      = var.osv_url

    # OTLP to the ADOT sidecar on loopback (§16.2, D-25). Every agentryd
    # service in this file runs the sidecar, so this is set once here. Without
    # it the sidecar receives nothing and the §16.3 alarms below read metrics
    # that are never emitted — which is exactly the state this replaces.
    AGENTRY_OTEL_ENDPOINT = "http://localhost:4318"

    # CloudFront -> app ALB -> task, so the last two X-Forwarded-For hops were
    # written by infrastructure in this account. Anything earlier came from the
    # client. This MUST match the real hop count: set too high, callers can
    # pick their own per-IP rate-limit bucket (§19) and forge the address the
    # audit log records. The git service overrides it below — git.<domain> has
    # no CDN in front of it (§13.5).
    AGENTRY_TRUSTED_PROXIES = "2"
  }

  # Secrets injected from Secrets Manager (execution role reads; app sees value).
  core_secrets = {
    AGENTRY_DATABASE_URL     = module.rds.database_url_secret_arn
    AGENTRY_REDIS_URL        = module.elasticache.redis_url_secret_arn
    AGENTRY_AUTH_SEALING_KEY = aws_secretsmanager_secret.sealing.arn
  }
  # sandbox/judge don't use Redis (and can't reach it — no egress rule).
  no_redis_secrets = {
    AGENTRY_DATABASE_URL     = module.rds.database_url_secret_arn
    AGENTRY_AUTH_SEALING_KEY = aws_secretsmanager_secret.sealing.arn
  }

  efs_git_volume = {
    file_system_id    = module.efs.file_system_id
    access_point_id   = module.efs.access_point_ids["git"]
    mount_path        = "/data/git"
    security_group_id = module.efs.security_group_id
  }
}

# --- AGENTRY_AUTH_SEALING_KEY (base64 32 bytes; required outside dev) -------

resource "random_bytes" "sealing" {
  length = 32
}

resource "aws_secretsmanager_secret" "sealing" {
  name       = "agentry/${var.environment}/auth-sealing-key"
  kms_key_id = module.kms.data_key_arn
}

resource "aws_secretsmanager_secret_version" "sealing" {
  secret_id     = aws_secretsmanager_secret.sealing.id
  secret_string = random_bytes.sealing.base64
}

# --- Cluster ---------------------------------------------------------------

resource "aws_ecs_cluster" "this" {
  name = local.name
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

resource "aws_ecs_cluster_capacity_providers" "this" {
  cluster_name       = aws_ecs_cluster.this.name
  capacity_providers = ["FARGATE", "FARGATE_SPOT"]

  default_capacity_provider_strategy {
    capacity_provider = "FARGATE"
    weight            = 1
    base              = 1
  }
}

# --- Foundation modules ----------------------------------------------------

module "network" {
  source = "../../modules/network"

  name               = local.name
  aws_region         = var.aws_region
  az_count           = var.az_count
  single_nat_gateway = var.single_nat_gateway
}

module "kms" {
  source = "../../modules/kms"

  name        = local.name
  environment = var.environment
  # ONLY worker-core may kms:Sign (§13.3, D-16).
  signing_principal_arns = [local.worker_core_task_role_arn]
}

module "s3_suite" {
  source = "../../modules/s3-suite"

  name        = local.name
  environment = var.environment
  kms_key_arn = module.kms.data_key_arn

  audit_replication_destination_bucket_arn = var.audit_replication_destination_bucket_arn == "" ? null : var.audit_replication_destination_bucket_arn
  audit_replication_destination_account_id = var.audit_replication_destination_account_id == "" ? null : var.audit_replication_destination_account_id
}

module "rds" {
  source = "../../modules/rds"

  name                       = local.name
  environment                = var.environment
  vpc_id                     = module.network.vpc_id
  subnet_ids                 = module.network.data_subnet_ids
  allowed_security_group_ids = [module.network.app_tier_security_group_id]
  kms_key_arn                = module.kms.data_key_arn

  instance_class          = var.rds_instance_class
  multi_az                = var.rds_multi_az
  backup_retention_period = var.rds_backup_retention_period
  allocated_storage       = var.rds_allocated_storage
  deletion_protection     = var.environment == "prod"
}

module "elasticache" {
  source = "../../modules/elasticache"

  name                       = local.name
  environment                = var.environment
  vpc_id                     = module.network.vpc_id
  subnet_ids                 = module.network.data_subnet_ids
  allowed_security_group_ids = [module.network.app_tier_security_group_id]
  kms_key_arn                = module.kms.data_key_arn

  node_type     = var.redis_node_type
  replica_count = var.redis_replica_count
}

module "efs" {
  source = "../../modules/efs"

  name                       = local.name
  environment                = var.environment
  vpc_id                     = module.network.vpc_id
  subnet_ids                 = module.network.data_subnet_ids
  allowed_security_group_ids = [module.network.git_tier_security_group_id]
  kms_key_arn                = module.kms.data_key_arn
}

module "waf" {
  source = "../../modules/waf"

  name        = local.name
  environment = var.environment
  scope       = "REGIONAL"
}

module "observability" {
  source = "../../modules/observability"

  name        = local.name
  environment = var.environment
  aws_region  = var.aws_region

  app_alb_arn_suffix        = aws_lb.app.arn_suffix
  git_alb_arn_suffix        = aws_lb.git.arn_suffix
  rds_instance_id           = module.rds.instance_identifier
  signing_key_id            = module.kms.signing_key_id
  web_acl_metric_name       = module.waf.web_acl_name
  cloudtrail_log_group_name = var.cloudtrail_log_group_name == "" ? null : var.cloudtrail_log_group_name

  page_subscriptions   = var.page_subscriptions
  ticket_subscriptions = var.ticket_subscriptions
}

# --- ALBs (app: web/api behind CloudFront; git: direct, tuned WAF) ---------

resource "aws_security_group" "alb_app" {
  name        = "${local.name}-alb-app"
  description = "app ALB — 443/80 from CloudFront origin-facing prefix list only."
  vpc_id      = module.network.vpc_id

  ingress {
    description     = "HTTPS from CloudFront"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    prefix_list_ids = [data.aws_ec2_managed_prefix_list.cloudfront.id]
  }
  ingress {
    description     = "HTTP from CloudFront (redirect)"
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    prefix_list_ids = [data.aws_ec2_managed_prefix_list.cloudfront.id]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [module.network.vpc_cidr]
  }
}

resource "aws_lb" "app" {
  name               = "${local.name}-app"
  load_balancer_type = "application"
  internal           = false
  subnets            = module.network.public_subnet_ids
  security_groups    = [aws_security_group.alb_app.id]

  drop_invalid_header_fields = true
}

resource "aws_lb_listener" "app_http" {
  load_balancer_arn = aws_lb.app.arn
  port              = 80
  protocol          = "HTTP"
  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_lb_listener" "app_https" {
  load_balancer_arn = aws_lb.app.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.acm_alb_certificate_arn

  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      message_body = "not found"
      status_code  = "404"
    }
  }
}

resource "aws_wafv2_web_acl_association" "app" {
  resource_arn = aws_lb.app.arn
  web_acl_arn  = module.waf.web_acl_arn
}

resource "aws_security_group" "alb_git" {
  name        = "${local.name}-alb-git"
  description = "git ALB — 443/80 from the internet (git clients are arbitrary)."
  vpc_id      = module.network.vpc_id

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "HTTP (redirect)"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [module.network.vpc_cidr]
  }
}

resource "aws_lb" "git" {
  name               = "${local.name}-git"
  load_balancer_type = "application"
  internal           = false
  subnets            = module.network.public_subnet_ids
  security_groups    = [aws_security_group.alb_git.id]
}

resource "aws_lb_listener" "git_http" {
  load_balancer_arn = aws_lb.git.arn
  port              = 80
  protocol          = "HTTP"
  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_lb_listener" "git_https" {
  load_balancer_arn = aws_lb.git.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.acm_alb_certificate_arn

  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      message_body = "not found"
      status_code  = "404"
    }
  }
}

resource "aws_wafv2_web_acl_association" "git" {
  resource_arn = aws_lb.git.arn
  web_acl_arn  = module.waf.git_acl_arn
}

# --- Per-service least-privilege task-role policies (§13.3) -----------------

data "aws_iam_policy_document" "api" {
  statement {
    sid       = "ReadReleases"
    actions   = ["s3:GetObject"]
    resources = ["${module.s3_suite.releases_bucket_arn}/*"]
  }
  statement {
    sid       = "EvidenceRW"
    actions   = ["s3:GetObject", "s3:PutObject"]
    resources = ["${module.s3_suite.evidence_bucket_arn}/*"]
  }
  statement {
    sid       = "DataKey"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = [module.kms.data_key_arn]
  }
}

data "aws_iam_policy_document" "worker_core" {
  statement {
    sid       = "ReleasesRW"
    actions   = ["s3:GetObject", "s3:PutObject", "s3:ListBucket"]
    resources = [module.s3_suite.releases_bucket_arn, "${module.s3_suite.releases_bucket_arn}/*"]
  }
  statement {
    sid       = "EvidenceRW"
    actions   = ["s3:GetObject", "s3:PutObject"]
    resources = ["${module.s3_suite.evidence_bucket_arn}/*"]
  }
  statement {
    sid       = "AuditAppend"
    actions   = ["s3:PutObject"]
    resources = ["${module.s3_suite.audit_bucket_arn}/*"]
  }
  statement {
    sid       = "Sign"
    actions   = ["kms:Sign", "kms:GetPublicKey", "kms:DescribeKey"]
    resources = [module.kms.signing_key_arn]
  }
  statement {
    sid       = "DataKey"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = [module.kms.data_key_arn]
  }
  statement {
    sid       = "SendEmail"
    actions   = ["ses:SendEmail", "ses:SendRawEmail"]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "worker_sandbox" {
  statement {
    sid       = "ReadReleasesOnly"
    actions   = ["s3:GetObject"]
    resources = ["${module.s3_suite.releases_bucket_arn}/*"]
  }
  statement {
    sid       = "DecryptReleases"
    actions   = ["kms:Decrypt"]
    resources = [module.kms.data_key_arn]
  }
}

data "aws_iam_policy_document" "worker_judge" {
  statement {
    sid       = "ReadReleasesOnly"
    actions   = ["s3:GetObject"]
    resources = ["${module.s3_suite.releases_bucket_arn}/*"]
  }
  statement {
    sid       = "DecryptReleases"
    actions   = ["kms:Decrypt"]
    resources = [module.kms.data_key_arn]
  }
  statement {
    sid       = "InvokeJudge"
    actions   = ["bedrock:InvokeModel"]
    resources = [local.bedrock_model_arn]
  }
}

# --- Services (§13.3) ------------------------------------------------------

module "web" {
  source = "../../modules/ecs-service"

  name        = "web"
  environment = var.environment
  cluster_arn = aws_ecs_cluster.this.arn
  aws_region  = var.aws_region

  image          = var.web_image
  cpu            = var.service_scaling["web"].cpu
  memory         = var.service_scaling["web"].memory
  desired_count  = var.service_scaling["web"].desired_count
  min_count      = var.service_scaling["web"].min_count
  max_count      = var.service_scaling["web"].max_count
  container_port = 3000

  environment_variables = {
    NODE_ENV             = "production"
    PORT                 = "3000"
    AGENTRY_API_BASE_URL = local.base_url
  }
  readonly_root_filesystem = true
  enable_adot              = false

  vpc_id     = module.network.vpc_id
  subnet_ids = module.network.app_subnet_ids

  ingress_source_security_group_ids  = [aws_security_group.alb_app.id]
  allow_all_egress                   = true
  egress_endpoints_security_group_id = module.network.endpoints_security_group_id

  attach_alb                 = true
  alb_listener_arn           = aws_lb_listener.app_https.arn
  alb_arn_suffix             = aws_lb.app.arn_suffix
  alb_listener_rule_priority = 100
  alb_host_headers           = [var.apex_domain, "www.${var.apex_domain}"]
  health_check_path          = "/"
  scaling_metric             = "alb_request_count"
  scaling_target_value       = 1000
}

module "api" {
  source = "../../modules/ecs-service"

  name        = "api"
  environment = var.environment
  cluster_arn = aws_ecs_cluster.this.arn
  aws_region  = var.aws_region

  image          = var.agentryd_image
  command        = ["api"]
  cpu            = var.service_scaling["api"].cpu
  memory         = var.service_scaling["api"].memory
  desired_count  = var.service_scaling["api"].desired_count
  min_count      = var.service_scaling["api"].min_count
  max_count      = var.service_scaling["api"].max_count
  container_port = 8080

  environment_variables    = local.agentryd_env
  secrets                  = local.core_secrets
  kms_key_arns_for_secrets = [module.kms.data_key_arn]
  task_role_policy_json    = data.aws_iam_policy_document.api.json

  vpc_id                   = module.network.vpc_id
  subnet_ids               = module.network.app_subnet_ids
  extra_security_group_ids = [module.network.app_tier_security_group_id]

  ingress_source_security_group_ids  = [aws_security_group.alb_app.id]
  allow_all_egress                   = true
  egress_endpoints_security_group_id = module.network.endpoints_security_group_id
  egress_s3_prefix_list_id           = module.network.s3_prefix_list_id
  egress_rds_security_group_id       = module.rds.security_group_id
  egress_redis_security_group_id     = module.elasticache.security_group_id

  attach_alb                 = true
  alb_listener_arn           = aws_lb_listener.app_https.arn
  alb_arn_suffix             = aws_lb.app.arn_suffix
  alb_listener_rule_priority = 10
  alb_path_patterns          = ["/api/*", "/.well-known/*", "/scim/*"]
  health_check_path          = "/healthz"
  scaling_metric             = "cpu"
  scaling_target_value       = 60

  adot_config_ssm_arn = module.observability.adot_config_ssm_arn
}

module "git" {
  source = "../../modules/ecs-service"

  name        = "git"
  environment = var.environment
  cluster_arn = aws_ecs_cluster.this.arn
  aws_region  = var.aws_region

  image          = var.agentryd_image
  command        = ["git"]
  cpu            = var.service_scaling["git"].cpu
  memory         = var.service_scaling["git"].memory
  desired_count  = var.service_scaling["git"].desired_count
  min_count      = var.service_scaling["git"].min_count
  max_count      = var.service_scaling["git"].max_count
  container_port = 8080

  environment_variables = merge(local.agentryd_env, {
    AGENTRY_GIT_DATA_DIR = "/data/git"
    # git traffic reaches its own ALB directly — one trusted hop, not two.
    AGENTRY_TRUSTED_PROXIES = "1"
  })
  secrets                  = local.core_secrets
  kms_key_arns_for_secrets = [module.kms.data_key_arn]

  vpc_id                   = module.network.vpc_id
  subnet_ids               = module.network.app_subnet_ids
  extra_security_group_ids = [module.network.app_tier_security_group_id, module.network.git_tier_security_group_id]

  ingress_source_security_group_ids  = [aws_security_group.alb_git.id]
  allow_all_egress                   = false
  egress_endpoints_security_group_id = module.network.endpoints_security_group_id
  egress_rds_security_group_id       = module.rds.security_group_id

  efs_volume = local.efs_git_volume

  attach_alb                 = true
  alb_listener_arn           = aws_lb_listener.git_https.arn
  alb_arn_suffix             = aws_lb.git.arn_suffix
  alb_listener_rule_priority = 10
  alb_host_headers           = [var.git_domain]
  health_check_path          = "/healthz"
  scaling_metric             = "cpu"
  scaling_target_value       = 60

  adot_config_ssm_arn = module.observability.adot_config_ssm_arn
}

module "worker_core" {
  source = "../../modules/ecs-service"

  name        = "worker-core"
  environment = var.environment
  cluster_arn = aws_ecs_cluster.this.arn
  aws_region  = var.aws_region

  image         = var.agentryd_image
  command       = ["worker", "--queues=core"]
  cpu           = var.service_scaling["worker-core"].cpu
  memory        = var.service_scaling["worker-core"].memory
  desired_count = var.service_scaling["worker-core"].desired_count
  min_count     = var.service_scaling["worker-core"].min_count
  max_count     = var.service_scaling["worker-core"].max_count

  environment_variables    = local.agentryd_env
  secrets                  = local.core_secrets
  kms_key_arns_for_secrets = [module.kms.data_key_arn]
  task_role_policy_json    = data.aws_iam_policy_document.worker_core.json

  vpc_id                   = module.network.vpc_id
  subnet_ids               = module.network.app_subnet_ids
  extra_security_group_ids = [module.network.app_tier_security_group_id, module.network.git_tier_security_group_id]

  # worker-core needs the internet (webhooks, SES, S7 registry attestations).
  allow_all_egress                   = true
  egress_endpoints_security_group_id = module.network.endpoints_security_group_id
  egress_s3_prefix_list_id           = module.network.s3_prefix_list_id
  egress_rds_security_group_id       = module.rds.security_group_id
  egress_redis_security_group_id     = module.elasticache.security_group_id

  efs_volume = local.efs_git_volume # gc job touches repos (§6.2)

  scaling_metric        = "custom"
  scaling_target_value  = 100
  scaling_custom_metric = { namespace = "Agentry", metric_name = "QueueDepth", dimensions = { queue = "core" } }

  adot_config_ssm_arn = module.observability.adot_config_ssm_arn
}

# --- The §8.2 sandbox jail: no 0.0.0.0/0; only S3 + RDS + control plane ----
module "worker_sandbox" {
  source = "../../modules/ecs-service"

  name        = "worker-sandbox"
  environment = var.environment
  cluster_arn = aws_ecs_cluster.this.arn
  aws_region  = var.aws_region

  image         = var.agentryd_image
  command       = ["worker", "--queues=sandbox"]
  cpu           = var.service_scaling["worker-sandbox"].cpu
  memory        = var.service_scaling["worker-sandbox"].memory
  desired_count = var.service_scaling["worker-sandbox"].desired_count
  min_count     = var.service_scaling["worker-sandbox"].min_count
  max_count     = var.service_scaling["worker-sandbox"].max_count

  environment_variables    = local.agentryd_env
  secrets                  = local.no_redis_secrets
  kms_key_arns_for_secrets = [module.kms.data_key_arn]
  task_role_policy_json    = data.aws_iam_policy_document.worker_sandbox.json

  # Untrusted-content profile (§8.2): read-only root + scratch, non-root image.
  readonly_root_filesystem = true

  vpc_id                   = module.network.vpc_id
  subnet_ids               = module.network.app_subnet_ids
  extra_security_group_ids = [module.network.app_tier_security_group_id]

  # NO allow_all_egress -> no 0.0.0.0/0. Only these routes exist:
  allow_all_egress                   = false
  egress_endpoints_security_group_id = module.network.endpoints_security_group_id # ECR/Logs/KMS
  egress_s3_prefix_list_id           = module.network.s3_prefix_list_id           # read archives
  egress_rds_security_group_id       = module.rds.security_group_id               # write findings

  scaling_metric        = "custom"
  scaling_target_value  = 50
  scaling_custom_metric = { namespace = "Agentry", metric_name = "QueueDepth", dimensions = { queue = "sandbox" } }

  adot_config_ssm_arn = module.observability.adot_config_ssm_arn
}

# --- The §8.2 judge jail: egress adds Bedrock (via the endpoints SG) --------
module "worker_judge" {
  source = "../../modules/ecs-service"

  name        = "worker-judge"
  environment = var.environment
  cluster_arn = aws_ecs_cluster.this.arn
  aws_region  = var.aws_region

  image         = var.agentryd_image
  command       = ["worker", "--queues=judge"]
  cpu           = var.service_scaling["worker-judge"].cpu
  memory        = var.service_scaling["worker-judge"].memory
  desired_count = var.service_scaling["worker-judge"].desired_count
  min_count     = var.service_scaling["worker-judge"].min_count
  max_count     = var.service_scaling["worker-judge"].max_count

  environment_variables    = local.agentryd_env
  secrets                  = local.no_redis_secrets
  kms_key_arns_for_secrets = [module.kms.data_key_arn]
  task_role_policy_json    = data.aws_iam_policy_document.worker_judge.json

  readonly_root_filesystem = true

  vpc_id                   = module.network.vpc_id
  subnet_ids               = module.network.app_subnet_ids
  extra_security_group_ids = [module.network.app_tier_security_group_id]

  # Bedrock is reached through the shared interface-endpoints SG; still no
  # 0.0.0.0/0. (§8.2: judge's only external egress is the judge endpoint.)
  allow_all_egress                   = false
  egress_endpoints_security_group_id = module.network.endpoints_security_group_id # Bedrock + ECR/Logs
  egress_s3_prefix_list_id           = module.network.s3_prefix_list_id
  egress_rds_security_group_id       = module.rds.security_group_id

  scaling_metric        = "custom"
  scaling_target_value  = 20
  scaling_custom_metric = { namespace = "Agentry", metric_name = "QueueDepth", dimensions = { queue = "judge" } }

  adot_config_ssm_arn = module.observability.adot_config_ssm_arn
}

# --- CloudFront (fronts the app ALB; serves releases via OAC) ---------------

module "cloudfront" {
  source = "../../modules/cloudfront"

  name        = local.name
  environment = var.environment
  aliases     = [var.apex_domain, "www.${var.apex_domain}"]

  acm_certificate_arn                  = var.acm_cloudfront_certificate_arn == "" ? null : var.acm_cloudfront_certificate_arn
  releases_bucket_regional_domain_name = module.s3_suite.releases_bucket_regional_domain_name
  alb_domain_name                      = aws_lb.app.dns_name
}

# --- DNS records (optional; needs a hosted zone) ---------------------------

resource "aws_route53_record" "apex" {
  count   = var.route53_zone_id == "" ? 0 : 1
  zone_id = var.route53_zone_id
  name    = var.apex_domain
  type    = "A"
  alias {
    name                   = module.cloudfront.domain_name
    zone_id                = module.cloudfront.hosted_zone_id
    evaluate_target_health = false
  }
}

resource "aws_route53_record" "www" {
  count   = var.route53_zone_id == "" ? 0 : 1
  zone_id = var.route53_zone_id
  name    = "www.${var.apex_domain}"
  type    = "A"
  alias {
    name                   = module.cloudfront.domain_name
    zone_id                = module.cloudfront.hosted_zone_id
    evaluate_target_health = false
  }
}

resource "aws_route53_record" "git" {
  count   = var.route53_zone_id == "" ? 0 : 1
  zone_id = var.route53_zone_id
  name    = var.git_domain
  type    = "A"
  alias {
    name                   = aws_lb.git.dns_name
    zone_id                = aws_lb.git.zone_id
    evaluate_target_health = true
  }
}
