# dev — single-AZ, small (§13.8 ≈ $250-400/mo). Auto-deploys main (§13.1).
environment = "dev"
aws_region  = "us-east-1" # Q8

az_count           = 1
single_nat_gateway = true

agentryd_image = "PLACEHOLDER.dkr.ecr.us-east-1.amazonaws.com/agentry/agentryd:latest"
web_image      = "PLACEHOLDER.dkr.ecr.us-east-1.amazonaws.com/agentry/web:latest"

# Small data tier; no Multi-AZ, no Redis replica, short backups.
rds_instance_class          = "db.t4g.medium"
rds_multi_az                = false
rds_backup_retention_period = 7
rds_allocated_storage       = 20
redis_node_type             = "cache.t4g.small"
redis_replica_count         = 0

# One task per service (min=max=1 via the override below).
service_scaling = {
  web            = { cpu = 256, memory = 512, desired_count = 1, min_count = 1, max_count = 2 }
  api            = { cpu = 512, memory = 1024, desired_count = 1, min_count = 1, max_count = 2 }
  git            = { cpu = 512, memory = 1024, desired_count = 1, min_count = 1, max_count = 2 }
  worker-core    = { cpu = 512, memory = 1024, desired_count = 1, min_count = 1, max_count = 2 }
  worker-sandbox = { cpu = 512, memory = 2048, desired_count = 1, min_count = 1, max_count = 2 }
  worker-judge   = { cpu = 256, memory = 512, desired_count = 1, min_count = 1, max_count = 1 }
}

apex_domain = "dev.agentry.example" # PLACEHOLDER
git_domain  = "git.dev.agentry.example"

acm_alb_certificate_arn        = "" # PLACEHOLDER
acm_cloudfront_certificate_arn = "" # PLACEHOLDER
route53_zone_id                = "" # PLACEHOLDER

judge_model = "anthropic.claude-3-5-sonnet-20241022-v2:0"
