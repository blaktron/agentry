# staging — release candidates + SSO test IdP (§13.1). Single-AZ, small but with
# Multi-AZ RDS off and a modest ceiling; closer to prod shape than dev.
environment = "staging"
aws_region  = "us-east-1" # Q8

az_count           = 2
single_nat_gateway = true

agentryd_image = "PLACEHOLDER.dkr.ecr.us-east-1.amazonaws.com/agentry/agentryd:latest"
web_image      = "PLACEHOLDER.dkr.ecr.us-east-1.amazonaws.com/agentry/web:latest"

rds_instance_class          = "db.t4g.large"
rds_multi_az                = false
rds_backup_retention_period = 14
rds_allocated_storage       = 50
redis_node_type             = "cache.t4g.small"
redis_replica_count         = 0

service_scaling = {
  web            = { cpu = 512, memory = 1024, desired_count = 1, min_count = 1, max_count = 3 }
  api            = { cpu = 512, memory = 1024, desired_count = 1, min_count = 1, max_count = 3 }
  git            = { cpu = 512, memory = 1024, desired_count = 1, min_count = 1, max_count = 3 }
  worker-core    = { cpu = 512, memory = 1024, desired_count = 1, min_count = 1, max_count = 3 }
  worker-sandbox = { cpu = 512, memory = 2048, desired_count = 1, min_count = 1, max_count = 3 }
  worker-judge   = { cpu = 256, memory = 512, desired_count = 1, min_count = 1, max_count = 2 }
}

apex_domain = "staging.agentry.example" # PLACEHOLDER
git_domain  = "git.staging.agentry.example"

acm_alb_certificate_arn        = "" # PLACEHOLDER
acm_cloudfront_certificate_arn = "" # PLACEHOLDER
route53_zone_id                = "" # PLACEHOLDER

judge_model = "anthropic.claude-3-5-sonnet-20241022-v2:0"
