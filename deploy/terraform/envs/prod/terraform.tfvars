# prod — full HA per §13.3/§13.4. Fill PLACEHOLDER values before apply.
environment = "prod"
aws_region  = "us-east-1" # Q8

az_count           = 3
single_nat_gateway = false

# From global/ecr outputs:
agentryd_image = "PLACEHOLDER.dkr.ecr.us-east-1.amazonaws.com/agentry/agentryd:latest"
web_image      = "PLACEHOLDER.dkr.ecr.us-east-1.amazonaws.com/agentry/web:latest"

# Data services (§13.4).
rds_instance_class          = "db.r6g.large"
rds_multi_az                = true
rds_backup_retention_period = 35
rds_allocated_storage       = 100
redis_node_type             = "cache.t4g.small"
redis_replica_count         = 1

# Edge / DNS.
apex_domain = "agentry.example" # PLACEHOLDER
git_domain  = "git.agentry.example"
# From global/dns outputs:
acm_alb_certificate_arn        = "" # PLACEHOLDER (alb_certificate_arn)
acm_cloudfront_certificate_arn = "" # PLACEHOLDER (cloudfront_certificate_arn)
route53_zone_id                = "" # PLACEHOLDER (zone_id)

# S5 judge (Q3).
judge_model = "anthropic.claude-3-5-sonnet-20241022-v2:0"

# Cross-account audit replication (§13.4) + T-09 KMS Sign alarm source.
audit_replication_destination_bucket_arn = "" # PLACEHOLDER (security acct bucket ARN)
audit_replication_destination_account_id = "" # PLACEHOLDER (security acct id)
cloudtrail_log_group_name                = "" # PLACEHOLDER (org CloudTrail log group)

# Alerting (§16.3). Example: PagerDuty for page, email for ticket.
page_subscriptions   = [] # e.g. [{ protocol = "https", endpoint = "https://events.pagerduty.com/integration/XXX/enqueue" }]
ticket_subscriptions = [] # e.g. [{ protocol = "email", endpoint = "oncall@agentry.example" }]
