variable "aws_region" {
  description = "Deployment region (Q8: default us-east-1)."
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "dev | staging | prod."
  type        = string
}

# --- Network ---------------------------------------------------------------

variable "az_count" {
  type    = number
  default = 3
}

variable "single_nat_gateway" {
  type    = bool
  default = false
}

# --- Images (from global/ecr; full URI incl. tag) --------------------------

variable "agentryd_image" {
  description = "agentryd image URI. e.g. <acct>.dkr.ecr.<region>.amazonaws.com/agentry/agentryd:<tag>."
  type        = string
  default     = "PLACEHOLDER.dkr.ecr.us-east-1.amazonaws.com/agentry/agentryd:latest"
}

variable "web_image" {
  description = "web (Next.js) image URI."
  type        = string
  default     = "PLACEHOLDER.dkr.ecr.us-east-1.amazonaws.com/agentry/web:latest"
}

# --- Per-service sizing (§13.3) --------------------------------------------

variable "service_scaling" {
  description = "cpu/memory (Fargate units)/counts per service. Prod defaults per §13.3."
  type = map(object({
    cpu           = number
    memory        = number
    desired_count = number
    min_count     = number
    max_count     = number
  }))
  default = {
    web            = { cpu = 512, memory = 1024, desired_count = 2, min_count = 2, max_count = 6 }
    api            = { cpu = 1024, memory = 2048, desired_count = 2, min_count = 2, max_count = 8 }
    git            = { cpu = 1024, memory = 2048, desired_count = 2, min_count = 2, max_count = 6 }
    worker-core    = { cpu = 1024, memory = 2048, desired_count = 2, min_count = 2, max_count = 8 }
    worker-sandbox = { cpu = 1024, memory = 4096, desired_count = 1, min_count = 1, max_count = 4 }
    worker-judge   = { cpu = 512, memory = 1024, desired_count = 1, min_count = 1, max_count = 2 }
  }
}

# --- Data services (§13.4) -------------------------------------------------

variable "rds_instance_class" {
  type    = string
  default = "db.r6g.large"
}

variable "rds_multi_az" {
  type    = bool
  default = true
}

variable "rds_backup_retention_period" {
  type    = number
  default = 35
}

variable "rds_allocated_storage" {
  type    = number
  default = 100
}

variable "redis_node_type" {
  type    = string
  default = "cache.t4g.small"
}

variable "redis_replica_count" {
  type    = number
  default = 1
}

# --- Edge / DNS ------------------------------------------------------------

variable "apex_domain" {
  type    = string
  default = "agentry.example"
}

variable "git_domain" {
  type    = string
  default = "git.agentry.example"
}

variable "acm_alb_certificate_arn" {
  description = "Regional ACM cert for the ALBs (from global/dns alb_certificate_arn)."
  type        = string
  default     = ""
}

variable "acm_cloudfront_certificate_arn" {
  description = "us-east-1 ACM cert for CloudFront (from global/dns cloudfront_certificate_arn)."
  type        = string
  default     = ""
}

variable "route53_zone_id" {
  description = "Hosted zone ID for apex/git records. Empty skips record creation."
  type        = string
  default     = ""
}

# --- Judge (§8.4, D-13; Q3) ------------------------------------------------

variable "judge_model" {
  description = "Bedrock model id for S5 (Q3: default Sonnet-class)."
  type        = string
  default     = "anthropic.claude-3-5-sonnet-20241022-v2:0"
}

# --- Cross-account / observability wiring ----------------------------------

variable "audit_replication_destination_bucket_arn" {
  description = "Security-account bucket ARN for audit-archive replication (§13.4). Empty disables."
  type        = string
  default     = ""
}

variable "audit_replication_destination_account_id" {
  type    = string
  default = ""
}

variable "cloudtrail_log_group_name" {
  description = "CloudWatch log group with org CloudTrail (kms:Sign data events) for the T-09 alarm. Empty disables."
  type        = string
  default     = ""
}

variable "page_subscriptions" {
  type = list(object({
    protocol = string
    endpoint = string
  }))
  default = []
}

variable "ticket_subscriptions" {
  type = list(object({
    protocol = string
    endpoint = string
  }))
  default = []
}

# --- Scanner external tools (§8.3, agentry#40) ------------------------------

variable "osv_url" {
  description = "OSV API base URL for S7 vulnerability lookups (e.g. https://api.osv.dev). Empty keeps S7 offline: the report says \"not checked\" instead of \"no vulnerabilities\"."
  type        = string
  default     = ""
}

# --- Directory service (DEV-057, agentry#51) --------------------------------

variable "idp_client_id" {
  description = "OIDC client id of the registry in the directory service (Authentik). Empty keeps native credential flows."
  type        = string
  default     = ""
}

variable "idp_issuer" {
  description = "OIDC issuer of the directory's Agentry application, e.g. https://auth.example.com/application/o/agentry/."
  type        = string
  default     = ""
}

variable "idp_logout_url" {
  description = "End-session URL the web tier redirects to on sign-out, e.g. https://auth.example.com/application/o/agentry/end-session/."
  type        = string
  default     = ""
}

variable "idp_staff_group" {
  description = "Directory group whose members are platform staff (granted/revoked at sign-in from the groups claim). Empty disables the sync."
  type        = string
  default     = "agentry-platform-staff"
}
