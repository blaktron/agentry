variable "name" {
  type = string
}

variable "environment" {
  type = string
}

variable "aws_region" {
  type = string
}

variable "metrics_namespace" {
  description = "CloudWatch namespace the ADOT collector writes app metrics to (matches awsemf config)."
  type        = string
  default     = "Agentry"
}

# --- Targets for dashboards/alarms (from other modules' outputs) -----------

variable "app_alb_arn_suffix" {
  description = "app ALB ARN suffix for RED/5xx metrics."
  type        = string
  default     = null
}

variable "git_alb_arn_suffix" {
  description = "git ALB ARN suffix."
  type        = string
  default     = null
}

variable "rds_instance_id" {
  description = "RDS instance identifier for the failover EventBridge rule + DB dashboards."
  type        = string
  default     = null
}

variable "signing_key_id" {
  description = "KMS signing key id — labels the KMS Sign anomaly alarm."
  type        = string
  default     = null
}

variable "cloudtrail_log_group_name" {
  description = "CloudWatch log group receiving org CloudTrail (incl. kms:Sign data events) for the T-09 metric filter. null skips the KMS Sign alarm."
  type        = string
  default     = null
}

variable "web_acl_metric_name" {
  description = "web/API WAF ACL name (AWS/WAFV2 metric dimension) for the block-spike alarm."
  type        = string
  default     = null
}

# --- Alarm thresholds (§16.3) ----------------------------------------------

variable "availability_error_ratio" {
  description = "5xx/requests ratio that trips the availability burn alarm (99.9% SLO -> 0.001)."
  type        = number
  default     = 0.001
}

variable "queue_age_seconds_threshold" {
  description = "River queue age page threshold (§16.3: 15 min)."
  type        = number
  default     = 900
}

variable "scan_error_rate_threshold" {
  description = "Scan pipeline error-rate page threshold (§16.3: 5%)."
  type        = number
  default     = 0.05
}

# --- Notification routing --------------------------------------------------

variable "page_subscriptions" {
  description = "PAGE SNS subscriptions (protocol/endpoint), e.g. [{protocol=\"https\", endpoint=\"https://events.pagerduty.com/...\"}]."
  type = list(object({
    protocol = string
    endpoint = string
  }))
  default = []
}

variable "ticket_subscriptions" {
  description = "TICKET SNS subscriptions (email/Jira webhook, etc.)."
  type = list(object({
    protocol = string
    endpoint = string
  }))
  default = []
}

variable "tags" {
  type    = map(string)
  default = {}
}
