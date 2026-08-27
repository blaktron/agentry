# NOTE: ElastiCache Redis is mandated by PLAN §13.2/§13.4 but is not one of the
# nine modules named in the §13.7 tree. It lives here as its own module so
# AGENTRY_REDIS_URL (D-06, sessions/rate-limits/hot caches) is wired for real.

variable "name" {
  type = string
}

variable "environment" {
  type = string
}

variable "vpc_id" {
  type = string
}

variable "subnet_ids" {
  description = "Private-data subnet IDs."
  type        = list(string)
}

variable "allowed_security_group_ids" {
  description = "App-tier SG(s) permitted to reach 6379."
  type        = list(string)
}

variable "node_type" {
  description = "§13.4: cache.t4g.small."
  type        = string
  default     = "cache.t4g.small"
}

variable "replica_count" {
  description = "Replicas per node group. prod=1 (2 nodes total, §13.4); dev/staging=0."
  type        = number
  default     = 1
}

variable "engine_version" {
  description = "§13.4: Redis 7."
  type        = string
  default     = "7.1"
}

variable "kms_key_arn" {
  description = "KMS key for at-rest encryption + the URL secret."
  type        = string
}

variable "tags" {
  type    = map(string)
  default = {}
}
