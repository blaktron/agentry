variable "name" {
  description = "Prefix for bucket names (e.g. agentry-prod); must be globally unique-able."
  type        = string
}

variable "environment" {
  type = string
}

variable "kms_key_arn" {
  description = "KMS data key for SSE-KMS on all three buckets."
  type        = string
}

variable "releases_object_lock_years" {
  description = "Object-lock governance retention on releases (§13.4: 2 y)."
  type        = number
  default     = 2
}

variable "audit_object_lock_days" {
  description = "Object-lock COMPLIANCE retention on audit-archive (§13.4: 400 d)."
  type        = number
  default     = 400
}

variable "evidence_ia_transition_days" {
  description = "Evidence lifecycle → STANDARD_IA (§13.4: 90 d)."
  type        = number
  default     = 90
}

variable "audit_replication_destination_bucket_arn" {
  description = "Security-account bucket ARN to replicate audit-archive to (§13.4). null disables replication."
  type        = string
  default     = null
}

variable "audit_replication_destination_account_id" {
  description = "Security account ID owning the replication destination (for ACL translation)."
  type        = string
  default     = null
}

variable "tags" {
  type    = map(string)
  default = {}
}
