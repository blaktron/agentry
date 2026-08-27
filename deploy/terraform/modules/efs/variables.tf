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
  description = "Private-data subnet IDs for mount targets."
  type        = list(string)
}

variable "allowed_security_group_ids" {
  description = "SG(s) permitted NFS (2049) — the git-tier identity SG (git + worker-core gc)."
  type        = list(string)
}

variable "kms_key_arn" {
  description = "KMS key for EFS encryption at rest."
  type        = string
}

variable "access_points" {
  description = "Per-service uid-scoped access points (§13.3). name => {uid, gid, path}."
  type = map(object({
    uid  = number
    gid  = number
    path = string
    perm = optional(string, "0700")
  }))
  default = {
    git = { uid = 10001, gid = 10001, path = "/git", perm = "0700" }
  }
}

variable "backup_retention_days" {
  description = "AWS Backup retention (§13.4: 35 d)."
  type        = number
  default     = 35
}

variable "transition_to_ia" {
  description = "Lifecycle policy: move files to IA after this window (or null to disable)."
  type        = string
  default     = "AFTER_30_DAYS"
}

variable "tags" {
  type    = map(string)
  default = {}
}
