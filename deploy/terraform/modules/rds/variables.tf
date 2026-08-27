variable "name" {
  description = "Identifier prefix (e.g. agentry-prod)."
  type        = string
}

variable "environment" {
  type = string
}

variable "vpc_id" {
  type = string
}

variable "subnet_ids" {
  description = "Private-data subnet IDs for the DB subnet group."
  type        = list(string)
}

variable "allowed_security_group_ids" {
  description = "App-tier SG(s) permitted to reach 5432 — the only ingress source (§13.4: only app SGs)."
  type        = list(string)
}

variable "instance_class" {
  description = "prod: db.r6g.large (§13.4); dev/staging: db.t4g.medium."
  type        = string
  default     = "db.r6g.large"
}

variable "engine_version" {
  description = "PostgreSQL major/minor. §13.4: Postgres 16."
  type        = string
  default     = "16"
}

variable "multi_az" {
  description = "Multi-AZ standby (prod true; dev/staging false)."
  type        = bool
  default     = true
}

variable "allocated_storage" {
  type    = number
  default = 100
}

variable "max_allocated_storage" {
  description = "gp3 storage autoscaling ceiling."
  type        = number
  default     = 500
}

variable "backup_retention_period" {
  description = "Automated backup + PITR window in days. prod=35 (satisfies §13.4 snapshots 35d and PITR>=14d); dev/staging=7."
  type        = number
  default     = 35
}

variable "performance_insights_retention" {
  description = "PI retention days (7 = free tier; 731 = long-term)."
  type        = number
  default     = 7
}

variable "deletion_protection" {
  type    = bool
  default = true
}

variable "kms_key_arn" {
  description = "KMS key for storage + PI + the DSN secret encryption (data key from the kms module)."
  type        = string
}

variable "db_name" {
  description = "Initial database (§13.4: one agentry DB)."
  type        = string
  default     = "agentry"
}

variable "master_username" {
  type    = string
  default = "agentry"
}

variable "tags" {
  type    = map(string)
  default = {}
}
