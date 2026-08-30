variable "aws_region" {
  description = "Primary region (Q8: default us-east-1)."
  type        = string
  default     = "us-east-1"
}

variable "manage_organization" {
  description = "Create the AWS Organization + accounts (management account only)."
  type        = bool
  default     = false
}

variable "github_repository" {
  description = "owner/repo allowed to assume the deploy role via OIDC."
  type        = string
  default     = "blaktron/agentry"
}

variable "apex_domain" {
  type    = string
  default = "agentry.example"
}

variable "git_domain" {
  type    = string
  default = "git.agentry.example"
}

variable "organization_id" {
  description = "AWS Org ID for cross-account ECR pulls (o-xxxx). null = same-account only."
  type        = string
  default     = null
}
