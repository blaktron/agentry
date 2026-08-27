variable "manage_organization" {
  description = "Create the AWS Organization + member accounts (run in the management account only). false = document-only / accounts already exist (§13.1)."
  type        = bool
  default     = false
}

variable "account_emails" {
  description = "Root emails for the three accounts (§13.1: prod, nonprod, security)."
  type = object({
    prod     = string
    nonprod  = string
    security = string
  })
  default = {
    prod     = "aws+agentry-prod@example.com"     # PLACEHOLDER
    nonprod  = "aws+agentry-nonprod@example.com"  # PLACEHOLDER
    security = "aws+agentry-security@example.com" # PLACEHOLDER
  }
}

variable "create_oidc_provider" {
  description = "Create the GitHub Actions OIDC provider in this account (§13.1: no IAM users; OIDC role assumption)."
  type        = bool
  default     = true
}

variable "github_repository" {
  description = "owner/repo permitted to assume the deploy role via OIDC."
  type        = string
  default     = "PLACEHOLDER_ORG/agentry"
}

variable "github_deploy_branches" {
  description = "Refs allowed to assume the deploy role (apply job runs on merge to these)."
  type        = list(string)
  default     = ["main"]
}

variable "tags" {
  type    = map(string)
  default = {}
}
