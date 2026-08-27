variable "name" {
  type = string
}

variable "environment" {
  type = string
}

variable "scope" {
  description = "REGIONAL (ALB) or CLOUDFRONT. This reference associates both ACLs to ALBs -> REGIONAL."
  type        = string
  default     = "REGIONAL"

  validation {
    condition     = contains(["REGIONAL", "CLOUDFRONT"], var.scope)
    error_message = "scope must be REGIONAL or CLOUDFRONT."
  }
}

variable "web_rate_limit" {
  description = "Per-IP request budget over 5 minutes for the web/API ACL."
  type        = number
  default     = 2000
}

variable "git_rate_limit" {
  description = "Per-IP request budget over 5 minutes for the git ACL (clones are heavier)."
  type        = number
  default     = 600
}

variable "git_body_inspection_excluded_rules" {
  description = "CommonRuleSet rules set to COUNT on the git host — body-inspection rules false-positive on packfiles (§13.5)."
  type        = list(string)
  default = [
    "SizeRestrictions_BODY",
    "CrossSiteScripting_BODY",
    "GenericRFI_BODY",
    "GenericLFI_BODY",
  ]
}

variable "tags" {
  type    = map(string)
  default = {}
}
