variable "apex_domain" {
  description = "Primary domain (§13). PLACEHOLDER: agentry.example."
  type        = string
  default     = "agentry.example"
}

variable "git_domain" {
  description = "git hostname (§6.1, §13.5). PLACEHOLDER: git.agentry.example."
  type        = string
  default     = "git.agentry.example"
}

variable "create_zone" {
  description = "Create the hosted zone (false if delegated elsewhere)."
  type        = bool
  default     = true
}

variable "tags" {
  type    = map(string)
  default = {}
}
