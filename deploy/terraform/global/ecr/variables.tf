variable "repositories" {
  description = "ECR repos to create (§13.7 global/ecr). agentryd (server, all roles) + web (Next.js)."
  type        = list(string)
  default     = ["agentryd", "web"]
}

variable "kms_key_arn" {
  description = "Optional CMK for image encryption. null = AES256."
  type        = string
  default     = null
}

variable "organization_id" {
  description = "AWS Org ID (o-xxxx) permitted to pull, so prod/nonprod pull from a shared registry. null = same-account only."
  type        = string
  default     = null
}

variable "keep_last_images" {
  description = "Tagged images retained by the lifecycle policy."
  type        = number
  default     = 20
}

variable "tags" {
  type    = map(string)
  default = {}
}
