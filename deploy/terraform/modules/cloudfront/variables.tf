variable "name" {
  type = string
}

variable "environment" {
  type = string
}

variable "aliases" {
  description = "CNAMEs served (e.g. [\"agentry.example\",\"www.agentry.example\"]). git.* is NOT here — it bypasses CloudFront (§13.2)."
  type        = list(string)
  default     = []
}

variable "acm_certificate_arn" {
  description = "ACM cert ARN in us-east-1 (CloudFront requirement, §13.5). null uses the default CF cert."
  type        = string
  default     = null
}

variable "releases_bucket_regional_domain_name" {
  description = "S3 releases bucket regional domain (origin for immutable downloads)."
  type        = string
}

variable "alb_domain_name" {
  description = "Public DNS name of the app ALB (origin for web/api pass-through)."
  type        = string
}

variable "releases_path_pattern" {
  description = "Path routed to S3 releases (immutable, long cache). Everything else -> ALB."
  type        = string
  default     = "/dl/*"
}

variable "web_acl_id" {
  description = "Optional CLOUDFRONT-scope WAF web ACL ARN. Default: WAF is applied at the ALB (REGIONAL) in this reference."
  type        = string
  default     = null
}

variable "price_class" {
  type    = string
  default = "PriceClass_100"
}

variable "tags" {
  type    = map(string)
  default = {}
}
