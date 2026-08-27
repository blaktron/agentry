variable "name" {
  description = "Name prefix for all network resources (e.g. agentry-prod)."
  type        = string
}

variable "vpc_cidr" {
  description = "VPC CIDR (PLAN §13.2: 10.0.0.0/16)."
  type        = string
  default     = "10.0.0.0/16"
}

variable "az_count" {
  description = "Number of AZs to span. prod=3 (§13.2); dev/staging=1 (§13.8 single-AZ small)."
  type        = number
  default     = 3

  validation {
    condition     = var.az_count >= 1 && var.az_count <= 3
    error_message = "az_count must be between 1 and 3."
  }
}

variable "single_nat_gateway" {
  description = "Use one shared NAT gateway instead of one-per-AZ. true for dev/staging cost savings; false for prod HA (§13.3 NAT×3)."
  type        = bool
  default     = false
}

variable "aws_region" {
  description = "Region hosting this VPC (used to build VPC endpoint service names). Q8: default us-east-1."
  type        = string
}

variable "interface_endpoints" {
  description = "Interface VPC endpoint short service names to create (§13.2). Gateway S3 is always created separately."
  type        = list(string)
  default = [
    "ecr.api",
    "ecr.dkr",
    "logs",
    "secretsmanager",
    "kms",
    "bedrock-runtime",
    "email-smtp", # SES SMTP submission (transactional email, §13.4)
  ]
}

variable "tags" {
  description = "Tags applied to all resources."
  type        = map(string)
  default     = {}
}
