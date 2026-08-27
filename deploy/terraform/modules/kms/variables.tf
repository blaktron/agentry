variable "name" {
  type = string
}

variable "environment" {
  type = string
}

variable "signing_principal_arns" {
  description = "Task role ARN(s) allowed to kms:Sign — ONLY the worker-core signing job (§13.3, D-16). Passed as constructed ARN strings so the key policy has no dependency on the ECS module (avoids a cycle)."
  type        = list(string)
}

variable "deletion_window_days" {
  type    = number
  default = 30
}

variable "tags" {
  type    = map(string)
  default = {}
}
