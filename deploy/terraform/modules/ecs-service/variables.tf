variable "name" {
  description = "Service name (e.g. api, git, worker-sandbox). Used for all child resources."
  type        = string
}

variable "environment" {
  description = "Deployment environment: dev | staging | prod."
  type        = string
}

variable "cluster_arn" {
  description = "ECS cluster ARN to run the service in."
  type        = string
}

variable "aws_region" {
  description = "Region (for the awslogs driver and ADOT sidecar)."
  type        = string
}

# --- Task shape ------------------------------------------------------------

variable "image" {
  description = "Fully-qualified container image (ECR URI incl. tag/digest)."
  type        = string
}

variable "command" {
  description = "Container command, e.g. [\"api\"] or [\"worker\",\"--queues=sandbox\"]."
  type        = list(string)
  default     = []
}

variable "cpu" {
  description = "Task CPU units (256 = 0.25 vCPU)."
  type        = number
}

variable "memory" {
  description = "Task memory (MiB)."
  type        = number
}

variable "cpu_architecture" {
  description = "X86_64 (safe default; images built amd64) or ARM64 (Graviton, cheaper — requires arm64 images)."
  type        = string
  default     = "X86_64"

  validation {
    condition     = contains(["X86_64", "ARM64"], var.cpu_architecture)
    error_message = "cpu_architecture must be X86_64 or ARM64."
  }
}

variable "desired_count" {
  description = "Baseline task count."
  type        = number
  default     = 2
}

variable "min_count" {
  description = "Autoscaling floor."
  type        = number
  default     = 2
}

variable "max_count" {
  description = "Autoscaling ceiling."
  type        = number
  default     = 6
}

variable "container_port" {
  description = "Port the container listens on; null for workers (no listener, no LB)."
  type        = number
  default     = null
}

variable "environment_variables" {
  description = "Plain (non-secret) AGENTRY_* env vars."
  type        = map(string)
  default     = {}
}

variable "secrets" {
  description = "Secret env vars: name => Secrets Manager / SSM ARN injected via valueFrom."
  type        = map(string)
  default     = {}
}

variable "readonly_root_filesystem" {
  description = "Mount the container root FS read-only (sandbox/judge profile, §8.2)."
  type        = bool
  default     = true
}

variable "tmpfs_size_mib" {
  description = "Size of the /scratch tmpfs mount (0 disables). Sandbox uses tmpfs scratch (§8.2)."
  type        = number
  default     = 0
}

variable "log_retention_days" {
  description = "CloudWatch log group retention."
  type        = number
  default     = 30
}

# --- Networking ------------------------------------------------------------

variable "vpc_id" {
  type = string
}

variable "subnet_ids" {
  description = "Private-app subnet IDs the tasks run in."
  type        = list(string)
}

variable "extra_security_group_ids" {
  description = "Additional SGs attached to the task ENI (e.g. app-tier, git-tier identity SGs)."
  type        = list(string)
  default     = []
}

variable "ingress_source_security_group_ids" {
  description = "SGs allowed to reach container_port (e.g. the ALB SG). Empty = no ingress (workers)."
  type        = list(string)
  default     = []
}

# Egress is expressed as explicit allowances so the sandbox/judge no-egress
# profiles (§8.2) are readable in one place. allow_all_egress=false + the
# scoped toggles below means NO 0.0.0.0/0 route.
variable "allow_all_egress" {
  description = "Permit egress to 0.0.0.0/0 via NAT (web/api/git/worker-core). false = restricted profile."
  type        = bool
  default     = false
}

variable "egress_endpoints_security_group_id" {
  description = "Interface-endpoints SG; 443 egress here reaches ECR/Logs/Secrets/KMS/Bedrock/SES privately."
  type        = string
  default     = null
}

variable "egress_s3_prefix_list_id" {
  description = "S3 gateway endpoint prefix list; 443 egress here reaches the releases/evidence buckets."
  type        = string
  default     = null
}

variable "egress_rds_security_group_id" {
  description = "RDS SG; 5432 egress here reaches Postgres."
  type        = string
  default     = null
}

variable "egress_redis_security_group_id" {
  description = "Redis SG; 6379 egress here reaches ElastiCache."
  type        = string
  default     = null
}

# --- IAM -------------------------------------------------------------------

variable "task_role_policy_json" {
  description = "Least-privilege inline policy for the task role (S3/Bedrock/KMS/EFS as the service needs). null = no extra perms."
  type        = string
  default     = null
}

variable "execution_extra_secret_arns" {
  description = "Secret/SSM ARNs the execution role may read to inject env (incl. ADOT config)."
  type        = list(string)
  default     = []
}

variable "kms_key_arns_for_secrets" {
  description = "KMS keys the execution role may Decrypt to read the injected secrets."
  type        = list(string)
  default     = []
}

# --- Load balancer attachment ---------------------------------------------

variable "attach_alb" {
  description = "Create a target group + listener rule and register the service (web/api/git)."
  type        = bool
  default     = false
}

variable "alb_listener_arn" {
  description = "HTTPS listener ARN to attach the listener rule to."
  type        = string
  default     = null
}

variable "alb_arn_suffix" {
  description = "ALB ARN suffix (app/<name>/<id>) — required to build the ALBRequestCountPerTarget scaling label."
  type        = string
  default     = null
}

variable "alb_listener_rule_priority" {
  description = "Listener rule priority (unique per listener)."
  type        = number
  default     = 100
}

variable "alb_host_headers" {
  description = "Host header match for the listener rule (e.g. [\"api.agentry.example\"])."
  type        = list(string)
  default     = []
}

variable "alb_path_patterns" {
  description = "Path pattern match for the listener rule (e.g. [\"/api/*\"]). Combined with host if both set."
  type        = list(string)
  default     = []
}

variable "health_check_path" {
  description = "Target group health check path."
  type        = string
  default     = "/healthz"
}

variable "deregistration_delay" {
  description = "Target group connection draining seconds."
  type        = number
  default     = 30
}

# --- Autoscaling -----------------------------------------------------------

variable "scaling_metric" {
  description = "cpu | alb_request_count | custom."
  type        = string
  default     = "cpu"

  validation {
    condition     = contains(["cpu", "alb_request_count", "custom"], var.scaling_metric)
    error_message = "scaling_metric must be one of cpu, alb_request_count, custom."
  }
}

variable "scaling_target_value" {
  description = "Target-tracking setpoint (e.g. 60 for 60% CPU, or queue depth for custom)."
  type        = number
  default     = 60
}

variable "scaling_custom_metric" {
  description = "For scaling_metric=custom: {namespace, metric_name, dimensions{}} of the queue-depth/age metric (River, §16.2)."
  type = object({
    namespace   = string
    metric_name = string
    statistic   = optional(string, "Average")
    dimensions  = optional(map(string), {})
  })
  default = null
}

# --- EFS mount (git; optional) --------------------------------------------

variable "efs_volume" {
  description = "Optional EFS mount: {file_system_id, access_point_id, mount_path, security_group_id}. git mounts /data/git (§13.3, D-19)."
  type = object({
    file_system_id     = string
    access_point_id    = string
    mount_path         = string
    security_group_id  = string
    transit_encryption = optional(bool, true)
  })
  default = null
}

# --- Observability ---------------------------------------------------------

variable "enable_adot" {
  description = "Attach the ADOT collector sidecar (OTel -> CloudWatch, §16, D-25)."
  type        = bool
  default     = true
}

variable "adot_image" {
  description = "ADOT collector image."
  type        = string
  default     = "public.ecr.aws/aws-observability/aws-otel-collector:latest"
}

variable "adot_config_ssm_arn" {
  description = "SSM parameter ARN holding the ADOT collector config (from the observability module)."
  type        = string
  default     = null
}

variable "tags" {
  type    = map(string)
  default = {}
}
