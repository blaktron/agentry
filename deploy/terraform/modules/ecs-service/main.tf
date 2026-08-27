# Reusable ECS Fargate service (PLAN §13.3). Each of the six services (web,
# api, git, worker-core, worker-sandbox, worker-judge) is one instantiation of
# this module; the differences are pure inputs — image/command, size, LB
# attachment, EFS mount, IAM policy, and (critically) the egress profile that
# expresses the §8.2 sandbox/judge network jails.

data "aws_partition" "current" {}

locals {
  log_group = "/agentry/${var.environment}/${var.name}"

  base_env = [for k, v in var.environment_variables : { name = k, value = tostring(v) }]

  secret_env = [for k, v in var.secrets : { name = k, valueFrom = v }]

  needs_scratch = var.readonly_root_filesystem

  mount_points = concat(
    var.efs_volume != null ? [{
      sourceVolume  = "git-data"
      containerPath = var.efs_volume.mount_path
      readOnly      = false
    }] : [],
    local.needs_scratch ? [
      { sourceVolume = "scratch", containerPath = "/scratch", readOnly = false },
      { sourceVolume = "scratch", containerPath = "/tmp", readOnly = false },
    ] : [],
  )

  main_container = {
    name                   = var.name
    image                  = var.image
    command                = var.command
    essential              = true
    readonlyRootFilesystem = var.readonly_root_filesystem
    environment            = local.base_env
    secrets                = local.secret_env
    mountPoints            = local.mount_points
    portMappings = var.container_port == null ? [] : [{
      containerPort = var.container_port
      protocol      = "tcp"
    }]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = local.log_group
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = var.name
      }
    }
  }

  # ADOT collector sidecar (§16, D-25): reads its config from SSM and ships
  # OTel traces/metrics to CloudWatch. Runs alongside every task.
  adot_container = {
    name                   = "adot-collector"
    image                  = var.adot_image
    essential              = false
    readonlyRootFilesystem = true
    command                = ["--config=env:AOT_CONFIG_CONTENT"]
    environment            = []
    secrets = var.adot_config_ssm_arn == null ? [] : [{
      name      = "AOT_CONFIG_CONTENT"
      valueFrom = var.adot_config_ssm_arn
    }]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = local.log_group
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "adot"
      }
    }
  }

  has_adot = var.enable_adot && var.adot_config_ssm_arn != null
  containers = concat(
    [local.main_container],
    [for _ in range(local.has_adot ? 1 : 0) : local.adot_container],
  )

  # The execution role must read every injected secret/param, including the
  # ADOT config SSM parameter when the sidecar is present.
  execution_read_arns = distinct(concat(
    values(var.secrets),
    var.execution_extra_secret_arns,
    local.has_adot ? [var.adot_config_ssm_arn] : [],
  ))
}

# --- Logs ------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "this" {
  name              = local.log_group
  retention_in_days = var.log_retention_days
  tags              = var.tags
}

# --- IAM: execution role (pulls image, writes logs, reads injected secrets) -

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "execution" {
  name               = "agentry-${var.environment}-${var.name}-exec"
  assume_role_policy = data.aws_iam_policy_document.assume.json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "execution_managed" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

data "aws_iam_policy_document" "execution_secrets" {
  count = length(local.execution_read_arns) > 0 ? 1 : 0

  statement {
    sid       = "ReadInjectedSecrets"
    actions   = ["secretsmanager:GetSecretValue", "ssm:GetParameters", "ssm:GetParameter"]
    resources = local.execution_read_arns
  }

  dynamic "statement" {
    for_each = length(var.kms_key_arns_for_secrets) > 0 ? [1] : []
    content {
      sid       = "DecryptSecrets"
      actions   = ["kms:Decrypt"]
      resources = var.kms_key_arns_for_secrets
    }
  }
}

resource "aws_iam_role_policy" "execution_secrets" {
  count  = length(data.aws_iam_policy_document.execution_secrets) > 0 ? 1 : 0
  name   = "read-secrets"
  role   = aws_iam_role.execution.id
  policy = data.aws_iam_policy_document.execution_secrets[0].json
}

# --- IAM: task role (the application's own least-privilege identity) --------

resource "aws_iam_role" "task" {
  name               = "agentry-${var.environment}-${var.name}-task"
  assume_role_policy = data.aws_iam_policy_document.assume.json
  tags               = var.tags
}

resource "aws_iam_role_policy" "task" {
  count  = var.task_role_policy_json == null ? 0 : 1
  name   = "app"
  role   = aws_iam_role.task.id
  policy = var.task_role_policy_json
}

# The ADOT collector runs under the task role and needs to write metrics/logs
# (CloudWatch EMF) and traces (X-Ray).
resource "aws_iam_role_policy_attachment" "task_adot_cw" {
  count      = local.has_adot ? 1 : 0
  role       = aws_iam_role.task.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/CloudWatchAgentServerPolicy"
}

resource "aws_iam_role_policy_attachment" "task_adot_xray" {
  count      = local.has_adot ? 1 : 0
  role       = aws_iam_role.task.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AWSXRayDaemonWriteAccess"
}

# EFS client access for the git role (mount + write through the access point).
data "aws_iam_policy_document" "task_efs" {
  count = var.efs_volume == null ? 0 : 1
  statement {
    actions = [
      "elasticfilesystem:ClientMount",
      "elasticfilesystem:ClientWrite",
      "elasticfilesystem:ClientRootAccess",
    ]
    resources = [
      "arn:${data.aws_partition.current.partition}:elasticfilesystem:${var.aws_region}:*:file-system/${var.efs_volume.file_system_id}",
    ]
    condition {
      test     = "StringEquals"
      variable = "elasticfilesystem:AccessPointArn"
      values   = ["arn:${data.aws_partition.current.partition}:elasticfilesystem:${var.aws_region}:*:access-point/${var.efs_volume.access_point_id}"]
    }
  }
}

resource "aws_iam_role_policy" "task_efs" {
  count  = var.efs_volume == null ? 0 : 1
  name   = "efs"
  role   = aws_iam_role.task.id
  policy = data.aws_iam_policy_document.task_efs[0].json
}

# --- Security group + egress profile (§8.2) --------------------------------

resource "aws_security_group" "service" {
  name        = "agentry-${var.environment}-${var.name}"
  description = "ECS service ${var.name} (${var.environment})."
  vpc_id      = var.vpc_id
  tags        = merge(var.tags, { Name = "agentry-${var.environment}-${var.name}" })
}

resource "aws_vpc_security_group_ingress_rule" "from_alb" {
  for_each                     = var.container_port == null ? toset([]) : toset(var.ingress_source_security_group_ids)
  security_group_id            = aws_security_group.service.id
  description                  = "App traffic from ${each.value}"
  from_port                    = var.container_port
  to_port                      = var.container_port
  ip_protocol                  = "tcp"
  referenced_security_group_id = each.value
}

# Full internet egress via NAT — web/api/git/worker-core only.
resource "aws_vpc_security_group_egress_rule" "all" {
  count             = var.allow_all_egress ? 1 : 0
  security_group_id = aws_security_group.service.id
  description       = "All egress via NAT"
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}

# Scoped egress allowances. For the sandbox/judge profiles allow_all_egress is
# false, so THESE ARE THE ONLY egress routes — no 0.0.0.0/0. Sandbox reaches
# only S3 + RDS (+ the AWS control plane for image pull/logs); judge adds the
# Bedrock endpoint (fronted by the shared interface-endpoints SG).
resource "aws_vpc_security_group_egress_rule" "endpoints" {
  count             = var.egress_endpoints_security_group_id == null ? 0 : 1
  security_group_id = aws_security_group.service.id
  description       = "443 to interface VPC endpoints (ECR/Logs/Secrets/KMS/Bedrock/SES)"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"

  referenced_security_group_id = var.egress_endpoints_security_group_id
}

resource "aws_vpc_security_group_egress_rule" "s3" {
  count             = var.egress_s3_prefix_list_id == null ? 0 : 1
  security_group_id = aws_security_group.service.id
  description       = "443 to S3 gateway endpoint (releases/evidence)"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  prefix_list_id    = var.egress_s3_prefix_list_id
}

resource "aws_vpc_security_group_egress_rule" "rds" {
  count                        = var.egress_rds_security_group_id == null ? 0 : 1
  security_group_id            = aws_security_group.service.id
  description                  = "5432 to RDS Postgres"
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
  referenced_security_group_id = var.egress_rds_security_group_id
}

resource "aws_vpc_security_group_egress_rule" "redis" {
  count                        = var.egress_redis_security_group_id == null ? 0 : 1
  security_group_id            = aws_security_group.service.id
  description                  = "6379 to ElastiCache Redis"
  from_port                    = 6379
  to_port                      = 6379
  ip_protocol                  = "tcp"
  referenced_security_group_id = var.egress_redis_security_group_id
}

resource "aws_vpc_security_group_egress_rule" "efs" {
  count                        = var.efs_volume == null ? 0 : 1
  security_group_id            = aws_security_group.service.id
  description                  = "2049 to EFS mount targets"
  from_port                    = 2049
  to_port                      = 2049
  ip_protocol                  = "tcp"
  referenced_security_group_id = var.efs_volume.security_group_id
}

# --- Task definition -------------------------------------------------------

resource "aws_ecs_task_definition" "this" {
  family                   = "agentry-${var.environment}-${var.name}"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.cpu
  memory                   = var.memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn
  container_definitions    = jsonencode(local.containers)

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = var.cpu_architecture
  }

  dynamic "volume" {
    for_each = var.efs_volume == null ? [] : [var.efs_volume]
    content {
      name = "git-data"
      efs_volume_configuration {
        file_system_id     = volume.value.file_system_id
        transit_encryption = volume.value.transit_encryption ? "ENABLED" : "DISABLED"
        authorization_config {
          access_point_id = volume.value.access_point_id
          iam             = "ENABLED"
        }
      }
    }
  }

  # Writable scratch for a read-only root filesystem. On Fargate this is backed
  # by encrypted task ephemeral storage (the platform equivalent of the §8.2
  # tmpfs scratch; Fargate does not expose linuxParameters.tmpfs).
  dynamic "volume" {
    for_each = local.needs_scratch ? [1] : []
    content {
      name = "scratch"
    }
  }

  tags = var.tags
}

# --- Service ---------------------------------------------------------------

resource "aws_ecs_service" "this" {
  name            = var.name
  cluster         = var.cluster_arn
  task_definition = aws_ecs_task_definition.this.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.subnet_ids
    security_groups  = concat([aws_security_group.service.id], var.extra_security_group_ids)
    assign_public_ip = false
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  dynamic "load_balancer" {
    for_each = var.attach_alb && var.container_port != null ? [1] : []
    content {
      target_group_arn = aws_lb_target_group.this[0].arn
      container_name   = var.name
      container_port   = var.container_port
    }
  }

  # Autoscaling manages desired_count after creation.
  lifecycle {
    ignore_changes = [desired_count]
  }

  depends_on = [aws_lb_listener_rule.this]
}

# --- ALB target group + listener rule (web/api/git) ------------------------

resource "aws_lb_target_group" "this" {
  count                = var.attach_alb && var.container_port != null ? 1 : 0
  name                 = "agentry-${var.environment}-${var.name}"
  port                 = var.container_port
  protocol             = "HTTP"
  vpc_id               = var.vpc_id
  target_type          = "ip"
  deregistration_delay = var.deregistration_delay

  health_check {
    path                = var.health_check_path
    healthy_threshold   = 2
    unhealthy_threshold = 3
    timeout             = 5
    interval            = 15
    matcher             = "200"
  }

  tags = var.tags
}

resource "aws_lb_listener_rule" "this" {
  count        = var.attach_alb && var.container_port != null ? 1 : 0
  listener_arn = var.alb_listener_arn
  priority     = var.alb_listener_rule_priority

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this[0].arn
  }

  dynamic "condition" {
    for_each = length(var.alb_host_headers) > 0 ? [1] : []
    content {
      host_header {
        values = var.alb_host_headers
      }
    }
  }

  dynamic "condition" {
    for_each = length(var.alb_path_patterns) > 0 ? [1] : []
    content {
      path_pattern {
        values = var.alb_path_patterns
      }
    }
  }

  tags = var.tags
}

# --- Autoscaling (§13.3 scaling signals) -----------------------------------

resource "aws_appautoscaling_target" "this" {
  max_capacity       = var.max_count
  min_capacity       = var.min_count
  resource_id        = "service/${element(split("/", var.cluster_arn), 1)}/${var.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"

  depends_on = [aws_ecs_service.this]
}

resource "aws_appautoscaling_policy" "this" {
  name               = "agentry-${var.environment}-${var.name}-track"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.this.resource_id
  scalable_dimension = aws_appautoscaling_target.this.scalable_dimension
  service_namespace  = aws_appautoscaling_target.this.service_namespace

  target_tracking_scaling_policy_configuration {
    target_value       = var.scaling_target_value
    scale_in_cooldown  = 120
    scale_out_cooldown = 60

    dynamic "predefined_metric_specification" {
      for_each = var.scaling_metric == "cpu" ? [1] : []
      content {
        predefined_metric_type = "ECSServiceAverageCPUUtilization"
      }
    }

    dynamic "predefined_metric_specification" {
      for_each = var.scaling_metric == "alb_request_count" && var.attach_alb ? [1] : []
      content {
        predefined_metric_type = "ALBRequestCountPerTarget"
        resource_label         = "${var.alb_arn_suffix}/${aws_lb_target_group.this[0].arn_suffix}"
      }
    }

    dynamic "customized_metric_specification" {
      for_each = var.scaling_metric == "custom" && var.scaling_custom_metric != null ? [1] : []
      content {
        namespace   = var.scaling_custom_metric.namespace
        metric_name = var.scaling_custom_metric.metric_name
        statistic   = var.scaling_custom_metric.statistic
        dynamic "dimensions" {
          for_each = var.scaling_custom_metric.dimensions
          content {
            name  = dimensions.key
            value = dimensions.value
          }
        }
      }
    }
  }
}
