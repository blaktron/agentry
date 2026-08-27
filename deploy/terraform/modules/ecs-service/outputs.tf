output "service_name" {
  value = aws_ecs_service.this.name
}

output "task_definition_arn" {
  value = aws_ecs_task_definition.this.arn
}

output "security_group_id" {
  description = "The service's own SG (egress profile lives here)."
  value       = aws_security_group.service.id
}

output "task_role_arn" {
  description = "Application identity — reference this in KMS/S3 key policies for least privilege."
  value       = aws_iam_role.task.arn
}

output "task_role_name" {
  value = aws_iam_role.task.name
}

output "execution_role_arn" {
  value = aws_iam_role.execution.arn
}

output "target_group_arn" {
  value = var.attach_alb && var.container_port != null ? aws_lb_target_group.this[0].arn : null
}

output "log_group_name" {
  value = aws_cloudwatch_log_group.this.name
}
