output "adot_config_ssm_arn" {
  description = "Pass to ecs-service.adot_config_ssm_arn so sidecars load this config."
  value       = aws_ssm_parameter.adot_config.arn
}

output "page_topic_arn" {
  value = aws_sns_topic.page.arn
}

output "ticket_topic_arn" {
  value = aws_sns_topic.ticket.arn
}

output "metrics_log_group" {
  value = aws_cloudwatch_log_group.metrics.name
}
