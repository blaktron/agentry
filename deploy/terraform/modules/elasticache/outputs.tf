output "security_group_id" {
  description = "Redis SG — services egress 6379 to this."
  value       = aws_security_group.this.id
}

output "primary_endpoint" {
  value = aws_elasticache_replication_group.this.primary_endpoint_address
}

output "redis_url_secret_arn" {
  description = "Secrets Manager ARN holding AGENTRY_REDIS_URL."
  value       = aws_secretsmanager_secret.url.arn
}
