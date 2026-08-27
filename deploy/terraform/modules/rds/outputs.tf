output "security_group_id" {
  description = "RDS SG — services egress 5432 to this."
  value       = aws_security_group.this.id
}

output "endpoint" {
  value = aws_db_instance.this.address
}

output "port" {
  value = aws_db_instance.this.port
}

output "db_name" {
  value = aws_db_instance.this.db_name
}

output "database_url_secret_arn" {
  description = "Secrets Manager ARN holding the AGENTRY_DATABASE_URL DSN."
  value       = aws_secretsmanager_secret.dsn.arn
}

output "instance_identifier" {
  description = "Used by the observability module for the RDS failover EventBridge rule."
  value       = aws_db_instance.this.identifier
}
