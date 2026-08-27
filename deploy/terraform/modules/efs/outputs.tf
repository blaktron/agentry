output "file_system_id" {
  value = aws_efs_file_system.this.id
}

output "file_system_arn" {
  value = aws_efs_file_system.this.arn
}

output "security_group_id" {
  description = "EFS SG — git/worker-core egress 2049 to this."
  value       = aws_security_group.this.id
}

output "access_point_ids" {
  description = "name => access point id."
  value       = { for k, v in aws_efs_access_point.this : k => v.id }
}

output "access_point_arns" {
  value = { for k, v in aws_efs_access_point.this : k => v.arn }
}
