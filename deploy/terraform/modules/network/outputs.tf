output "vpc_id" {
  value = aws_vpc.this.id
}

output "vpc_cidr" {
  value = aws_vpc.this.cidr_block
}

output "public_subnet_ids" {
  value = aws_subnet.public[*].id
}

output "app_subnet_ids" {
  value = aws_subnet.app[*].id
}

output "data_subnet_ids" {
  value = aws_subnet.data[*].id
}

output "app_tier_security_group_id" {
  description = "Attach to every app task; used as the source in data-tier ingress rules."
  value       = aws_security_group.app_tier.id
}

output "git_tier_security_group_id" {
  description = "Attach to EFS-mounting tasks (git, worker-core); source for EFS ingress."
  value       = aws_security_group.git_tier.id
}

output "endpoints_security_group_id" {
  description = "SG fronting the interface VPC endpoints; services egress 443 here."
  value       = aws_security_group.endpoints.id
}

output "s3_prefix_list_id" {
  description = "Prefix list of the S3 gateway endpoint; used in restricted egress rules."
  value       = aws_vpc_endpoint.s3.prefix_list_id
}

output "interface_endpoint_ids" {
  value = { for k, v in aws_vpc_endpoint.interface : k => v.id }
}
