output "cloudfront_domain_name" {
  value = module.cloudfront.domain_name
}

output "app_alb_dns_name" {
  value = aws_lb.app.dns_name
}

output "git_alb_dns_name" {
  value = aws_lb.git.dns_name
}

output "releases_bucket" {
  value = module.s3_suite.releases_bucket
}

output "rds_endpoint" {
  value = module.rds.endpoint
}

output "signing_key_arn" {
  value = module.kms.signing_key_arn
}

output "page_topic_arn" {
  value = module.observability.page_topic_arn
}
