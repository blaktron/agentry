output "github_deploy_role_arn" {
  value = module.accounts.github_deploy_role_arn
}

output "zone_name_servers" {
  value = module.dns.name_servers
}

output "cloudfront_certificate_arn" {
  value = module.dns.cloudfront_certificate_arn
}

output "alb_certificate_arn" {
  value = module.dns.alb_certificate_arn
}

output "ecr_repository_urls" {
  value = module.ecr.repository_urls
}
