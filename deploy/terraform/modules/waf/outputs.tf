output "web_acl_arn" {
  description = "web/API web ACL — associate to the app ALB."
  value       = aws_wafv2_web_acl.web.arn
}

output "web_acl_name" {
  value = aws_wafv2_web_acl.web.name
}

output "git_acl_arn" {
  description = "git web ACL — associate to the git ALB."
  value       = aws_wafv2_web_acl.git.arn
}

output "git_acl_name" {
  value = aws_wafv2_web_acl.git.name
}
