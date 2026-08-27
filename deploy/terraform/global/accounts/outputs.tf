output "github_deploy_role_arn" {
  description = "Role GitHub Actions assumes via OIDC (configure as the workflow's role-to-assume)."
  value       = var.create_oidc_provider ? aws_iam_role.github_deploy[0].arn : null
}

output "account_ids" {
  description = "Created member account IDs (empty unless manage_organization=true)."
  value = var.manage_organization ? {
    prod     = aws_organizations_account.prod[0].id
    nonprod  = aws_organizations_account.nonprod[0].id
    security = aws_organizations_account.security[0].id
  } : {}
}
