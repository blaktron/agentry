# Global composition (§13.7 global/{accounts,dns,ecr}).

module "accounts" {
  source = "./accounts"

  manage_organization = var.manage_organization
  github_repository   = var.github_repository
}

module "dns" {
  source = "./dns"
  providers = {
    aws           = aws
    aws.us_east_1 = aws.us_east_1
  }

  apex_domain = var.apex_domain
  git_domain  = var.git_domain
}

module "ecr" {
  source = "./ecr"

  organization_id = var.organization_id
}
