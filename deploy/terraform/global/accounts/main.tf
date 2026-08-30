# AWS Organizations + GitHub Actions OIDC (PLAN §13.1).
#
# Accounts (§13.1): prod (production), nonprod (dev auto-deploy + staging as
# separate VPCs), security (org CloudTrail, audit-archive replication target,
# break-glass). Humans use IAM Identity Center; there are NO IAM users or
# long-lived keys anywhere — GitHub Actions deploys by assuming an OIDC role.

data "aws_partition" "current" {}

# --- Organization + member accounts (management account only) --------------

resource "aws_organizations_organization" "this" {
  count       = var.manage_organization ? 1 : 0
  feature_set = "ALL"
  aws_service_access_principals = [
    "cloudtrail.amazonaws.com",
    "sso.amazonaws.com",
    "backup.amazonaws.com",
  ]
}

resource "aws_organizations_organizational_unit" "workloads" {
  count     = var.manage_organization ? 1 : 0
  name      = "workloads"
  parent_id = aws_organizations_organization.this[0].roots[0].id
}

resource "aws_organizations_organizational_unit" "security" {
  count     = var.manage_organization ? 1 : 0
  name      = "security"
  parent_id = aws_organizations_organization.this[0].roots[0].id
}

resource "aws_organizations_account" "prod" {
  count     = var.manage_organization ? 1 : 0
  name      = "agentry-prod"
  email     = var.account_emails.prod
  parent_id = aws_organizations_organizational_unit.workloads[0].id
  role_name = "OrganizationAccountAccessRole"
  tags      = var.tags
  lifecycle {
    ignore_changes = [role_name]
  }
}

resource "aws_organizations_account" "nonprod" {
  count     = var.manage_organization ? 1 : 0
  name      = "agentry-nonprod"
  email     = var.account_emails.nonprod
  parent_id = aws_organizations_organizational_unit.workloads[0].id
  role_name = "OrganizationAccountAccessRole"
  tags      = var.tags
  lifecycle {
    ignore_changes = [role_name]
  }
}

resource "aws_organizations_account" "security" {
  count     = var.manage_organization ? 1 : 0
  name      = "agentry-security"
  email     = var.account_emails.security
  parent_id = aws_organizations_organizational_unit.security[0].id
  role_name = "OrganizationAccountAccessRole"
  tags      = var.tags
  lifecycle {
    ignore_changes = [role_name]
  }
}

# --- GitHub Actions OIDC provider + deploy role ----------------------------

resource "aws_iam_openid_connect_provider" "github" {
  count           = var.create_oidc_provider ? 1 : 0
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
  tags            = var.tags
}

data "aws_iam_policy_document" "github_assume" {
  count = var.create_oidc_provider ? 1 : 0

  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github[0].arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = [for b in var.github_deploy_branches : "repo:${var.github_repository}:ref:refs/heads/${b}"]
    }
  }
}

resource "aws_iam_role" "github_deploy" {
  count              = var.create_oidc_provider ? 1 : 0
  name               = "agentry-github-deploy"
  assume_role_policy = data.aws_iam_policy_document.github_assume[0].json
  tags               = var.tags
}

# Reference-grade permissions. In production, scope to the Terraform-managed
# resource ARNs and require a permissions boundary; keep plan (read-only) and
# apply as separate roles if desired.
resource "aws_iam_role_policy_attachment" "github_deploy_admin" {
  count      = var.create_oidc_provider ? 1 : 0
  role       = aws_iam_role.github_deploy[0].name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AdministratorAccess"
}
