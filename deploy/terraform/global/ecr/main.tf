# ECR repositories (PLAN §13.3, §13.7): scan-on-push, immutable tags,
# lifecycle expiry. The git service image (agentryd) additionally carries the
# git binary — same repo, built by CI.

resource "aws_ecr_repository" "this" {
  for_each             = toset(var.repositories)
  name                 = "agentry/${each.value}"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = var.kms_key_arn == null ? "AES256" : "KMS"
    kms_key         = var.kms_key_arn
  }

  tags = var.tags
}

resource "aws_ecr_lifecycle_policy" "this" {
  for_each   = aws_ecr_repository.this
  repository = each.value.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Expire untagged images after 14 days"
        selection = {
          tagStatus   = "untagged"
          countType   = "sinceImagePushed"
          countUnit   = "days"
          countNumber = 14
        }
        action = { type = "expire" }
      },
      {
        rulePriority = 2
        description  = "Keep only the most recent tagged images"
        selection = {
          tagStatus     = "tagged"
          tagPrefixList = ["v", "sha-"]
          countType     = "imageCountMoreThan"
          countNumber   = var.keep_last_images
        }
        action = { type = "expire" }
      },
    ]
  })
}

# Cross-account pull for the workload accounts (scoped to the org).
data "aws_iam_policy_document" "cross_account_pull" {
  count = var.organization_id == null ? 0 : 1

  statement {
    sid    = "OrgPull"
    effect = "Allow"
    actions = [
      "ecr:GetDownloadUrlForLayer",
      "ecr:BatchGetImage",
      "ecr:BatchCheckLayerAvailability",
    ]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalOrgID"
      values   = [var.organization_id]
    }
  }
}

resource "aws_ecr_repository_policy" "this" {
  for_each   = var.organization_id == null ? {} : aws_ecr_repository.this
  repository = each.value.name
  policy     = data.aws_iam_policy_document.cross_account_pull[0].json
}
