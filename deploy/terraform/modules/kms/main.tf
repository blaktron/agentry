# KMS keys (PLAN §13, D-16):
#   data    — symmetric envelope-encryption key (rotation on) for RDS/S3/EFS/
#             ElastiCache/Secrets SSE and app-level envelope encryption.
#   signing — asymmetric ECDSA_NIST_P256 for DSSE attestations (§8.8). Its key
#             policy restricts kms:Sign to the worker-core task role ONLY.
#
# T-09 / §16.3: enable CloudTrail *data events* for kms:Sign on the signing key
# so the observability module's "KMS Sign anomaly" alarm can fire on it. The
# signing_key_arn output is the metric-filter target.

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  root_arn = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"
}

# --- Data key (symmetric, rotating) ----------------------------------------

data "aws_iam_policy_document" "data" {
  statement {
    sid       = "EnableIAMRootPermissions"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = [local.root_arn]
    }
  }

  # Let AWS services (S3, RDS, EFS, ElastiCache, Secrets, Backup) use the key
  # on behalf of account principals via grants.
  statement {
    sid       = "AllowServiceUseViaGrants"
    effect    = "Allow"
    actions   = ["kms:CreateGrant", "kms:ListGrants", "kms:RevokeGrant"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = [local.root_arn]
    }
    condition {
      test     = "Bool"
      variable = "kms:GrantIsForAWSResource"
      values   = ["true"]
    }
  }
}

resource "aws_kms_key" "data" {
  description             = "agentry ${var.environment} data key (envelope encryption)"
  enable_key_rotation     = true
  deletion_window_in_days = var.deletion_window_days
  policy                  = data.aws_iam_policy_document.data.json
  tags                    = var.tags
}

resource "aws_kms_alias" "data" {
  name          = "alias/${var.name}-data"
  target_key_id = aws_kms_key.data.key_id
}

# --- Signing key (asymmetric ECDSA P-256; §8.8, D-16) ----------------------

data "aws_iam_policy_document" "signing" {
  statement {
    sid       = "KeyAdministration"
    effect    = "Allow"
    actions   = ["kms:Create*", "kms:Describe*", "kms:Enable*", "kms:List*", "kms:Put*", "kms:Update*", "kms:Revoke*", "kms:Disable*", "kms:Get*", "kms:Delete*", "kms:TagResource", "kms:UntagResource", "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = [local.root_arn]
    }
  }

  # Sign is granted to account IAM principals BUT restricted by condition to
  # exactly the worker-core task role ARN(s). Using a condition (not a hard
  # Principal reference) keeps this key independent of the ECS module, so the
  # role can be created afterward without a dependency cycle.
  statement {
    sid       = "AllowWorkerCoreSignOnly"
    effect    = "Allow"
    actions   = ["kms:Sign", "kms:GetPublicKey", "kms:DescribeKey"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = [local.root_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalArn"
      values   = var.signing_principal_arns
    }
  }

  # Public-key retrieval / verify is safe to expose to account principals
  # (verification is public via /.well-known/agentry/signing-keys.json, §8.8).
  statement {
    sid       = "AllowVerify"
    effect    = "Allow"
    actions   = ["kms:Verify", "kms:GetPublicKey", "kms:DescribeKey"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = [local.root_arn]
    }
  }
}

resource "aws_kms_key" "signing" {
  description              = "agentry ${var.environment} DSSE attestation signing key (ECDSA P-256, D-16)"
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "ECC_NIST_P256"
  enable_key_rotation      = false # asymmetric keys cannot auto-rotate; rotation is manual w/ overlapping validity (§8.8)
  deletion_window_in_days  = var.deletion_window_days
  policy                   = data.aws_iam_policy_document.signing.json
  tags                     = var.tags
}

resource "aws_kms_alias" "signing" {
  name          = "alias/${var.name}-signing"
  target_key_id = aws_kms_key.signing.key_id
}
