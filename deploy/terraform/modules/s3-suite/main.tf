# Three-bucket S3 suite (PLAN §13.4):
#   releases      — immutable content-addressed archives (§6.5): versioned,
#                   object-lock GOVERNANCE 2y, deny-delete policy, EventBridge
#                   on write, read via CloudFront OAC.
#   evidence      — scan reports + judge transcripts; lifecycle -> IA 90d.
#   audit-archive — tamper-evident NDJSON; object-lock COMPLIANCE 400d,
#                   replicated to the security account.
# All buckets: SSE-KMS, public access fully blocked, TLS-only.

locals {
  # The environment tag rides with every resource this module creates.
  tags = merge(var.tags, { Environment = var.environment })
}

data "aws_caller_identity" "current" {}

# ===========================================================================
# releases
# ===========================================================================

resource "aws_s3_bucket" "releases" {
  bucket              = "${var.name}-releases"
  object_lock_enabled = true
  tags                = merge(local.tags, { Name = "${var.name}-releases" })
}

resource "aws_s3_bucket_versioning" "releases" {
  bucket = aws_s3_bucket.releases.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "releases" {
  bucket = aws_s3_bucket.releases.id
  rule {
    default_retention {
      mode  = "GOVERNANCE"
      years = var.releases_object_lock_years
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "releases" {
  bucket = aws_s3_bucket.releases.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "releases" {
  bucket                  = aws_s3_bucket.releases.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_notification" "releases" {
  bucket      = aws_s3_bucket.releases.id
  eventbridge = true
}

data "aws_iam_policy_document" "releases" {
  statement {
    sid       = "EnforceTLS"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.releases.arn, "${aws_s3_bucket.releases.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  # Write-once: nobody may delete objects/versions (§13.4 deny-delete).
  statement {
    sid       = "DenyDelete"
    effect    = "Deny"
    actions   = ["s3:DeleteObject", "s3:DeleteObjectVersion"]
    resources = ["${aws_s3_bucket.releases.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }

  # CloudFront OAC read (scoped to this account's distributions).
  statement {
    sid       = "AllowCloudFrontOAC"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.releases.arn}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_s3_bucket_policy" "releases" {
  bucket = aws_s3_bucket.releases.id
  policy = data.aws_iam_policy_document.releases.json
}

# ===========================================================================
# evidence
# ===========================================================================

resource "aws_s3_bucket" "evidence" {
  bucket = "${var.name}-evidence"
  tags   = merge(local.tags, { Name = "${var.name}-evidence" })
}

resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket                  = aws_s3_bucket.evidence.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    id     = "to-ia"
    status = "Enabled"
    filter {}
    transition {
      days          = var.evidence_ia_transition_days
      storage_class = "STANDARD_IA"
    }
  }
}

data "aws_iam_policy_document" "evidence" {
  statement {
    sid       = "EnforceTLS"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.evidence.arn, "${aws_s3_bucket.evidence.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  policy = data.aws_iam_policy_document.evidence.json
}

# ===========================================================================
# audit-archive
# ===========================================================================

resource "aws_s3_bucket" "audit" {
  bucket              = "${var.name}-audit-archive"
  object_lock_enabled = true
  tags                = merge(local.tags, { Name = "${var.name}-audit-archive" })
}

resource "aws_s3_bucket_versioning" "audit" {
  bucket = aws_s3_bucket.audit.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id
  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = var.audit_object_lock_days
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "audit" {
  bucket                  = aws_s3_bucket.audit.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_iam_policy_document" "audit" {
  statement {
    sid       = "EnforceTLS"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.audit.arn, "${aws_s3_bucket.audit.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid       = "DenyDelete"
    effect    = "Deny"
    actions   = ["s3:DeleteObject", "s3:DeleteObjectVersion"]
    resources = ["${aws_s3_bucket.audit.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}

resource "aws_s3_bucket_policy" "audit" {
  bucket = aws_s3_bucket.audit.id
  policy = data.aws_iam_policy_document.audit.json
}

# --- audit-archive replication to the security account ---------------------

locals {
  replication_enabled = var.audit_replication_destination_bucket_arn != null
}

data "aws_iam_policy_document" "replication_assume" {
  count = local.replication_enabled ? 1 : 0
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "replication" {
  count              = local.replication_enabled ? 1 : 0
  name               = "${var.name}-audit-replication"
  assume_role_policy = data.aws_iam_policy_document.replication_assume[0].json
  tags               = local.tags
}

data "aws_iam_policy_document" "replication" {
  count = local.replication_enabled ? 1 : 0

  statement {
    actions   = ["s3:GetReplicationConfiguration", "s3:ListBucket"]
    resources = [aws_s3_bucket.audit.arn]
  }
  statement {
    actions   = ["s3:GetObjectVersionForReplication", "s3:GetObjectVersionAcl", "s3:GetObjectVersionTagging"]
    resources = ["${aws_s3_bucket.audit.arn}/*"]
  }
  statement {
    actions   = ["s3:ReplicateObject", "s3:ReplicateDelete", "s3:ReplicateTags"]
    resources = ["${var.audit_replication_destination_bucket_arn}/*"]
  }
}

resource "aws_iam_role_policy" "replication" {
  count  = local.replication_enabled ? 1 : 0
  name   = "replication"
  role   = aws_iam_role.replication[0].id
  policy = data.aws_iam_policy_document.replication[0].json
}

resource "aws_s3_bucket_replication_configuration" "audit" {
  count      = local.replication_enabled ? 1 : 0
  bucket     = aws_s3_bucket.audit.id
  role       = aws_iam_role.replication[0].arn
  depends_on = [aws_s3_bucket_versioning.audit]

  rule {
    id       = "to-security-account"
    status   = "Enabled"
    priority = 0

    filter {}

    delete_marker_replication {
      status = "Disabled"
    }

    destination {
      bucket        = var.audit_replication_destination_bucket_arn
      storage_class = "STANDARD"

      dynamic "access_control_translation" {
        for_each = var.audit_replication_destination_account_id == null ? [] : [1]
        content {
          owner = "Destination"
        }
      }

      account = var.audit_replication_destination_account_id
    }
  }
}
