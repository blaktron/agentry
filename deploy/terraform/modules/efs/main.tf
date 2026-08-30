# EFS for the git bare repos (PLAN §6.2, §13.4, D-19). General Purpose, elastic
# throughput, encrypted, uid-scoped access points, mount targets in the data
# subnets, and AWS Backup daily/35d.

locals {
  # The environment tag rides with every resource this module creates.
  tags = merge(var.tags, { Environment = var.environment })
}

resource "aws_efs_file_system" "this" {
  creation_token   = "${var.name}-git"
  encrypted        = true
  kms_key_id       = var.kms_key_arn
  performance_mode = "generalPurpose"
  throughput_mode  = "elastic"

  dynamic "lifecycle_policy" {
    for_each = var.transition_to_ia == null ? [] : [var.transition_to_ia]
    content {
      transition_to_ia = lifecycle_policy.value
    }
  }

  tags = merge(local.tags, { Name = "${var.name}-git" })
}

resource "aws_security_group" "this" {
  name        = "${var.name}-efs"
  description = "EFS mount targets — 2049 from git-tier SGs only."
  vpc_id      = var.vpc_id
  tags        = merge(local.tags, { Name = "${var.name}-efs" })
}

resource "aws_vpc_security_group_ingress_rule" "nfs" {
  for_each                     = toset(var.allowed_security_group_ids)
  security_group_id            = aws_security_group.this.id
  description                  = "NFS from git tier ${each.value}"
  from_port                    = 2049
  to_port                      = 2049
  ip_protocol                  = "tcp"
  referenced_security_group_id = each.value
}

resource "aws_efs_mount_target" "this" {
  count           = length(var.subnet_ids)
  file_system_id  = aws_efs_file_system.this.id
  subnet_id       = var.subnet_ids[count.index]
  security_groups = [aws_security_group.this.id]
}

# uid-scoped access points — the git role sees only /git as uid 10001 (§13.3).
resource "aws_efs_access_point" "this" {
  for_each       = var.access_points
  file_system_id = aws_efs_file_system.this.id

  posix_user {
    uid = each.value.uid
    gid = each.value.gid
  }

  root_directory {
    path = each.value.path
    creation_info {
      owner_uid   = each.value.uid
      owner_gid   = each.value.gid
      permissions = each.value.perm
    }
  }

  tags = merge(local.tags, { Name = "${var.name}-${each.key}" })
}

# --- AWS Backup (daily, 35 d) ---------------------------------------------

resource "aws_backup_vault" "this" {
  name        = "${var.name}-efs"
  kms_key_arn = var.kms_key_arn
  tags        = local.tags
}

resource "aws_iam_role" "backup" {
  name = "${var.name}-efs-backup"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "backup.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = local.tags
}

resource "aws_iam_role_policy_attachment" "backup" {
  role       = aws_iam_role.backup.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
}

resource "aws_backup_plan" "this" {
  name = "${var.name}-efs-daily"

  rule {
    rule_name         = "daily"
    target_vault_name = aws_backup_vault.this.name
    schedule          = "cron(0 5 * * ? *)"
    start_window      = 60
    completion_window = 300

    lifecycle {
      delete_after = var.backup_retention_days
    }
  }

  tags = local.tags
}

resource "aws_backup_selection" "this" {
  name         = "${var.name}-efs"
  iam_role_arn = aws_iam_role.backup.arn
  plan_id      = aws_backup_plan.this.id
  resources    = [aws_efs_file_system.this.arn]
}
