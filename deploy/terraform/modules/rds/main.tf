# RDS PostgreSQL 16 — the system of record (PLAN §13.4, D-03). Multi-AZ, gp3,
# Performance Insights, PITR, encrypted at rest with the KMS data key. The full
# AGENTRY_DATABASE_URL DSN is published to Secrets Manager so ecs-service can
# inject it as a secret env var.

resource "aws_db_subnet_group" "this" {
  name       = "${var.name}-pg"
  subnet_ids = var.subnet_ids
  tags       = var.tags
}

resource "aws_security_group" "this" {
  name        = "${var.name}-rds"
  description = "RDS Postgres — 5432 from app-tier SGs only."
  vpc_id      = var.vpc_id
  tags        = merge(var.tags, { Name = "${var.name}-rds" })
}

resource "aws_vpc_security_group_ingress_rule" "postgres" {
  for_each                     = toset(var.allowed_security_group_ids)
  security_group_id            = aws_security_group.this.id
  description                  = "Postgres from app tier ${each.value}"
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
  referenced_security_group_id = each.value
}

# force_ssl so clients must use TLS (agentryd uses sslmode=require in prod DSNs).
resource "aws_db_parameter_group" "this" {
  name_prefix = "${var.name}-pg16-"
  family      = "postgres16"

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }
  parameter {
    name  = "log_min_duration_statement"
    value = "500"
  }

  lifecycle {
    create_before_destroy = true
  }
  tags = var.tags
}

resource "random_password" "master" {
  length           = 32
  special          = true
  override_special = "!#$%^&*()-_=+[]{}"
}

resource "aws_db_instance" "this" {
  identifier     = "${var.name}-pg"
  engine         = "postgres"
  engine_version = var.engine_version
  instance_class = var.instance_class

  db_name  = var.db_name
  username = var.master_username
  password = random_password.master.result
  port     = 5432

  allocated_storage     = var.allocated_storage
  max_allocated_storage = var.max_allocated_storage
  storage_type          = "gp3"
  storage_encrypted     = true
  kms_key_id            = var.kms_key_arn

  multi_az               = var.multi_az
  db_subnet_group_name   = aws_db_subnet_group.this.name
  vpc_security_group_ids = [aws_security_group.this.id]
  parameter_group_name   = aws_db_parameter_group.this.name

  backup_retention_period    = var.backup_retention_period
  backup_window              = "07:00-08:00"
  maintenance_window         = "Sun:08:30-Sun:09:30"
  copy_tags_to_snapshot      = true
  auto_minor_version_upgrade = true
  deletion_protection        = var.deletion_protection
  apply_immediately          = false

  performance_insights_enabled          = true
  performance_insights_kms_key_id       = var.kms_key_arn
  performance_insights_retention_period = var.performance_insights_retention
  enabled_cloudwatch_logs_exports       = ["postgresql", "upgrade"]

  final_snapshot_identifier = "${var.name}-pg-final"
  skip_final_snapshot       = false

  tags = var.tags
}

# Full DSN for AGENTRY_DATABASE_URL (§ config.go). sslmode=require enforces TLS.
resource "aws_secretsmanager_secret" "dsn" {
  name        = "agentry/${var.environment}/database-url"
  description = "AGENTRY_DATABASE_URL DSN for the agentry system-of-record DB."
  kms_key_id  = var.kms_key_arn
  tags        = var.tags
}

resource "aws_secretsmanager_secret_version" "dsn" {
  secret_id = aws_secretsmanager_secret.dsn.id
  secret_string = format(
    "postgres://%s:%s@%s:%d/%s?sslmode=require",
    var.master_username,
    random_password.master.result,
    aws_db_instance.this.address,
    aws_db_instance.this.port,
    var.db_name,
  )
}
