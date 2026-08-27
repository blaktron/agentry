resource "aws_elasticache_subnet_group" "this" {
  name       = "${var.name}-redis"
  subnet_ids = var.subnet_ids
  tags       = var.tags
}

resource "aws_security_group" "this" {
  name        = "${var.name}-redis"
  description = "ElastiCache Redis — 6379 from app-tier SGs only."
  vpc_id      = var.vpc_id
  tags        = merge(var.tags, { Name = "${var.name}-redis" })
}

resource "aws_vpc_security_group_ingress_rule" "redis" {
  for_each                     = toset(var.allowed_security_group_ids)
  security_group_id            = aws_security_group.this.id
  description                  = "Redis from app tier ${each.value}"
  from_port                    = 6379
  to_port                      = 6379
  ip_protocol                  = "tcp"
  referenced_security_group_id = each.value
}

# AUTH token for the rediss:// URL (in-transit TLS + token = the SaaS default).
resource "random_password" "auth" {
  length  = 48
  special = false
}

resource "aws_elasticache_replication_group" "this" {
  replication_group_id = "${var.name}-redis"
  description          = "agentry ${var.environment} sessions/rate-limits/caches"
  engine               = "redis"
  engine_version       = var.engine_version
  node_type            = var.node_type
  port                 = 6379

  num_node_groups            = 1
  replicas_per_node_group    = var.replica_count
  automatic_failover_enabled = var.replica_count > 0
  multi_az_enabled           = var.replica_count > 0

  subnet_group_name  = aws_elasticache_subnet_group.this.name
  security_group_ids = [aws_security_group.this.id]

  at_rest_encryption_enabled = true
  kms_key_id                 = var.kms_key_arn
  transit_encryption_enabled = true
  auth_token                 = random_password.auth.result

  snapshot_retention_limit = 7
  apply_immediately        = false

  tags = var.tags
}

resource "aws_secretsmanager_secret" "url" {
  name        = "agentry/${var.environment}/redis-url"
  description = "AGENTRY_REDIS_URL (rediss:// with auth token)."
  kms_key_id  = var.kms_key_arn
  tags        = var.tags
}

resource "aws_secretsmanager_secret_version" "url" {
  secret_id = aws_secretsmanager_secret.url.id
  secret_string = format(
    "rediss://:%s@%s:6379/0",
    random_password.auth.result,
    aws_elasticache_replication_group.this.primary_endpoint_address,
  )
}
