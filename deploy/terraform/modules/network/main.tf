# Network foundation (PLAN §13.2): VPC 10.0.0.0/16 across N AZs with three
# subnet tiers (public / private-app / private-data), IGW, NAT gateways, and
# the VPC endpoints (§13.2) that let private-tier tasks reach AWS services
# without internet egress — the substrate for the sandbox/judge no-egress
# profiles (§8.2).

data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  azs = slice(data.aws_availability_zones.available.names, 0, var.az_count)

  # /20 blocks carved from the /16: public 0-2, app 3-5, data 6-8.
  public_subnets = [for i in range(var.az_count) : cidrsubnet(var.vpc_cidr, 4, i)]
  app_subnets    = [for i in range(var.az_count) : cidrsubnet(var.vpc_cidr, 4, i + 3)]
  data_subnets   = [for i in range(var.az_count) : cidrsubnet(var.vpc_cidr, 4, i + 6)]

  nat_count = var.single_nat_gateway ? 1 : var.az_count
}

resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = merge(var.tags, { Name = var.name })
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags   = merge(var.tags, { Name = "${var.name}-igw" })
}

# --- Subnets ---------------------------------------------------------------

resource "aws_subnet" "public" {
  count                   = var.az_count
  vpc_id                  = aws_vpc.this.id
  cidr_block              = local.public_subnets[count.index]
  availability_zone       = local.azs[count.index]
  map_public_ip_on_launch = false
  tags = merge(var.tags, {
    Name = "${var.name}-public-${local.azs[count.index]}"
    Tier = "public"
  })
}

resource "aws_subnet" "app" {
  count             = var.az_count
  vpc_id            = aws_vpc.this.id
  cidr_block        = local.app_subnets[count.index]
  availability_zone = local.azs[count.index]
  tags = merge(var.tags, {
    Name = "${var.name}-app-${local.azs[count.index]}"
    Tier = "private-app"
  })
}

resource "aws_subnet" "data" {
  count             = var.az_count
  vpc_id            = aws_vpc.this.id
  cidr_block        = local.data_subnets[count.index]
  availability_zone = local.azs[count.index]
  tags = merge(var.tags, {
    Name = "${var.name}-data-${local.azs[count.index]}"
    Tier = "private-data"
  })
}

# --- NAT gateways (§13.3: 3 in prod, 1 shared in dev/staging) --------------

resource "aws_eip" "nat" {
  count      = local.nat_count
  domain     = "vpc"
  depends_on = [aws_internet_gateway.this]
  tags       = merge(var.tags, { Name = "${var.name}-nat-${count.index}" })
}

resource "aws_nat_gateway" "this" {
  count         = local.nat_count
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id
  tags          = merge(var.tags, { Name = "${var.name}-nat-${count.index}" })
  depends_on    = [aws_internet_gateway.this]
}

# --- Route tables ----------------------------------------------------------

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }
  tags = merge(var.tags, { Name = "${var.name}-public" })
}

resource "aws_route_table_association" "public" {
  count          = var.az_count
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# App subnets route egress through NAT (workers that legitimately need the
# internet — worker-core registry/webhook/SES — plus web/api).
resource "aws_route_table" "app" {
  count  = var.az_count
  vpc_id = aws_vpc.this.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.this[var.single_nat_gateway ? 0 : count.index].id
  }
  tags = merge(var.tags, { Name = "${var.name}-app-${local.azs[count.index]}" })
}

resource "aws_route_table_association" "app" {
  count          = var.az_count
  subnet_id      = aws_subnet.app[count.index].id
  route_table_id = aws_route_table.app[count.index].id
}

# Data subnets have NO default route to the internet (RDS/Redis/EFS only).
resource "aws_route_table" "data" {
  vpc_id = aws_vpc.this.id
  tags   = merge(var.tags, { Name = "${var.name}-data" })
}

resource "aws_route_table_association" "data" {
  count          = var.az_count
  subnet_id      = aws_subnet.data[count.index].id
  route_table_id = aws_route_table.data.id
}

# --- Tier / identity security groups ---------------------------------------
# These carry no rules of their own; they are membership tags used as the
# *source* in RDS/Redis/EFS/endpoint ingress rules, which keeps data-tier
# ingress restricted to app SGs (§13.4) without creating SG dependency cycles.

resource "aws_security_group" "app_tier" {
  name        = "${var.name}-app-tier"
  description = "Identity SG attached to every app-tier ECS task; source for data-tier ingress."
  vpc_id      = aws_vpc.this.id
  tags        = merge(var.tags, { Name = "${var.name}-app-tier" })
  # No ingress/egress: identity only. Egress is governed per-service.
}

resource "aws_security_group" "git_tier" {
  name        = "${var.name}-git-tier"
  description = "Identity SG for EFS-mounting tasks (git, worker-core gc); source for EFS ingress."
  vpc_id      = aws_vpc.this.id
  tags        = merge(var.tags, { Name = "${var.name}-git-tier" })
}

# --- VPC endpoints (§13.2) -------------------------------------------------

resource "aws_security_group" "endpoints" {
  name        = "${var.name}-vpce"
  description = "Interface VPC endpoints: 443 from within the VPC."
  vpc_id      = aws_vpc.this.id
  tags        = merge(var.tags, { Name = "${var.name}-vpce" })

  ingress {
    description = "HTTPS from within the VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    description = "Return traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.vpc_cidr]
  }
}

# S3 gateway endpoint — attached to app + data route tables so private tasks
# (incl. the no-egress sandbox) can reach the releases/evidence buckets.
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = concat(aws_route_table.app[*].id, [aws_route_table.data.id])
  tags              = merge(var.tags, { Name = "${var.name}-s3-gw" })
}

# Interface endpoints (ECR, Logs, Secrets, KMS, Bedrock, SES) in the data
# subnets with private DNS so service SDKs resolve to the endpoint privately.
resource "aws_vpc_endpoint" "interface" {
  for_each            = toset(var.interface_endpoints)
  vpc_id              = aws_vpc.this.id
  service_name        = "com.amazonaws.${var.aws_region}.${each.value}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.data[*].id
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = true
  tags                = merge(var.tags, { Name = "${var.name}-${each.value}" })
}
