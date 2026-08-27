# Route53 + ACM (PLAN §13.5). One hosted zone for the apex; git.* is a record
# in the same zone (separate ALB + WAF, not a separate zone). Two certs:
#   - us-east-1 for CloudFront (apex + www),
#   - regional for the ALBs (apex + www + git).
# All DNS-validated. TLS 1.2+ / HSTS preload are enforced at the edge (§13.5).

locals {
  apex_sans = ["www.${var.apex_domain}"]
  alb_sans  = ["www.${var.apex_domain}", var.git_domain]
}

resource "aws_route53_zone" "this" {
  count = var.create_zone ? 1 : 0
  name  = var.apex_domain
  tags  = var.tags
}

# --- CloudFront cert (must be us-east-1) ------------------------------------

resource "aws_acm_certificate" "cloudfront" {
  provider                  = aws.us_east_1
  domain_name               = var.apex_domain
  subject_alternative_names = local.apex_sans
  validation_method         = "DNS"
  tags                      = var.tags

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "cloudfront_validation" {
  for_each = var.create_zone ? {
    for dvo in aws_acm_certificate.cloudfront.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      type   = dvo.resource_record_type
      record = dvo.resource_record_value
    }
  } : {}

  zone_id         = aws_route53_zone.this[0].zone_id
  name            = each.value.name
  type            = each.value.type
  records         = [each.value.record]
  ttl             = 60
  allow_overwrite = true
}

resource "aws_acm_certificate_validation" "cloudfront" {
  count                   = var.create_zone ? 1 : 0
  provider                = aws.us_east_1
  certificate_arn         = aws_acm_certificate.cloudfront.arn
  validation_record_fqdns = [for r in aws_route53_record.cloudfront_validation : r.fqdn]
}

# --- Regional cert for the ALBs --------------------------------------------

resource "aws_acm_certificate" "alb" {
  domain_name               = var.apex_domain
  subject_alternative_names = local.alb_sans
  validation_method         = "DNS"
  tags                      = var.tags

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "alb_validation" {
  for_each = var.create_zone ? {
    for dvo in aws_acm_certificate.alb.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      type   = dvo.resource_record_type
      record = dvo.resource_record_value
    }
  } : {}

  zone_id         = aws_route53_zone.this[0].zone_id
  name            = each.value.name
  type            = each.value.type
  records         = [each.value.record]
  ttl             = 60
  allow_overwrite = true
}

resource "aws_acm_certificate_validation" "alb" {
  count                   = var.create_zone ? 1 : 0
  certificate_arn         = aws_acm_certificate.alb.arn
  validation_record_fqdns = [for r in aws_route53_record.alb_validation : r.fqdn]
}
