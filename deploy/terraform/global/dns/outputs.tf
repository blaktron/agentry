output "zone_id" {
  value = var.create_zone ? aws_route53_zone.this[0].zone_id : null
}

output "name_servers" {
  description = "Delegate the registrar to these."
  value       = var.create_zone ? aws_route53_zone.this[0].name_servers : null
}

output "cloudfront_certificate_arn" {
  description = "us-east-1 ACM cert for CloudFront (cloudfront module acm_certificate_arn)."
  value       = aws_acm_certificate.cloudfront.arn
}

output "alb_certificate_arn" {
  description = "Regional ACM cert for the app + git ALBs."
  value       = aws_acm_certificate.alb.arn
}
