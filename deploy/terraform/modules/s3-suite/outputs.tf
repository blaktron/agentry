output "releases_bucket" {
  value = aws_s3_bucket.releases.bucket
}

output "releases_bucket_arn" {
  value = aws_s3_bucket.releases.arn
}

output "releases_bucket_regional_domain_name" {
  description = "Origin domain for the CloudFront releases behavior."
  value       = aws_s3_bucket.releases.bucket_regional_domain_name
}

output "evidence_bucket" {
  value = aws_s3_bucket.evidence.bucket
}

output "evidence_bucket_arn" {
  value = aws_s3_bucket.evidence.arn
}

output "audit_bucket" {
  value = aws_s3_bucket.audit.bucket
}

output "audit_bucket_arn" {
  value = aws_s3_bucket.audit.arn
}
