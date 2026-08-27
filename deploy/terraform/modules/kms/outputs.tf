output "data_key_arn" {
  value = aws_kms_key.data.arn
}

output "data_key_id" {
  value = aws_kms_key.data.key_id
}

output "signing_key_arn" {
  description = "AGENTRY_SIGNING_KMS_KEY_ARN. Also the CloudTrail kms:Sign metric-filter target (T-09)."
  value       = aws_kms_key.signing.arn
}

output "signing_key_id" {
  value = aws_kms_key.signing.key_id
}
