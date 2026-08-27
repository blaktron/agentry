# Remote state for the global config (§13.7: S3 + DynamoDB lock).
# PLACEHOLDER bucket/table — create out-of-band (or via a bootstrap module)
# before `terraform init`. Q8: region defaults to us-east-1.
terraform {
  backend "s3" {
    bucket         = "agentry-tfstate-PLACEHOLDER" # PLACEHOLDER
    key            = "global/terraform.tfstate"
    region         = "us-east-1"                  # Q8
    dynamodb_table = "agentry-tflock-PLACEHOLDER" # PLACEHOLDER
    encrypt        = true
  }
}
