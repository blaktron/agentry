# Remote state (§13.7: S3 + DynamoDB lock, per env). PLACEHOLDER bucket/table.
# dev lives in the nonprod account (§13.1). Q8: region defaults to us-east-1.
terraform {
  backend "s3" {
    bucket         = "agentry-tfstate-PLACEHOLDER" # PLACEHOLDER
    key            = "envs/dev/terraform.tfstate"
    region         = "us-east-1"                  # Q8
    dynamodb_table = "agentry-tflock-PLACEHOLDER" # PLACEHOLDER
    encrypt        = true
  }
}
