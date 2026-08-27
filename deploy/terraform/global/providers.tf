# Global account-scoped resources (org, DNS, ECR). Applied once, typically in
# the management/shared account. Q8: region defaults to us-east-1.

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      Project   = "agentry"
      ManagedBy = "terraform"
      Scope     = "global"
    }
  }
}

# us-east-1 alias for the CloudFront ACM certificate (ACM certs for CloudFront
# must live in us-east-1 regardless of the primary region).
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
  default_tags {
    tags = {
      Project   = "agentry"
      ManagedBy = "terraform"
      Scope     = "global"
    }
  }
}
