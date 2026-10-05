# LocalStack only: emulated AWS, fixed test credentials. No real AWS account is ever used by this lab.
provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
  s3_use_path_style           = true
  endpoints {
    s3         = var.endpoint
    iam        = var.endpoint
    sts        = var.endpoint
    cloudtrail = var.endpoint
    ec2        = var.endpoint
    kms        = var.endpoint
    logs       = var.endpoint
  }
}
