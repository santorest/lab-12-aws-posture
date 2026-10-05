# Feasibility spike: every planted flaw at its flawed setting, applied to LocalStack. Removed in Task 9.
terraform {
  required_version = ">= 1.16.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "6.67.0"
    }
  }
}

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
  s3_use_path_style           = true
  endpoints {
    s3         = "http://localhost:4566"
    iam        = "http://localhost:4566"
    sts        = "http://localhost:4566"
    cloudtrail = "http://localhost:4566"
    ec2        = "http://localhost:4566"
    kms        = "http://localhost:4566"
    logs       = "http://localhost:4566"
  }
}

# P1 public bucket
resource "aws_s3_bucket" "public_assets" {
  bucket = "acme-public-assets"
}
resource "aws_s3_bucket_public_access_block" "public_assets" {
  bucket                  = aws_s3_bucket.public_assets.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}
resource "aws_s3_bucket_policy" "public_assets" {
  bucket     = aws_s3_bucket.public_assets.id
  depends_on = [aws_s3_bucket_public_access_block.public_assets]
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = "*", Action = "s3:GetObject", Resource = "${aws_s3_bucket.public_assets.arn}/*" }]
  })
}

# P2 unencrypted, unversioned data bucket (no TLS-only policy)
resource "aws_s3_bucket" "customer_data" {
  bucket = "acme-customer-data"
}

# P3 admin policy attached to a user; P4a user with access key, no MFA
resource "aws_iam_user" "deploy" {
  name = "svc-deploy"
}
resource "aws_iam_access_key" "deploy" {
  user = aws_iam_user.deploy.name
}
resource "aws_iam_policy" "admin" {
  name   = "acme-admin-policy"
  policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }] })
}
resource "aws_iam_user_policy_attachment" "deploy_admin" {
  user       = aws_iam_user.deploy.name
  policy_arn = aws_iam_policy.admin.arn
}

# P4b weak password policy
resource "aws_iam_account_password_policy" "weak" {
  minimum_password_length = 6
}

# P5 single-region trail without log validation
resource "aws_s3_bucket" "trail" {
  bucket        = "acme-cloudtrail-logs"
  force_destroy = true
}
resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Principal = { Service = "cloudtrail.amazonaws.com" }, Action = "s3:GetBucketAcl", Resource = aws_s3_bucket.trail.arn },
      { Effect = "Allow", Principal = { Service = "cloudtrail.amazonaws.com" }, Action = "s3:PutObject", Resource = "${aws_s3_bucket.trail.arn}/*" },
    ]
  })
}
resource "aws_cloudtrail" "trail" {
  name                          = "acme-trail"
  s3_bucket_name                = aws_s3_bucket.trail.id
  is_multi_region_trail         = false
  enable_log_file_validation    = false
  include_global_service_events = false
  depends_on                    = [aws_s3_bucket_policy.trail]
}

# P6a open admin ports; P6b default SG allows traffic; P7b VPC without flow logs
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
  tags       = { Name = "acme-vpc" }
}
resource "aws_security_group" "legacy_admin" {
  name   = "acme-legacy-admin"
  vpc_id = aws_vpc.main.id
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main.id
  ingress {
    from_port = 0
    to_port   = 0
    protocol  = "-1"
    self      = true
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# P7a KMS key without rotation
resource "aws_kms_key" "data" {
  description         = "acme data key"
  enable_key_rotation = false
}
resource "aws_kms_alias" "data" {
  name          = "alias/acme-data"
  target_key_id = aws_kms_key.data.key_id
}
