terraform {
  required_version = ">= 1.16.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = ">= 6.0" }
  }
}

variable "trail_missing_multiregion" {
  description = "P5a"
  type        = bool
}
variable "trail_no_validation" {
  description = "P5b"
  type        = bool
}
variable "cloudtrail_bucket_public" {
  description = "Demo only: the log bucket made public"
  type        = bool
}
variable "kms_key_arn" {
  description = "Key for the log bucket's default encryption"
  type        = string
}

resource "aws_s3_bucket" "trail" {
  bucket        = "acme-cloudtrail-logs"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "trail" {
  bucket                  = aws_s3_bucket.trail.id
  block_public_acls       = !var.cloudtrail_bucket_public
  block_public_policy     = !var.cloudtrail_bucket_public
  ignore_public_acls      = !var.cloudtrail_bucket_public
  restrict_public_buckets = !var.cloudtrail_bucket_public
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "trail" {
  bucket = aws_s3_bucket.trail.id
  versioning_configuration {
    status = "Enabled"
  }
}

locals {
  cloudtrail_statements = [
    {
      Sid       = "CloudTrailAclCheck"
      Effect    = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action    = "s3:GetBucketAcl"
      Resource  = aws_s3_bucket.trail.arn
    },
    {
      Sid       = "CloudTrailWrite"
      Effect    = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action    = "s3:PutObject"
      Resource  = "${aws_s3_bucket.trail.arn}/*"
      Condition = { StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" } }
    },
    {
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.trail.arn, "${aws_s3_bucket.trail.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    },
  ]
  public_statement = [{
    Sid       = "PublicRead"
    Effect    = "Allow"
    Principal = "*"
    Action    = "s3:GetObject"
    Resource  = "${aws_s3_bucket.trail.arn}/*"
  }]
}

resource "aws_s3_bucket_policy" "trail" {
  bucket     = aws_s3_bucket.trail.id
  depends_on = [aws_s3_bucket_public_access_block.trail]
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = concat(local.cloudtrail_statements, var.cloudtrail_bucket_public ? local.public_statement : [])
  })
}

# P5 — one trail; single-region and without log file validation when the flaws are on
resource "aws_cloudtrail" "this" {
  name                          = "acme-trail"
  s3_bucket_name                = aws_s3_bucket.trail.id
  is_multi_region_trail         = !var.trail_missing_multiregion
  include_global_service_events = true
  enable_log_file_validation    = !var.trail_no_validation
  kms_key_id                    = var.kms_key_arn
  depends_on                    = [aws_s3_bucket_policy.trail]
}

output "posture" {
  description = "Planted parts in this module"
  value = {
    p5a_multi_region                 = aws_cloudtrail.this.is_multi_region_trail
    p5b_log_validation               = aws_cloudtrail.this.enable_log_file_validation
    trail_bucket_block_public_access = aws_s3_bucket_public_access_block.trail.block_public_policy
  }
}
