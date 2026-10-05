terraform {
  required_version = ">= 1.16.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = ">= 6.0" }
  }
}

variable "s3_public_assets" {
  description = "P1"
  type        = bool
}
variable "s3_data_unencrypted" {
  description = "P2a"
  type        = bool
}
variable "s3_data_no_versioning_tls" {
  description = "P2b"
  type        = bool
}
variable "kms_key_arn" {
  description = "Key for the data bucket's default encryption"
  type        = string
}

# P1 — a bucket for website assets, readable by anyone when the flaw is on
resource "aws_s3_bucket" "public_assets" {
  bucket        = "acme-public-assets"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "public_assets" {
  bucket                  = aws_s3_bucket.public_assets.id
  block_public_acls       = !var.s3_public_assets
  block_public_policy     = !var.s3_public_assets
  ignore_public_acls      = !var.s3_public_assets
  restrict_public_buckets = !var.s3_public_assets
}

resource "aws_s3_bucket_policy" "public_assets" {
  count      = var.s3_public_assets ? 1 : 0
  bucket     = aws_s3_bucket.public_assets.id
  depends_on = [aws_s3_bucket_public_access_block.public_assets]
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PublicRead"
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.public_assets.arn}/*"
    }]
  })
}

# P2 — customer data: not encrypted, not versioned and reachable over HTTP when the flaws are on
resource "aws_s3_bucket" "customer_data" {
  bucket        = "acme-customer-data"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "customer_data" {
  bucket                  = aws_s3_bucket.customer_data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "customer_data" {
  count  = var.s3_data_unencrypted ? 0 : 1
  bucket = aws_s3_bucket.customer_data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "customer_data" {
  count  = var.s3_data_no_versioning_tls ? 0 : 1
  bucket = aws_s3_bucket.customer_data.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_policy" "customer_data_tls" {
  count      = var.s3_data_no_versioning_tls ? 0 : 1
  bucket     = aws_s3_bucket.customer_data.id
  depends_on = [aws_s3_bucket_public_access_block.customer_data]
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.customer_data.arn, "${aws_s3_bucket.customer_data.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

output "data_bucket_arn" {
  description = "ARN of the customer data bucket"
  value       = aws_s3_bucket.customer_data.arn
}

output "posture" {
  description = "Planted parts in this module"
  value = {
    p1_public_policy       = length(aws_s3_bucket_policy.public_assets) > 0
    p1_block_public_access = aws_s3_bucket_public_access_block.public_assets.block_public_policy
    p2a_encryption         = length(aws_s3_bucket_server_side_encryption_configuration.customer_data) > 0
    p2b_versioning         = length(aws_s3_bucket_versioning.customer_data) > 0
    p2b_tls_only           = length(aws_s3_bucket_policy.customer_data_tls) > 0
  }
}
