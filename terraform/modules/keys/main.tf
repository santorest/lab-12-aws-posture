terraform {
  required_version = ">= 1.16.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = ">= 6.0" }
  }
}

variable "kms_no_rotation" {
  description = "P7a: rotation off"
  type        = bool
}

resource "aws_kms_key" "data" {
  description             = "acme data key"
  enable_key_rotation     = !var.kms_no_rotation
  deletion_window_in_days = 7
  tags                    = { Name = "acme-data" }
}

resource "aws_kms_alias" "data" {
  name          = "alias/acme-data"
  target_key_id = aws_kms_key.data.key_id
}

output "key_arn" {
  description = "ARN of the acme data key"
  value       = aws_kms_key.data.arn
}

output "names" {
  description = "Name tag of the key"
  value       = [aws_kms_key.data.tags["Name"]]
}

output "posture" {
  description = "Planted parts in this module"
  value       = { p7a_rotation = aws_kms_key.data.enable_key_rotation }
}
