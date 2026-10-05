terraform {
  required_version = ">= 1.16.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = ">= 6.0" }
  }
}

variable "iam_admin_policy" {
  description = "P3"
  type        = bool
}
variable "iam_user_keys_no_mfa" {
  description = "P4a"
  type        = bool
}
variable "iam_weak_password_policy" {
  description = "P4b"
  type        = bool
}
variable "data_bucket_arn" {
  description = "What the deploy user really needs to read"
  type        = string
}

locals {
  admin  = { Version = "2012-10-17", Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }] }
  narrow = { Version = "2012-10-17", Statement = [{ Effect = "Allow", Action = "s3:GetObject", Resource = "${var.data_bucket_arn}/*" }] }
  deploy = var.iam_admin_policy ? local.admin : local.narrow
}

resource "aws_iam_user" "deploy" {
  name          = "svc-deploy"
  force_destroy = true
}

# P4a — a long-lived key on a user without MFA (MFA cannot be meaningfully emulated: the fix removes the key)
resource "aws_iam_access_key" "deploy" {
  count = var.iam_user_keys_no_mfa ? 1 : 0
  user  = aws_iam_user.deploy.name
}

# P3 — the deploy user's policy: everything on everything, or only what it needs
resource "aws_iam_policy" "deploy" {
  name   = "acme-admin-policy"
  policy = jsonencode(local.deploy)
}

resource "aws_iam_user_policy_attachment" "deploy" {
  user       = aws_iam_user.deploy.name
  policy_arn = aws_iam_policy.deploy.arn
}

# P4b — account password policy
resource "aws_iam_account_password_policy" "this" {
  minimum_password_length        = var.iam_weak_password_policy ? 6 : 14
  password_reuse_prevention      = var.iam_weak_password_policy ? 0 : 24
  require_uppercase_characters   = !var.iam_weak_password_policy
  require_lowercase_characters   = !var.iam_weak_password_policy
  require_numbers                = !var.iam_weak_password_policy
  require_symbols                = !var.iam_weak_password_policy
  max_password_age               = var.iam_weak_password_policy ? 0 : 90
  allow_users_to_change_password = true
}

output "posture" {
  description = "Planted parts in this module"
  value = {
    p3_admin_policy      = anytrue([for st in local.deploy.Statement : st.Action == "*" && st.Resource == "*"])
    p4a_access_key       = length(aws_iam_access_key.deploy) > 0
    p4b_min_length       = aws_iam_account_password_policy.this.minimum_password_length
    p4b_reuse_prevention = aws_iam_account_password_policy.this.password_reuse_prevention
  }
}
