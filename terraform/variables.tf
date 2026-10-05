# One switch per planted flaw (true = the flaw is present). envs/vulnerable.tfvars sets all true, envs/remediated.tfvars
# all false; both apply to the same state, so the remediation is an in-place change of the same resources.
variable "endpoint" {
  description = "LocalStack endpoint"
  type        = string
  default     = "http://localhost:4566"
}

variable "s3_public_assets" {
  description = "P1: assets bucket publicly readable, Block Public Access off"
  type        = bool
}
variable "s3_data_unencrypted" {
  description = "P2a: data bucket without a default encryption configuration"
  type        = bool
}
variable "s3_data_no_versioning_tls" {
  description = "P2b: data bucket unversioned, HTTP allowed"
  type        = bool
}
variable "iam_admin_policy" {
  description = "P3: Action * on Resource * attached to the deploy user"
  type        = bool
}
variable "iam_user_keys_no_mfa" {
  description = "P4a: long-lived access key on a user without MFA"
  type        = bool
}
variable "iam_weak_password_policy" {
  description = "P4b: weak account password policy"
  type        = bool
}
variable "trail_missing_multiregion" {
  description = "P5a: single-region trail"
  type        = bool
}
variable "trail_no_validation" {
  description = "P5b: trail without log file validation"
  type        = bool
}
variable "sg_admin_open" {
  description = "P6a: SSH and RDP open to 0.0.0.0/0"
  type        = bool
}
variable "sg_default_open" {
  description = "P6b: the VPC's default security group allows traffic"
  type        = bool
}
variable "kms_no_rotation" {
  description = "P7a: KMS key without rotation"
  type        = bool
}
variable "vpc_no_flow_logs" {
  description = "P7b: VPC without flow logs"
  type        = bool
}
variable "cloudtrail_bucket_public" {
  description = "Demo only: the CloudTrail log bucket made public"
  type        = bool
  default     = false
}
