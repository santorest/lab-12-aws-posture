# Each planted flaw is present in the vulnerable posture and absent in the remediated one (mocked provider, plan only).
mock_provider "aws" {}

run "vulnerable" {
  command = plan
  variables {
    s3_public_assets          = true
    s3_data_unencrypted       = true
    s3_data_no_versioning_tls = true
    iam_admin_policy          = true
    iam_user_keys_no_mfa      = true
    iam_weak_password_policy  = true
    trail_missing_multiregion = true
    trail_no_validation       = true
    sg_admin_open             = true
    sg_default_open           = true
    kms_no_rotation           = true
    vpc_no_flow_logs          = true
  }
  assert {
    condition     = output.posture.p1_public_policy && !output.posture.p1_block_public_access
    error_message = "P1: the assets bucket must be public"
  }
  assert {
    condition     = !output.posture.p2a_encryption
    error_message = "P2a: the data bucket must have no default encryption configuration"
  }
  assert {
    condition     = !output.posture.p2b_versioning && !output.posture.p2b_tls_only
    error_message = "P2b: the data bucket must be unversioned and allow HTTP"
  }
  assert {
    condition     = output.posture.p3_admin_policy
    error_message = "P3: the deploy user's policy must allow * on *"
  }
  assert {
    condition     = output.posture.p4a_access_key
    error_message = "P4a: the deploy user must have an access key"
  }
  assert {
    condition     = output.posture.p4b_min_length < 14
    error_message = "P4b: the password policy must be weak"
  }
  assert {
    condition     = !output.posture.p5a_multi_region
    error_message = "P5a: the trail must be single-region"
  }
  assert {
    condition     = !output.posture.p5b_log_validation
    error_message = "P5b: the trail must not validate log files"
  }
  assert {
    condition     = contains(output.posture.p6a_admin_cidrs, "0.0.0.0/0")
    error_message = "P6a: SSH/RDP must be open to the internet"
  }
  assert {
    condition     = output.posture.p6b_default_sg_rules > 0
    error_message = "P6b: the default security group must have rules"
  }
  assert {
    condition     = !output.posture.p7a_rotation
    error_message = "P7a: KMS rotation must be off"
  }
  assert {
    condition     = !output.posture.p7b_flow_logs
    error_message = "P7b: the VPC must have no flow log"
  }
}

run "remediated" {
  command = plan
  variables {
    s3_public_assets          = false
    s3_data_unencrypted       = false
    s3_data_no_versioning_tls = false
    iam_admin_policy          = false
    iam_user_keys_no_mfa      = false
    iam_weak_password_policy  = false
    trail_missing_multiregion = false
    trail_no_validation       = false
    sg_admin_open             = false
    sg_default_open           = false
    kms_no_rotation           = false
    vpc_no_flow_logs          = false
  }
  assert {
    condition     = !output.posture.p1_public_policy && output.posture.p1_block_public_access
    error_message = "P1: the assets bucket must block public access"
  }
  assert {
    condition     = output.posture.p2a_encryption
    error_message = "P2a: the data bucket must be encrypted with the KMS key"
  }
  assert {
    condition     = output.posture.p2b_versioning && output.posture.p2b_tls_only
    error_message = "P2b: the data bucket must be versioned and TLS-only"
  }
  assert {
    condition     = !output.posture.p3_admin_policy
    error_message = "P3: the deploy user's policy must be narrowed"
  }
  assert {
    condition     = !output.posture.p4a_access_key
    error_message = "P4a: the long-lived access key must be gone"
  }
  assert {
    condition     = output.posture.p4b_min_length >= 14 && output.posture.p4b_reuse_prevention >= 24
    error_message = "P4b: the password policy must be strong"
  }
  assert {
    condition     = output.posture.p5a_multi_region
    error_message = "P5a: the trail must be multi-region"
  }
  assert {
    condition     = output.posture.p5b_log_validation
    error_message = "P5b: the trail must validate log files"
  }
  assert {
    condition     = !contains(output.posture.p6a_admin_cidrs, "0.0.0.0/0") && length(output.posture.p6a_admin_cidrs) > 0
    error_message = "P6a: SSH/RDP must be limited to the VPC"
  }
  assert {
    condition     = output.posture.p6b_default_sg_rules == 0
    error_message = "P6b: the default security group must have no rules"
  }
  assert {
    condition     = output.posture.p7a_rotation
    error_message = "P7a: KMS rotation must be on"
  }
  assert {
    condition     = output.posture.p7b_flow_logs
    error_message = "P7b: the VPC must have a flow log"
  }
  assert {
    condition     = output.posture.trail_bucket_block_public_access
    error_message = "the CloudTrail log bucket must block public access"
  }
}
