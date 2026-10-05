# Vulnerable posture: every planted switch true (see variables.tf).
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
