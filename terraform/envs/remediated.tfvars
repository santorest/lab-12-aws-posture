# Remediated posture: every planted switch false (see variables.tf).
s3_public_assets          = false
s3_data_unencrypted       = false
s3_data_no_versioning_tls = false
iam_admin_policy          = false
iam_user_keys_no_mfa      = false
iam_weak_password_policy  = false
sg_admin_open             = false
sg_default_open           = false
kms_no_rotation           = false
vpc_no_flow_logs          = false
