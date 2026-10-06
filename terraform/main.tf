# A small company's AWS account ("acme"), rebuilt as code: storage, identity, network, keys.
module "keys" {
  source          = "./modules/keys"
  kms_no_rotation = var.kms_no_rotation
}

module "storage" {
  source                    = "./modules/storage"
  s3_public_assets          = var.s3_public_assets
  s3_data_unencrypted       = var.s3_data_unencrypted
  s3_data_no_versioning_tls = var.s3_data_no_versioning_tls
  extra_public_bucket       = var.extra_public_bucket
  kms_key_arn               = module.keys.key_arn
}

module "identity" {
  source                   = "./modules/identity"
  iam_admin_policy         = var.iam_admin_policy
  iam_user_keys_no_mfa     = var.iam_user_keys_no_mfa
  iam_weak_password_policy = var.iam_weak_password_policy
  data_bucket_arn          = module.storage.data_bucket_arn
}

module "network" {
  source           = "./modules/network"
  sg_admin_open    = var.sg_admin_open
  sg_default_open  = var.sg_default_open
  vpc_no_flow_logs = var.vpc_no_flow_logs
}
