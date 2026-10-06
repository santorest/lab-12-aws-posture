terraform {
  required_version = ">= 1.16.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = ">= 6.0" }
  }
}

variable "sg_admin_open" {
  description = "P6a"
  type        = bool
}
variable "sg_default_open" {
  description = "P6b"
  type        = bool
}
variable "vpc_no_flow_logs" {
  description = "P7b"
  type        = bool
}

locals {
  vpc_cidr    = "10.0.0.0/16"
  admin_cidrs = var.sg_admin_open ? ["0.0.0.0/0"] : [local.vpc_cidr]
  # Rules of the default security group, written as attributes: an explicit empty list removes every rule,
  # while empty dynamic blocks would only mean "not specified" and leave the old rules in place.
  rule = { description = null, from_port = 0, to_port = 0, protocol = "-1", self = false, cidr_blocks = [],
  ipv6_cidr_blocks = [], prefix_list_ids = [], security_groups = [] }
  default_ingress = var.sg_default_open ? [merge(local.rule, { self = true })] : []
  default_egress  = var.sg_default_open ? [merge(local.rule, { cidr_blocks = ["0.0.0.0/0"] })] : []
}

data "aws_caller_identity" "current" {}

resource "aws_vpc" "this" {
  cidr_block = local.vpc_cidr
  tags       = { Name = "acme-vpc" }
}

# P6a — administration ports: from anywhere, or only from inside the VPC
resource "aws_security_group" "legacy_admin" {
  name        = "acme-legacy-admin"
  description = "Administration access (SSH, RDP)"
  vpc_id      = aws_vpc.this.id
  dynamic "ingress" {
    for_each = [22, 3389]
    content {
      description = "admin port ${ingress.value}"
      from_port   = ingress.value
      to_port     = ingress.value
      protocol    = "tcp"
      cidr_blocks = local.admin_cidrs
    }
  }
  tags = { Name = "acme-legacy-admin" }
}

# P6b — the default security group: allows traffic, or has no rules at all
resource "aws_default_security_group" "this" {
  vpc_id  = aws_vpc.this.id
  tags    = { Name = "acme-default-sg" }
  ingress = local.default_ingress
  egress  = local.default_egress
}

# P7b — VPC flow logs to CloudWatch Logs
resource "aws_cloudwatch_log_group" "flow" {
  count             = var.vpc_no_flow_logs ? 0 : 1
  name              = "acme-vpc-flow"
  retention_in_days = 365
}

resource "aws_iam_role" "flow" {
  count = var.vpc_no_flow_logs ? 0 : 1
  name  = "acme-vpc-flow-logs"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
      Action    = "sts:AssumeRole"
      # only flow logs of this account may use the role (confused deputy)
      Condition = {
        StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
        ArnLike      = { "aws:SourceArn" = "arn:aws:ec2:*:${data.aws_caller_identity.current.account_id}:vpc-flow-log/*" }
      }
    }]
  })
}

resource "aws_iam_role_policy" "flow" {
  count = var.vpc_no_flow_logs ? 0 : 1
  name  = "write-flow-logs"
  role  = aws_iam_role.flow[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"]
      Resource = "${aws_cloudwatch_log_group.flow[0].arn}:*"
    }]
  })
}

resource "aws_flow_log" "this" {
  count           = var.vpc_no_flow_logs ? 0 : 1
  vpc_id          = aws_vpc.this.id
  traffic_type    = "ALL"
  log_destination = aws_cloudwatch_log_group.flow[0].arn
  iam_role_arn    = aws_iam_role.flow[0].arn
}

output "names" {
  description = "Name tags of the planted network resources"
  value = [
    aws_security_group.legacy_admin.tags["Name"],
    aws_default_security_group.this.tags["Name"],
    aws_vpc.this.tags["Name"],
  ]
}

output "posture" {
  description = "Planted parts in this module"
  value = {
    p6a_admin_cidrs      = local.admin_cidrs
    p6b_default_sg_rules = length(local.default_ingress) + length(local.default_egress)
    p7b_flow_logs        = length(aws_flow_log.this) > 0
  }
}
