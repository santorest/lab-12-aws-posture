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
  # rules of the default security group; none when fixed
  default_ingress = var.sg_default_open ? [{ protocol = "-1", self = true }] : []
  default_egress  = var.sg_default_open ? [{ protocol = "-1", cidr = "0.0.0.0/0" }] : []
}

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
  vpc_id = aws_vpc.this.id
  dynamic "ingress" {
    for_each = local.default_ingress
    content {
      from_port = 0
      to_port   = 0
      protocol  = ingress.value.protocol
      self      = ingress.value.self
    }
  }
  dynamic "egress" {
    for_each = local.default_egress
    content {
      from_port   = 0
      to_port     = 0
      protocol    = egress.value.protocol
      cidr_blocks = [egress.value.cidr]
    }
  }
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
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "vpc-flow-logs.amazonaws.com" }, Action = "sts:AssumeRole" }]
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

output "posture" {
  description = "Planted parts in this module"
  value = {
    p6a_admin_cidrs      = local.admin_cidrs
    p6b_default_sg_rules = length(local.default_ingress) + length(local.default_egress)
    p7b_flow_logs        = length(aws_flow_log.this) > 0
  }
}
