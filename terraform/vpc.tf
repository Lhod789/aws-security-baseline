locals {
  vpc_cidr = "10.20.0.0/16"
}

# Private network. There is deliberately no internet gateway: nothing in this
# VPC can reach, or be reached from, the internet unless one is added on purpose.
resource "aws_vpc" "main" {
  cidr_block           = local.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "security-baseline"
  }
}

# One private subnet. Resources launched here never get a public IP by default.
resource "aws_subnet" "private" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.20.1.0/24"
  availability_zone       = "${local.region}a"
  map_public_ip_on_launch = false

  tags = {
    Name = "security-baseline-private"
  }
}

# Every VPC comes with a default security group that lets everything attached
# to it talk to everything else, and resources land on it when nobody picks a
# group. Adopting it here with no rules strips all of them (CIS benchmark).
resource "aws_default_security_group" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "security-baseline-default-locked"
  }
}

# Example application security group: HTTPS only, and only from inside the
# VPC. There is no SSH rule at all; if instances are ever added, they are
# managed through Session Manager (no open port, no keys, every session logged).
resource "aws_security_group" "app" {
  name        = "security-baseline-app"
  description = "HTTPS from inside the VPC only; no SSH"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "security-baseline-app"
  }
}

resource "aws_vpc_security_group_ingress_rule" "app_https_from_vpc" {
  security_group_id = aws_security_group.app.id
  description       = "HTTPS from inside the VPC"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = local.vpc_cidr
}

# Egress is restricted too (no default allow-all): outbound HTTPS to the VPC
# only, for example to future VPC endpoints. Limits where data can be sent.
resource "aws_vpc_security_group_egress_rule" "app_https_to_vpc" {
  security_group_id = aws_security_group.app.id
  description       = "HTTPS to inside the VPC"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = local.vpc_cidr
}

# Flow logs: a record of every connection attempt (source, destination, port,
# accepted or rejected), not the content. Evidence for scanning and data
# leaving the network. Delivered to the log bucket under vpc-flow-logs/.
resource "aws_flow_log" "vpc" {
  vpc_id               = aws_vpc.main.id
  traffic_type         = "ALL" # accepted and rejected
  log_destination_type = "s3"
  log_destination      = "${aws_s3_bucket.logs.arn}/vpc-flow-logs/"

  # The bucket policy must allow log delivery first, otherwise AWS tries to
  # rewrite the policy itself and it drifts from Terraform.
  depends_on = [aws_s3_bucket_policy.logs]

  tags = {
    Name = "security-baseline-vpc-flow-logs"
  }
}

output "vpc_id" {
  value = aws_vpc.main.id
}
