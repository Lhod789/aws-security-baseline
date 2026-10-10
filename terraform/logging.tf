locals {
  cloudtrail_log_group_name = "/security-baseline/cloudtrail"

  # Built as a string because the KMS key policy must name the log group
  # before it exists (the log group itself references the key).
  cloudtrail_log_group_arn = "arn:aws:logs:${local.region}:${local.account_id}:log-group:${local.cloudtrail_log_group_name}"
}

# Live, searchable copy of CloudTrail. S3 stays the long-term archive; this is
# what Phase 2 alarms watch. Encrypted with our key, so read access to
# CloudWatch alone is not enough to read the events.
resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = local.cloudtrail_log_group_name
  retention_in_days = 90 # long enough for alarms and recent investigations; S3 keeps the rest
  kms_key_id        = aws_kms_key.cloudtrail.arn
}

# Role CloudTrail assumes to write into the log group. It trusts only the
# CloudTrail service acting for our trail (confused-deputy protection).
data "aws_iam_policy_document" "cloudtrail_to_cloudwatch_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }
}

resource "aws_iam_role" "cloudtrail_to_cloudwatch" {
  name               = "security-baseline-cloudtrail-to-cloudwatch"
  assume_role_policy = data.aws_iam_policy_document.cloudtrail_to_cloudwatch_trust.json
}

# Least privilege: create streams and write events in this one log group.
# No read, no delete, no other log groups.
data "aws_iam_policy_document" "cloudtrail_to_cloudwatch" {
  statement {
    sid       = "WriteCloudTrailEvents"
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.cloudtrail.arn}:log-stream:*"]
  }
}

resource "aws_iam_role_policy" "cloudtrail_to_cloudwatch" {
  name   = "write-cloudtrail-log-group"
  role   = aws_iam_role.cloudtrail_to_cloudwatch.id
  policy = data.aws_iam_policy_document.cloudtrail_to_cloudwatch.json
}

output "cloudtrail_log_group_name" {
  value = aws_cloudwatch_log_group.cloudtrail.name
}
