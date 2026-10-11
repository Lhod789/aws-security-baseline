locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.region
  trail_name = "security-baseline-trail"

  # Built as a string (not read from the trail resource) because the KMS key
  # policy and bucket policy must name the trail before the trail exists.
  trail_arn = "arn:aws:cloudtrail:${local.region}:${local.account_id}:trail/${local.trail_name}"
}

# Customer-managed key for CloudTrail logs. Being allowed to read the bucket
# is no longer enough to read the logs: the reader also needs kms:Decrypt,
# which only principals granted it in IAM have.
resource "aws_kms_key" "cloudtrail" {
  description             = "Encrypts security baseline logs and alerts (CloudTrail files, CloudWatch log group, SNS alert topic)"
  enable_key_rotation     = true
  deletion_window_in_days = 30 # longest window: maximum time to notice and cancel a deletion
  policy                  = data.aws_iam_policy_document.cloudtrail_kms.json
}

resource "aws_kms_alias" "cloudtrail" {
  name          = "alias/security-baseline-cloudtrail"
  target_key_id = aws_kms_key.cloudtrail.key_id
}

data "aws_iam_policy_document" "cloudtrail_kms" {
  # Lets IAM policies in this account grant use of the key. Without this the
  # key could become unmanageable (locked out).
  statement {
    sid       = "EnableIAMPolicies"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.account_id}:root"]
    }
  }

  # CloudTrail may encrypt, but only for this account's trails and only when
  # acting for this specific trail (prevents a confused-deputy misuse).
  statement {
    sid       = "AllowCloudTrailEncrypt"
    effect    = "Allow"
    actions   = ["kms:GenerateDataKey*"]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }

    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values   = ["arn:aws:cloudtrail:*:${local.account_id}:trail/*"]
    }
  }

  statement {
    sid       = "AllowCloudTrailDescribeKey"
    effect    = "Allow"
    actions   = ["kms:DescribeKey"]
    resources = ["*"]

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

  # CloudWatch Logs may use the key, but only for our CloudTrail log group.
  statement {
    sid    = "AllowCloudWatchLogsForTrailLogGroup"
    effect = "Allow"
    actions = [
      "kms:Encrypt*",
      "kms:Decrypt*",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:Describe*",
    ]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["logs.${local.region}.amazonaws.com"]
    }

    condition {
      test     = "ArnEquals"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = [local.cloudtrail_log_group_arn]
    }
  }

  # CloudWatch alarms publish to the encrypted SNS alert topic, which needs
  # the key; limited to alarms in this account.
  statement {
    sid       = "AllowCloudWatchAlarmsForEncryptedAlerts"
    effect    = "Allow"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey*"]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  # Deliberately no "any principal in the account may decrypt" statement
  # (the console default). Reading logs requires an explicit IAM grant.
}

# Records every management API call in the account, in every region.
resource "aws_cloudtrail" "main" {
  name           = local.trail_name
  s3_bucket_name = aws_s3_bucket.logs.id
  s3_key_prefix  = "cloudtrail"

  # Attackers like regions nobody watches; record them all.
  is_multi_region_trail = true

  # IAM and STS are global services; without this, identity changes go unrecorded.
  include_global_service_events = true

  # Signed hourly digest files prove whether log files were altered or deleted.
  enable_log_file_validation = true

  kms_key_id = aws_kms_key.cloudtrail.arn

  # Live feed into CloudWatch Logs (see logging.tf). CloudTrail requires the
  # ":*" suffix on the log group ARN.
  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_to_cloudwatch.arn

  # CloudTrail checks it can write to the bucket, and to the log group via the
  # role, so both permissions must exist first.
  depends_on = [
    aws_s3_bucket_policy.logs,
    aws_iam_role_policy.cloudtrail_to_cloudwatch,
  ]
}

output "cloudtrail_name" {
  value = aws_cloudtrail.main.name
}

output "cloudtrail_kms_key_alias" {
  value = aws_kms_alias.cloudtrail.name
}
