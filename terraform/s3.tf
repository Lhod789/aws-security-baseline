data "aws_region" "current" {}

locals {
  # Bucket names are global across all AWS customers. Including the account ID
  # and region makes the name unique to us, so nobody can claim it first.
  log_bucket_name = "security-baseline-logs-${data.aws_caller_identity.current.account_id}-${data.aws_region.current.region}"
}

# Account-wide guardrail: no bucket in this account can be made public,
# even if someone later weakens a single bucket's own settings.
resource "aws_s3_account_public_access_block" "this" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Central store for security logs (CloudTrail, flow logs). Attackers try to
# delete or read logs to cover their tracks, so this bucket is hardened first.
resource "aws_s3_bucket" "logs" {
  bucket = local.log_bucket_name
}

# Bucket-level public access block: second layer behind the account-wide one.
resource "aws_s3_bucket_public_access_block" "logs" {
  bucket = aws_s3_bucket.logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Disable ACLs entirely; access is controlled only by policies.
# Stops object-level ACLs quietly granting access to other accounts.
resource "aws_s3_bucket_ownership_controls" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# Keep every previous version, so a deleted or overwritten log can be recovered.
resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Encryption at rest with S3-managed keys (SSE-S3). Protects the stored data
# at the storage layer; it does NOT stop an IAM principal who is allowed to
# read the bucket. Customer-managed KMS keys are considered with CloudTrail.
resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Refuse any request that does not use TLS, so logs are never sent in clear text.
data "aws_iam_policy_document" "logs_bucket" {
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]

    resources = [
      aws_s3_bucket.logs.arn,
      "${aws_s3_bucket.logs.arn}/*",
    ]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  # CloudTrail checks the bucket's ACL before delivering, but only on behalf
  # of our own trail.
  statement {
    sid       = "AllowCloudTrailAclCheck"
    effect    = "Allow"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.logs.arn]

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

  # Only our trail may write, and only under its own prefix for this account.
  # The SourceArn condition stops another account's trail using this bucket.
  statement {
    sid       = "AllowCloudTrailWrite"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.logs.arn}/cloudtrail/AWSLogs/${local.account_id}/*"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }
}

resource "aws_s3_bucket_policy" "logs" {
  bucket = aws_s3_bucket.logs.id
  policy = data.aws_iam_policy_document.logs_bucket.json

  # The public access block must exist first, so the policy is never
  # evaluated against an unprotected bucket.
  depends_on = [aws_s3_bucket_public_access_block.logs]
}

output "log_bucket_name" {
  value = aws_s3_bucket.logs.bucket
}
