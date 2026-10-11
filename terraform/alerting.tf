# The guard's phone: every detection alarm publishes here, and SNS emails it
# on. Encrypted with our KMS key, so alert contents are protected at rest.
resource "aws_sns_topic" "alerts" {
  name              = "security-baseline-alerts"
  kms_master_key_id = aws_kms_key.cloudtrail.arn
}

data "aws_iam_policy_document" "alerts_topic" {
  # Only CloudWatch alarms in this account may publish (confused-deputy guard).
  statement {
    sid       = "AllowCloudWatchAlarmsToPublish"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]

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

  # Refuse publishing that does not use TLS. Topic policies accept only
  # topic-level actions, so "sns:*" is rejected ("action out of service scope").
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]

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
}

resource "aws_sns_topic_policy" "alerts" {
  arn    = aws_sns_topic.alerts.arn
  policy = data.aws_iam_policy_document.alerts_topic.json
}

# Email subscription. AWS sends a confirmation email; nothing is delivered
# until a human clicks the link in it.
resource "aws_sns_topic_subscription" "alerts_email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

output "alerts_topic_name" {
  value = aws_sns_topic.alerts.name
}
