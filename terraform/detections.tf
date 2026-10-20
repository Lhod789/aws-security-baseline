# Detections: each one is a metric filter (a counter that clicks +1 when a
# matching CloudTrail event reaches the CloudWatch log group) plus an alarm
# (if the counter clicks at least once in 5 minutes, publish to the alert
# topic). Every detection has the same shape, so they are defined as data
# here and created in a loop. Full write-ups live in detections/README.md.
locals {
  detections = {
    cloudtrail-tampering = {
      metric_name = "CloudTrailTampering"
      description = "CloudTrail stopped, deleted or reconfigured (ATT&CK T1562.008 Disable or Modify Cloud Logs). Includes failed attempts. See detections/README.md."
      pattern     = "{ ($.eventSource = \"cloudtrail.amazonaws.com\") && (($.eventName = \"StopLogging\") || ($.eventName = \"DeleteTrail\") || ($.eventName = \"UpdateTrail\") || ($.eventName = \"PutEventSelectors\") || ($.eventName = \"CreateTrail\") || ($.eventName = \"StartLogging\")) }"
    }

    # Account-level and bucket-level public access block changes are both
    # recorded under s3.amazonaws.com (checked in Event history).
    s3-public-access = {
      metric_name = "S3PublicAccessChange"
      description = "S3 public access block, bucket policy, ACL or ownership controls changed, at bucket or account level (ATT&CK T1530 Data from Cloud Storage). Includes failed attempts. See detections/README.md."
      pattern     = "{ ($.eventSource = \"s3.amazonaws.com\") && (($.eventName = \"PutBucketPublicAccessBlock\") || ($.eventName = \"DeleteBucketPublicAccessBlock\") || ($.eventName = \"PutAccountPublicAccessBlock\") || ($.eventName = \"DeleteAccountPublicAccessBlock\") || ($.eventName = \"PutBucketPolicy\") || ($.eventName = \"DeleteBucketPolicy\") || ($.eventName = \"PutBucketAcl\") || ($.eventName = \"PutBucketOwnershipControls\") || ($.eventName = \"DeleteBucketOwnershipControls\")) }"
    }

    # Any security group change, not only "open to the world": a precise
    # 0.0.0.0/0 match only reliably checks the first rule in a request, so the
    # broad match is safer and triage reads requestParameters instead.
    # ModifySecurityGroupRules (editing an existing rule) is newer than the CIS
    # list and is included deliberately.
    security-group-changes = {
      metric_name = "SecurityGroupChange"
      description = "Security group created, deleted or its rules changed (ATT&CK T1562.007 Disable or Modify Cloud Firewall). Includes failed attempts. Triage: read requestParameters for 0.0.0.0/0 or ::/0. See detections/README.md."
      pattern     = "{ ($.eventSource = \"ec2.amazonaws.com\") && (($.eventName = \"AuthorizeSecurityGroupIngress\") || ($.eventName = \"AuthorizeSecurityGroupEgress\") || ($.eventName = \"RevokeSecurityGroupIngress\") || ($.eventName = \"RevokeSecurityGroupEgress\") || ($.eventName = \"ModifySecurityGroupRules\") || ($.eventName = \"CreateSecurityGroup\") || ($.eventName = \"DeleteSecurityGroup\")) }"
    }

    # Weakening sign-in: MFA removed, password policy relaxed, a user taken out
    # of mfa-required, or the MFA policy detached or rewritten. IAM is global
    # (recorded in us-east-1); the all-region trail still delivers it here.
    auth-weakening = {
      metric_name = "AuthWeakening"
      description = "MFA deactivated or deleted, password policy changed or deleted, user removed from a group, or a group policy detached or rewritten (ATT&CK T1556 Modify Authentication Process). Includes failed attempts. See detections/README.md."
      pattern     = "{ ($.eventSource = \"iam.amazonaws.com\") && (($.eventName = \"DeactivateMFADevice\") || ($.eventName = \"DeleteVirtualMFADevice\") || ($.eventName = \"UpdateAccountPasswordPolicy\") || ($.eventName = \"DeleteAccountPasswordPolicy\") || ($.eventName = \"RemoveUserFromGroup\") || ($.eventName = \"DetachGroupPolicy\") || ($.eventName = \"CreatePolicyVersion\") || ($.eventName = \"SetDefaultPolicyVersion\")) }"
    }
  }
}

resource "aws_cloudwatch_log_metric_filter" "detection" {
  for_each = local.detections

  name           = "security-baseline-${each.key}"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = each.value.pattern

  metric_transformation {
    name      = each.value.metric_name
    namespace = "SecurityBaseline"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "detection" {
  for_each = local.detections

  alarm_name        = "security-baseline-${each.key}"
  alarm_description = each.value.description

  namespace   = "SecurityBaseline"
  metric_name = each.value.metric_name
  statistic   = "Sum"
  period      = 300
  threshold   = 1

  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1

  # No matching events means "all quiet", not "unknown".
  treat_missing_data = "notBreaching"

  alarm_actions = [aws_sns_topic.alerts.arn]

  # The filter must exist before the alarm watches its metric.
  depends_on = [aws_cloudwatch_log_metric_filter.detection]
}
