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
