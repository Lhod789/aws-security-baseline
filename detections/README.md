# Detections

Each detection is a CloudWatch Logs **metric filter** on the CloudTrail log
group plus a **CloudWatch alarm** that emails the alert channel. They are
defined in [`terraform/detections.tf`](../terraform/detections.tf).

Every detection is proven by a staged break: break the control, receive the
alert, see the drift in `terraform plan`, restore with `terraform apply`.

**Latency:** CloudTrail delivers to CloudWatch Logs in roughly 3–5 minutes and
the alarm evaluates 5-minute windows, so expect an alert 5–15 minutes after the
event. EventBridge rules would be faster; metric filters are what the CIS AWS
Foundations Benchmark specifies.

## 1. CloudTrail tampering

| | |
|---|---|
| **Fires when** | `StopLogging`, `DeleteTrail`, `UpdateTrail`, `PutEventSelectors`, `CreateTrail` or `StartLogging` is called on CloudTrail — including failed attempts |
| **Why it matters** | Stopping or narrowing the audit trail is often an attacker's first move; everything after it is invisible |
| **MITRE ATT&CK** | [T1562.008 — Impair Defenses: Disable or Modify Cloud Logs](https://attack.mitre.org/techniques/T1562/008/) |
| **Filter pattern** | `{ ($.eventSource = "cloudtrail.amazonaws.com") && (($.eventName = "StopLogging") \|\| ($.eventName = "DeleteTrail") \|\| ($.eventName = "UpdateTrail") \|\| ($.eventName = "PutEventSelectors") \|\| ($.eventName = "CreateTrail") \|\| ($.eventName = "StartLogging")) }` |
| **Known benign triggers** | Legitimate Terraform changes to the trail. Intended: any change to the audit trail deserves a human look |
| **Blind spot** | Events that happen *after* logging stops are not recorded but the `StopLogging` call itself is, because logging is still on when it happens |
| **Staged break** | `aws cloudtrail stop-logging --name security-baseline-trail` |
| **Restore** | `terraform plan` shows `enable_logging: false → true`; `terraform apply` |
| **Proven** | 2026-10-12: logging stopped 21:21:46 UTC → alarm 21:23:14 (~1.5 min) → email delivered → restored 21:23:55. Logging was off for 2 min 9 s. The `StopLogging` record shows the IAM user, MFA status, source IP and user agent |
