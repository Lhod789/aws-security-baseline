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

## 2. S3 public access changes

| | |
|---|---|
| **Fires when** | A bucket's or the account's public access block is changed or deleted, or a bucket policy, ACL or ownership setting is changed — including failed attempts |
| **Why it matters** | Publicly readable buckets are one of the most common causes of cloud data breaches; loosening these settings is the step before exposure |
| **MITRE ATT&CK** | [T1530 — Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/) |
| **Filter pattern** | `{ ($.eventSource = "s3.amazonaws.com") && (($.eventName = "PutBucketPublicAccessBlock") \|\| ($.eventName = "DeleteBucketPublicAccessBlock") \|\| ($.eventName = "PutAccountPublicAccessBlock") \|\| ($.eventName = "DeleteAccountPublicAccessBlock") \|\| ($.eventName = "PutBucketPolicy") \|\| ($.eventName = "DeleteBucketPolicy") \|\| ($.eventName = "PutBucketAcl") \|\| ($.eventName = "PutBucketOwnershipControls") \|\| ($.eventName = "DeleteBucketOwnershipControls")) }` |
| **Known benign triggers** | Legitimate Terraform changes to the log bucket's policy (for example, adding a new log source) |
| **Blind spot** | Object-level actions (reading or uploading individual files) are S3 *data events*, which this trail does not record |
| **Staged break** | Delete the bucket-level public access block, then try to attach a public bucket policy — the account-wide block should refuse it |
| **Restore** | `terraform plan` shows the bucket public access block to be re-created; `terraform apply` |
| **Proven** | 2026-10-18: bucket-level block deleted 16:17:00 UTC, public policy attempted 16:17:16 and **refused by the account-wide block** (`AccessDenied … BlockPublicPolicy`) → alarm 16:20:15 (~3 min, both events counted) → email delivered → restored 16:36:51. The bucket was never public |

## 3. Security group changes

| | |
|---|---|
| **Fires when** | A security group is created or deleted, or any of its inbound or outbound rules are added, removed or modified — including failed attempts |
| **Why it matters** | Opening a security group to `0.0.0.0/0` is one of the most common cloud misconfigurations; SSH open to the world draws automated break-in attempts within minutes. Attackers also open rules on purpose to create a way back in |
| **MITRE ATT&CK** | [T1562.007 — Impair Defenses: Disable or Modify Cloud Firewall](https://attack.mitre.org/techniques/T1562/007/) |
| **Filter pattern** | `{ ($.eventSource = "ec2.amazonaws.com") && (($.eventName = "AuthorizeSecurityGroupIngress") \|\| ($.eventName = "AuthorizeSecurityGroupEgress") \|\| ($.eventName = "RevokeSecurityGroupIngress") \|\| ($.eventName = "RevokeSecurityGroupEgress") \|\| ($.eventName = "ModifySecurityGroupRules") \|\| ($.eventName = "CreateSecurityGroup") \|\| ($.eventName = "DeleteSecurityGroup")) }` |
| **Design choice** | Fires on *any* change, not only "open to the world". Matching `0.0.0.0/0` precisely is fragile (a request can carry several rules and the filter reliably checks only the first), so triage reads `requestParameters` to judge the change. `ModifySecurityGroupRules` is newer than the CIS list and is included deliberately |
| **Known benign triggers** | Legitimate Terraform changes to security groups |
| **Blind spot** | Network ACL changes are a separate control and are not covered here |
| **Staged break** | Add SSH (port 22) from `0.0.0.0/0` to `security-baseline-app` — harmless here because the VPC has no internet gateway |
| **Restore** | **Not by Terraform:** `terraform plan` reported *No changes* with the rule present, because the rules are separate resources and Terraform ignores one added on top. Remove the exact rule by ID: `aws ec2 revoke-security-group-ingress --group-id <sg> --security-group-rule-ids <sgr-id>` |
| **Proven** | 2026-10-18: SSH 22 from `0.0.0.0/0` added 19:14:31 UTC → alarm 19:17:09 (~2.6 min) → email delivered → triage read `requestParameters` (tcp 22, `0.0.0.0/0`) → rule revoked by ID 19:23:28. Open ~9 minutes with nothing reachable (no internet gateway, no network interfaces). **Configuration-as-code is not monitoring: Terraform saw no drift; the detection caught it** |
