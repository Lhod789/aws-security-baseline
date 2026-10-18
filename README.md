# aws-security-baseline

A hardened AWS account baseline in Terraform: deploy it, break it on purpose, detect the break, restore it.

*Work in progress.*

## Controls

Each control states the attack it exists to stop.

| Control | Attack it stops | File |
|---|---|---|
| S3 log bucket: private (account-wide and bucket-level public access block), ACLs disabled, versioned, encrypted at rest, HTTPS-only | Attackers deleting or reading logs to cover their tracks; accidental public exposure of log data | [`terraform/s3.tf`](terraform/s3.tf) |
| CloudTrail: all regions, global service events, log file validation, encrypted with a customer-managed KMS key, bucket writable only by this trail | Unrecorded activity in unwatched regions; untracked identity changes; tampering with logs; anyone with bucket access reading logs | [`terraform/cloudtrail.tf`](terraform/cloudtrail.tf) |
| CloudWatch Logs: live CloudTrail feed, 90-day retention, encrypted with the customer-managed KMS key; CloudTrail writes through a write-only role scoped to one log group | Attacks going unnoticed because logs aren't searchable or can't trigger alarms; anyone who can read CloudWatch reading the events | [`terraform/logging.tf`](terraform/logging.tf) |
| IAM: password policy (14+ characters, no reuse of last 24, no forced expiry, per CIS and NIST); MFA required for all actions via the `mfa-required` group | Phished or leaked passwords used without a second factor; weak or recycled passwords; removing a user's MFA to weaken them | [`terraform/iam.tf`](terraform/iam.tf) |
| VPC: private network with no internet gateway, no public IPs, default security group stripped of all rules, app security group allowing HTTPS within the VPC only (no SSH), flow logs for all traffic | Internet exposure; remote-login brute force; lateral movement through the default security group; unnoticed scanning or data leaving the network | [`terraform/vpc.tf`](terraform/vpc.tf) |
| Alert channel: SNS topic encrypted with the KMS key; only this account's CloudWatch alarms may publish; TLS only; email subscription (address kept out of the repo) | Detections that fire but nobody hears; outsiders injecting fake alerts; alert contents exposed | [`terraform/alerting.tf`](terraform/alerting.tf) |

## Detections

Each detection is proven by a staged break: break the control, receive the alert, see the drift, restore with Terraform. Full write-ups: [`detections/README.md`](detections/README.md).

| Detection | MITRE ATT&CK | Proven |
|---|---|---|
| CloudTrail tampering: logging stopped, trail deleted, reconfigured or narrowed | T1562.008 | ✅ alert ~1.5 min after `StopLogging`; restored by `terraform apply` |
| S3 public access changes: bucket or account public-access block, bucket policy, ACL or ownership changed (failed attempts included) | T1530 | ✅ alert ~3 min after the bucket block was removed; the follow-up public-policy attempt was refused by the account-wide block; restored by `terraform apply` |
| Security group changes: rules added, removed or modified; groups created or deleted (failed attempts included) | T1562.007 | ✅ alert ~2.6 min after SSH was opened to `0.0.0.0/0`; **Terraform saw no drift**, so the rule was removed by ID; the detection is what caught it |
