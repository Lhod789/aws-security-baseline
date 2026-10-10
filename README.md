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
