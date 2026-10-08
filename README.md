# aws-security-baseline

A hardened AWS account baseline in Terraform: deploy it, break it on purpose, detect the break, restore it.

*Work in progress.*

## Controls

Each control states the attack it exists to stop.

| Control | Attack it stops | File |
|---|---|---|
| S3 log bucket: private (account-wide and bucket-level public access block), ACLs disabled, versioned, encrypted at rest, HTTPS-only | Attackers deleting or reading logs to cover their tracks; accidental public exposure of log data | [`terraform/s3.tf`](terraform/s3.tf) |
