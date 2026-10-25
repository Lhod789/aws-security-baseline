# Incident runbook

What to do when a security alert email arrives. There is one card per
detection in [`detections/README.md`](detections/README.md), and every card
follows the same five steps: **detect → triage → contain → restore → verify**.

Each card comes from an incident that was actually staged in this account.
The "From the staged incident" notes record what that run taught.

## Every alarm: first ten minutes

1. **Sign in.** Run `aws login` (as `admin`, with MFA).
2. **Note the time.** The email's *Timestamp* is when the alarm fired. The
   event itself usually happened 2-5 minutes earlier.
3. **Pull the matching events** from the live CloudWatch feed. Use the
   detection's filter pattern from `detections/README.md`:

   ```bash
   aws logs filter-log-events --log-group-name /security-baseline/cloudtrail \
     --start-time $(( ($(date +%s) - 3600) * 1000 )) \
     --filter-pattern '<the detection pattern>' \
     --query 'events[].message' --output text
   ```

4. **Answer six questions for each event:**

   | Question | Field |
   |---|---|
   | Who? | `userIdentity.type`, `userIdentity.userName` |
   | How? | `userAgent`: `aws-cli…`, `…Terraform…`, or `Mozilla/…` (the console) |
   | From where? | `sourceIPAddress`, compared with the addresses you normally use |
   | With MFA? | `userIdentity.sessionContext.attributes.mfaAuthenticated`; for sign-ins, `additionalEventData.MFAUsed` |
   | Did it work? | `errorCode` present means it failed. A *failed* attempt is still a signal |
   | What exactly? | `requestParameters`: the ports, addresses, policy text or settings requested |

5. **Look for follow-on events.** An alarm stays in ALARM for about 15 minutes
   and does not email again while it is in that state, so one email can hide
   several actions. Search everything the same identity did in the window:
   `--filter-pattern '{ $.userIdentity.userName = "<name>" }'`.
6. **Rule out the known benign triggers.** A Terraform apply (user agent
   contains `Terraform`) or planned break-glass use. If a person did it, ask
   them, then check what they say against the logs.
7. **Decide.** Authorised and explained: record it and close. Anything else:
   treat the identity as compromised and contain.

### Triage pitfalls

- **Trust `eventTime`, not the CloudWatch timestamp.** CloudWatch files events
  by when they *arrived*, a few minutes after they happened.
- **Event history lags** 5 to 15 minutes. If an event isn't there yet, wait
  rather than conclude it didn't happen.
- **Check the right region.** IAM events are recorded in `us-east-1`. A root
  console sign-in was recorded in `us-west-2`. The all-region trail delivers
  all of them to the London log group, but the console's Event history shows
  one region at a time.
- **Not every `AccessDenied` is an attack.** The console regularly probes
  services that aren't set up (for example IAM Identity Center) and gets
  refused. Check who, how and with MFA before raising it.
- **The logs cannot tell a person from an automation that uses their session.**
  An AI agent using your `aws login` session appears as you, with your MFA and
  your IP address.

### Containing a compromised identity

- **IAM user (not the only admin):** stop it doing anything, then remove its
  credentials.

  ```bash
  aws iam put-user-policy --user-name <user> --policy-name quarantine \
    --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'
  aws iam delete-login-profile --user-name <user>
  aws iam list-access-keys --user-name <user>
  aws iam update-access-key --user-name <user> --access-key-id <key-id> --status Inactive
  ```

- **If the compromised identity is `admin` itself:** quarantining it from
  `admin` locks you out. Sign in as **root** (break-glass, with MFA) to
  contain, then change `admin`'s password and MFA device.
- **Root:** change the root password, replace the root MFA device, look for
  anything root created (users, access keys, roles), and contact AWS Support.

## Severity at a glance

| Detection | Default severity | First containment step |
|---|---|---|
| 1. CloudTrail tampering | High | turn logging back on |
| 2. S3 public access | High if the bucket is public, otherwise Medium | re-apply the public access block |
| 3. Security group changes | High for admin ports open to `0.0.0.0/0`, otherwise Low | revoke the exact rule by ID |
| 4. Sign-in weakening | High | restore the policy, re-add the user to `mfa-required` |
| 5. KMS key tampering | Critical | cancel deletion and re-enable the key |
| 6. Root usage | High unless planned | confirm with the account owner |

---

## 1. CloudTrail tampering

**Detect:** `security-baseline-cloudtrail-tampering`. Someone called
`StopLogging`, `DeleteTrail`, `UpdateTrail`, `PutEventSelectors`,
`CreateTrail` or `StartLogging`.

**Triage**
- Is the trail still logging? `aws cloudtrail get-trail-status --name security-baseline-trail`
  (`IsLogging`, `LatestDeliveryError`).
- Which call was it, and was it Terraform?

**Contain:** turn logging back on before anything else. Every minute off is a
minute not recorded by the trail.

**Restore:** `terraform plan` shows the drift (for example
`enable_logging: false -> true`), then `terraform apply`. If the trail was
deleted, the apply re-creates it.

**Verify**
- `IsLogging: True` with no delivery errors, and `terraform plan` shows no
  changes.
- **Recover the gap:** CloudTrail **Event history** keeps management events
  for 90 days independently of any trail, so it still holds what happened
  while the trail was off.

*From the staged incident:*  CloudTrail recorded the command `StopLogging` that switched it off, because it was still on when that command ran.

## 2. S3 public access changes

**Detect:** `security-baseline-s3-public-access`. A public access block
(bucket or account), bucket policy, ACL or ownership setting changed, or an
attempt to change one failed.

**Triage**
- Is the bucket public right now?
  `aws s3api get-bucket-policy-status --bucket <bucket>` (`IsPublic`).
- Are both locks on?
  `aws s3api get-public-access-block --bucket <bucket>` and
  `aws s3control get-public-access-block --account-id <account>`.
- For `PutBucketPolicy`, read the policy in `requestParameters`: look for
  `"Principal": "*"`.

**Contain:** if `IsPublic` is true, close it **first** (re-apply the block)
and investigate second.

**Restore:** `terraform apply` re-creates a removed block and resets the
policy.

**Verify:** `IsPublic: False`, both blocks all `true`, and `terraform plan`
shows no changes.
- **Honest limit:** reading individual files is an S3 *data event*, which this
  trail does not record. If the bucket really was public, you cannot prove
  from these logs whether anything was read. To close this gap, turn on S3 data events for the log bucket in CloudTrail or turn on S3 server access logs. (extra cost)

*From the staged incident:* the bucket-level block was removed, and
then a public policy was attempted. The **account-wide block refused it**. The
alert counted both events, including the failed one.

## 3. Security group changes

**Detect:** `security-baseline-security-group-changes`. A rule was added,
removed or modified, or a security group was created or deleted.

**Triage**
- Read `requestParameters.ipPermissions`: which ports, and from where?
High severity: remote-login ports (22 SSH, 3389 RDP) open to everyone (0.0.0.0/0 or ::/0).
- What is behind the door?
  `aws ec2 describe-network-interfaces --filters Name=group-id,Values=<sg>`,
  and whether the VPC has an internet gateway.

**Contain:** remove the exact rule by its ID.

```bash
aws ec2 describe-security-group-rules --filters Name=group-id,Values=<sg>
aws ec2 revoke-security-group-ingress --group-id <sg> --security-group-rule-ids <sgr-id>
```

**Restore:** **not with Terraform.** The rules are separate Terraform
resources, so Terraform only checks the rules it created and reports *No
changes* when someone adds one on top. Removing the rule is the restore. 

**Verify**
- Only the intended rules remain.
- **Check the doorman's clipboard** (VPC flow logs) for connections through
  the opened port during the window. Flow logs are in the log bucket under
  `vpc-flow-logs/`. In the default format, field 7 is the destination port and
  field 13 is `ACCEPT` or `REJECT`.

*From the staged incident:* SSH was open to the world for about 9
minutes, and the alert came in about 2.6 minutes. `terraform plan` said *No
changes* the whole time, and the detection is what caught it. 

## 4. Sign-in weakening

**Detect:** `security-baseline-auth-weakening`. MFA was deactivated or
deleted, the password policy was changed or deleted, a user was removed from a
group, or a group policy was detached or rewritten.

**Triage**
- Password policy: compare `requestParameters` with the baseline (min length
  14, reuse 24, no expiry).
- `RemoveUserFromGroup`: was the group `mfa-required`? If so, that user is no
  longer forced to use MFA.
- `CreatePolicyVersion` or `SetDefaultPolicyVersion`: was it the
  `security-baseline-mfa-required` policy?

**Contain:** if a user was quietly taken out of MFA enforcement, treat that
user as compromised (see *Containing a compromised identity*).

**Restore:** `terraform apply` restores the password policy, the MFA policy
and `admin`'s membership. A deactivated MFA device must be re-enrolled by its
owner.

**Verify:** `aws iam get-account-password-policy`,
`aws iam list-groups-for-user --user-name <user>`, and `terraform plan` shows
no changes.

*From the staged incident:* the minimum length was lowered to 8,
the alert came in about 2.4 minutes, and Terraform caught the drift. In the
real no-MFA sign-in test, the **first run passed when it shouldn't have**,
because the test user had never been added to the mfa-required group. **Check a test's
preconditions before trusting its result.** 

## 5. KMS key tampering

**Detect:** `security-baseline-kms-key-tampering`. The key was disabled,
scheduled for deletion, had rotation switched off, or had its policy changed.

**Triage**
- A **refused** `DisableKey` or `ScheduleKeyDeletion` (`errorCode:
  AccessDenied`) means someone with admin credentials tried to destroy the
  key. Treat it as a compromise even though it failed.
- `PutKeyPolicy`: is `DenyKeyDisableOrDeletionExceptRoot` still in the policy?
  Removing it is the first step of a two-step attack.

```bash
aws kms describe-key --key-id alias/security-baseline-cloudtrail --query KeyMetadata.KeyState
aws kms get-key-policy --key-id <key-id> --policy-name default
```

**Contain**
- Key pending deletion: `aws kms cancel-key-deletion --key-id <key-id>`, then
  `aws kms enable-key --key-id <key-id>`.
- Key disabled: `aws kms enable-key --key-id <key-id>`.

**Restore:** `terraform apply` restores rotation and the key policy, including
the deny.

**Verify:** key `Enabled`, rotation on, the policy has all six statements,
CloudTrail has no delivery errors, and `terraform plan` shows no changes.
- **Know the blind spot:** this key also encrypts the log group and the alert
  topic. If an attack ever *succeeded* in disabling it, this alert might never
  arrive. A trail delivery error that mentions KMS is then the sign to look
  for.

*From the staged incident:* rotation was switched off in the console, alert in about 3 minutes, restored by
Terraform. A deletion attempt was **refused by the key policy**, and the
refused attempt was still alerted, because the key and the alerting kept
working.

## 6. Root usage

**Detect:** `security-baseline-root-usage`. Any action as root, including a
console sign-in.

**Triage**
- Find the sign-in. It may be recorded outside London (it was in `us-west-2`):
  filter the feed with `{ $.userIdentity.type = "Root" }` rather than relying
  on one region's Event history.
- Check `MFAUsed`, the source IP address, and **everything root did**: any
  write actions?
- Ask the account owner whether it was them.

**Contain (if it wasn't planned):** see *Containing a compromised identity*,
under Root.

**Restore:** undo whatever root changed. `terraform plan` shows drift for
anything Terraform manages.

**Verify:** no further root events, and `terraform plan` shows no changes.

*From the staged incident:* one sign-in with MFA produced 22 root
actions in five minutes, because the console makes many calls per page. The
alert came in about 3 minutes. All actions were reads, and the owner
confirmed both sign-ins.

## After every incident

- Write a short timeline in UTC: event, alert, containment, restore.
- Confirm every alarm is back to `OK`:
  `aws cloudwatch describe-alarms --alarm-name-prefix security-baseline- --query 'MetricAlarms[].[AlarmName,StateValue]' --output table`
- Confirm there is no drift: `terraform plan -detailed-exitcode` (exit code 0).
- Record what the incident taught, and update this runbook.
