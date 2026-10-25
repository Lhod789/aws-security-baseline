# Architecture

Two views of the same system: what is built and how a break is caught and
fixed.

## 1. What is built

Every API call in every region is recorded once, kept twice (an archive in S3
and a live, searchable copy in CloudWatch), watched by six tripwires, and
alerted by email. One KMS key locks the logs, the live copy and the alerts, and
only root may disable or delete it.

```mermaid
flowchart TB
  subgraph people["People and tooling"]
    admin["admin IAM user<br/>MFA, aws login<br/>no access keys"]
    root["Root user<br/>MFA, break-glass only"]
    tf["Terraform<br/>builds and restores"]
  end

  subgraph account["AWS account: every region recorded, home region eu-west-2"]
    api["API calls in every region"]

    subgraph logging["Logging"]
      trail["CloudTrail<br/>all regions, global events,<br/>log file validation"]
      bucket["S3 log bucket<br/>private, versioned,<br/>encrypted, TLS only"]
      cwl["CloudWatch log group<br/>live feed, 90 days"]
    end

    subgraph detection["Detection"]
      filters["6 metric filters<br/>the tripwires"]
      alarms["6 CloudWatch alarms"]
      sns["SNS alert topic<br/>only these alarms may publish"]
    end

    kms["KMS key<br/>rotation on<br/>only root may disable or delete it"]

    subgraph identity["Sign-in rules"]
      pw["Password policy<br/>14 or more characters,<br/>no reuse of the last 24"]
      mfa["mfa-required group<br/>everything denied without MFA"]
    end

    subgraph network["Network"]
      vpc["VPC with no internet gateway<br/>private subnet"]
      sg["Security groups<br/>default: no rules<br/>app: HTTPS within the VPC only"]
      flow["VPC flow logs"]
    end

    budget["Budget alarm<br/>5 USD a month"]
  end

  inbox["Your inbox"]

  tf --> account
  admin --> api
  root --> api
  admin -. member of .-> mfa
  api --> trail
  trail -->|archive| bucket
  trail -->|"live feed, write-only role"| cwl
  cwl --> filters --> alarms --> sns --> inbox
  vpc --- sg
  vpc --- flow
  flow --> bucket
  budget --> inbox
  kms -. encrypts .-> bucket
  kms -. encrypts .-> cwl
  kms -. encrypts .-> sns
```

The six tripwires, each mapped to MITRE ATT&CK and proven by a staged break
(see [`../detections/README.md`](../detections/README.md)):

| Tripwire | Fires when | ATT&CK |
|---|---|---|
| CloudTrail tampering | logging stopped, trail deleted, reconfigured or narrowed | T1562.008 |
| S3 public access | public access blocks, bucket policy, ACL or ownership changed | T1530 |
| Security group changes | rules added, removed or modified | T1562.007 |
| Sign-in weakening | MFA removed, password policy changed, user removed from a group | T1556 |
| KMS key tampering | key disabled, deletion scheduled, rotation off, policy changed | T1485 |
| Root usage | any action as root, including signing in | T1078.004 |

Two things are deliberately outside Terraform: the budget alarm and the
`admin` user, because both had to exist before any code could run.

## 2. Break, detect, restore

How each staged break went, end to end. The branch at the bottom is the main
finding: Terraform only notices changes to what it manages, so a rule added on
top of a security group is invisible to it, and the detection is what catches it.

```mermaid
flowchart TB
  brk["Staged break<br/>run by a human with MFA"]
  ev["CloudTrail records the call<br/>including failed attempts"]
  feed["Event reaches the<br/>CloudWatch log group"]
  trip["Metric filter counts it"]
  alarm["Alarm goes from OK to ALARM<br/>about 1.5 to 3 minutes after the break"]
  mail["Alert email"]
  triage["Triage: who, how, from where,<br/>with MFA, did it work, what exactly"]
  plan{"Does terraform plan<br/>show drift?"}
  apply["terraform apply restores it"]
  manual["Remove the exact change by ID<br/>example: the added SSH rule"]
  verify["Verify: no drift,<br/>alarm back to OK"]

  brk --> ev --> feed --> trip --> alarm --> mail --> triage --> plan
  plan -->|yes| apply --> verify
  plan -->|no| manual --> verify
```
For the KMS key, blocking comes before detecting. Only root is allowed to turn the key off or delete it. If anyone else tries, AWS refuses. The key keeps working, so the alerts keep working too, and the failed attempt still sets off an alarm.