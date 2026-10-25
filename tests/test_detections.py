"""Checks every detection's filter pattern against sample CloudTrail events.

The patterns are read from terraform/detections.tf through `terraform console`,
so the test checks exactly what is deployed. Matching is done by CloudWatch
Logs' own TestMetricFilter API, which is read-only but needs AWS credentials
(`aws login`). Without Terraform or credentials the tests are skipped, not
failed.

The sample events are synthetic and minimal: they carry only the fields the
patterns look at, with AWS's documentation account ID (123456789012). Each
detection is checked for what it must catch (including failed attempts) and
for near misses it must ignore (reads, the same event name from another
service, AWS service noise).

Run from the repo root:  python3 -m unittest discover -s tests -t .
"""

import json
import shutil
import subprocess
import unittest
from pathlib import Path

TERRAFORM_DIR = Path(__file__).resolve().parents[1] / "terraform"
ACCOUNT = "123456789012"


def event(source, name, *, identity="IAMUser", error=None,
          event_type="AwsApiCall", invoked_by=None):
    """Build a minimal CloudTrail record."""
    user = {"type": identity, "accountId": ACCOUNT}
    if identity == "IAMUser":
        user["userName"] = "admin"
    if identity == "Root":
        user["arn"] = f"arn:aws:iam::{ACCOUNT}:root"
    if invoked_by:
        user["invokedBy"] = invoked_by
    record = {
        "eventVersion": "1.11",
        "userIdentity": user,
        "eventSource": source,
        "eventName": name,
        "awsRegion": "eu-west-2",
        "eventType": event_type,
        "recipientAccountId": ACCOUNT,
    }
    if error:
        record["errorCode"] = error
    return record


CT, S3, EC2, IAM, KMS = (
    "cloudtrail.amazonaws.com", "s3.amazonaws.com", "ec2.amazonaws.com",
    "iam.amazonaws.com", "kms.amazonaws.com",
)

# (label, event, should_match) for each detection in terraform/detections.tf.
CASES = {
    "cloudtrail-tampering": [
        ("StopLogging", event(CT, "StopLogging"), True),
        ("DeleteTrail, denied", event(CT, "DeleteTrail", error="AccessDenied"), True),
        ("PutEventSelectors", event(CT, "PutEventSelectors"), True),
        ("GetTrailStatus (read)", event(CT, "GetTrailStatus"), False),
        ("StopLogging name, other service", event(S3, "StopLogging"), False),
    ],
    "s3-public-access": [
        ("DeleteBucketPublicAccessBlock", event(S3, "DeleteBucketPublicAccessBlock"), True),
        ("DeleteAccountPublicAccessBlock", event(S3, "DeleteAccountPublicAccessBlock"), True),
        ("PutBucketPolicy, denied", event(S3, "PutBucketPolicy", error="AccessDenied"), True),
        ("PutBucketAcl", event(S3, "PutBucketAcl"), True),
        ("GetBucketPolicy (read)", event(S3, "GetBucketPolicy"), False),
        ("DeleteBucketPolicy name, other service", event(CT, "DeleteBucketPolicy"), False),
    ],
    "security-group-changes": [
        ("AuthorizeSecurityGroupIngress", event(EC2, "AuthorizeSecurityGroupIngress"), True),
        ("RevokeSecurityGroupEgress", event(EC2, "RevokeSecurityGroupEgress"), True),
        ("ModifySecurityGroupRules", event(EC2, "ModifySecurityGroupRules"), True),
        ("AuthorizeSecurityGroupIngress, denied",
         event(EC2, "AuthorizeSecurityGroupIngress", error="Client.UnauthorizedOperation"), True),
        ("DescribeSecurityGroups (read)", event(EC2, "DescribeSecurityGroups"), False),
        ("AuthorizeSecurityGroupIngress name, other service",
         event(CT, "AuthorizeSecurityGroupIngress"), False),
    ],
    "auth-weakening": [
        ("DeactivateMFADevice", event(IAM, "DeactivateMFADevice"), True),
        ("UpdateAccountPasswordPolicy", event(IAM, "UpdateAccountPasswordPolicy"), True),
        ("RemoveUserFromGroup", event(IAM, "RemoveUserFromGroup"), True),
        ("CreatePolicyVersion", event(IAM, "CreatePolicyVersion"), True),
        ("DeleteAccountPasswordPolicy, denied",
         event(IAM, "DeleteAccountPasswordPolicy", error="AccessDenied"), True),
        ("AddUserToGroup (strengthens)", event(IAM, "AddUserToGroup"), False),
        ("GetAccountPasswordPolicy (read)", event(IAM, "GetAccountPasswordPolicy"), False),
        ("DeactivateMFADevice name, other service", event(CT, "DeactivateMFADevice"), False),
    ],
    "kms-key-tampering": [
        ("DisableKey", event(KMS, "DisableKey"), True),
        ("ScheduleKeyDeletion", event(KMS, "ScheduleKeyDeletion"), True),
        ("ScheduleKeyDeletion, denied", event(KMS, "ScheduleKeyDeletion", error="AccessDenied"), True),
        ("DisableKeyRotation", event(KMS, "DisableKeyRotation"), True),
        ("PutKeyPolicy", event(KMS, "PutKeyPolicy"), True),
        ("GenerateDataKey (a service using the key)",
         event(KMS, "GenerateDataKey", identity="AWSService", invoked_by="s3.amazonaws.com"), False),
        ("DescribeKey (read)", event(KMS, "DescribeKey"), False),
        ("DisableKey name, other service", event(CT, "DisableKey"), False),
    ],
    "root-usage": [
        ("root console sign-in",
         event("signin.amazonaws.com", "ConsoleLogin", identity="Root",
               event_type="AwsConsoleSignIn"), True),
        ("root API call", event(S3, "ListBuckets", identity="Root"), True),
        ("root API call, denied", event(S3, "ListBuckets", identity="Root", error="AccessDenied"), True),
        ("IAM user call", event(S3, "ListBuckets"), False),
        ("root, invoked by an AWS service",
         event(S3, "ListBuckets", identity="Root", invoked_by="support.amazonaws.com"), False),
        ("root, AWS service event",
         event(S3, "ListBuckets", identity="Root", event_type="AwsServiceEvent"), False),
    ],
}


def _run(cmd, **kwargs):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=120, **kwargs)


class DetectionPatternTests(unittest.TestCase):
    patterns = {}

    @classmethod
    def setUpClass(cls):
        if not (shutil.which("terraform") and shutil.which("aws")):
            raise unittest.SkipTest("terraform and aws CLIs are needed")
        if _run(["aws", "sts", "get-caller-identity"]).returncode != 0:
            raise unittest.SkipTest("no AWS credentials: run `aws login` first")
        console = _run(["terraform", "console"], cwd=TERRAFORM_DIR,
                       input="jsonencode({for k, v in local.detections : k => v.pattern})\n")
        if console.returncode != 0:
            raise unittest.SkipTest("terraform console failed: run `terraform init` in terraform/")
        cls.patterns = json.loads(json.loads(console.stdout))

    def test_every_detection_has_cases(self):
        self.assertEqual(sorted(self.patterns), sorted(CASES),
                         "each detection in detections.tf needs test cases here, and vice versa")

    def _check(self, name):
        cases = CASES[name]
        result = _run(["aws", "logs", "test-metric-filter",
                       "--filter-pattern", self.patterns[name],
                       "--log-event-messages", *[json.dumps(e) for _, e, _ in cases],
                       "--output", "json"])
        self.assertEqual(result.returncode, 0, result.stderr)
        matched = {m["eventNumber"] for m in json.loads(result.stdout)["matches"]}
        for number, (label, _, should_match) in enumerate(cases, start=1):
            with self.subTest(case=label):
                self.assertEqual(number in matched, should_match,
                                 f"{name}: '{label}' should {'match' if should_match else 'not match'}")

    def test_cloudtrail_tampering(self):
        self._check("cloudtrail-tampering")

    def test_s3_public_access(self):
        self._check("s3-public-access")

    def test_security_group_changes(self):
        self._check("security-group-changes")

    def test_auth_weakening(self):
        self._check("auth-weakening")

    def test_kms_key_tampering(self):
        self._check("kms-key-tampering")

    def test_root_usage(self):
        self._check("root-usage")


if __name__ == "__main__":
    unittest.main()
