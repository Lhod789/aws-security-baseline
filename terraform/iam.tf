# Account password policy for IAM users. Follows the current CIS benchmark
# and NIST SP 800-63B: length and no-reuse matter; forced expiry and
# composition rules are deliberately off, because they push people towards
# predictable passwords (Summer2026!) rather than strong ones.
resource "aws_iam_account_password_policy" "this" {
  minimum_password_length        = 14
  password_reuse_prevention      = 24
  allow_users_to_change_password = true

  # Explicit, so any drift towards these older rules shows up in a plan.
  require_lowercase_characters = false
  require_uppercase_characters = false
  require_numbers              = false
  require_symbols              = false
  hard_expiry                  = false
  # max_password_age is left unset: passwords do not expire.
}

# Without MFA, a user can do nothing except set up their own MFA and change
# their own password. A phished password alone is useless, and removing a
# user's MFA immediately removes their access.
data "aws_iam_policy_document" "mfa_required" {
  statement {
    sid       = "AllowViewAccountInfo"
    effect    = "Allow"
    actions   = ["iam:GetAccountPasswordPolicy", "iam:ListVirtualMFADevices"]
    resources = ["*"]
  }

  statement {
    sid       = "AllowManageOwnPassword"
    effect    = "Allow"
    actions   = ["iam:ChangePassword", "iam:GetUser"]
    resources = ["arn:aws:iam::*:user/$${aws:username}"]
  }

  statement {
    sid       = "AllowCreateOwnVirtualMFADevice"
    effect    = "Allow"
    actions   = ["iam:CreateVirtualMFADevice"]
    resources = ["arn:aws:iam::*:mfa/*"]
  }

  statement {
    sid    = "AllowManageOwnUserMFA"
    effect = "Allow"
    actions = [
      "iam:DeactivateMFADevice",
      "iam:EnableMFADevice",
      "iam:ListMFADevices",
      "iam:ResyncMFADevice",
    ]
    resources = ["arn:aws:iam::*:user/$${aws:username}"]
  }

  statement {
    sid    = "DenyAllExceptListedIfNoMFA"
    effect = "Deny"
    not_actions = [
      "iam:CreateVirtualMFADevice",
      "iam:EnableMFADevice",
      "iam:GetUser",
      "iam:GetMFADevice",
      "iam:ListMFADevices",
      "iam:ListVirtualMFADevices",
      "iam:ResyncMFADevice",
      "sts:GetSessionToken",
      "iam:ChangePassword",
      "iam:GetAccountPasswordPolicy",
      # `aws login` exchanges tokens through these two actions. Exempting them
      # only lets a session obtain CLI credentials; those credentials still
      # face this same MFA check for every other action.
      "signin:AuthorizeOAuth2Access",
      "signin:CreateOAuth2Token",
    ]
    resources = ["*"]

    # BoolIfExists: requests with no MFA information at all (for example,
    # long-term access keys) are treated as "no MFA" and denied.
    condition {
      test     = "BoolIfExists"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["false"]
    }
  }
}

resource "aws_iam_policy" "mfa_required" {
  name        = "security-baseline-mfa-required"
  description = "Denies everything except MFA self-service unless the session used MFA"
  policy      = data.aws_iam_policy_document.mfa_required.json
}

resource "aws_iam_group" "mfa_required" {
  name = "mfa-required"
}

resource "aws_iam_group_policy_attachment" "mfa_required" {
  group      = aws_iam_group.mfa_required.name
  policy_arn = aws_iam_policy.mfa_required.arn
}

# The admin user was created in the console during setup (identity bootstrap,
# like the budget). Terraform manages only its group membership, not the user.
resource "aws_iam_user_group_membership" "admin" {
  user   = "admin"
  groups = [aws_iam_group.mfa_required.name]

  # Join only once the policy is attached, so membership never means
  # "in the group but unprotected".
  depends_on = [aws_iam_group_policy_attachment.mfa_required]
}
