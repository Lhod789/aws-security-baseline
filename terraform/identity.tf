# Read-only lookup of who Terraform is running as. Used later to build
# account-scoped names and policies; also proves authentication works.
data "aws_caller_identity" "current" {}

output "account_id" {
  value = data.aws_caller_identity.current.account_id
}

output "caller_arn" {
  value = data.aws_caller_identity.current.arn
}
