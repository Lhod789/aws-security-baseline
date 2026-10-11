# Where security alerts are emailed. Deliberately has no default: the real
# address lives in terraform.tfvars, which .gitignore keeps out of the repo.
variable "alert_email" {
  description = "Email address that receives security alerts"
  type        = string
  sensitive   = true
}
