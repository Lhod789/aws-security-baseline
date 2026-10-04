terraform {
  required_version = ">= 1.10"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

# Credentials come from `aws login` (short-lived, auto-refreshing).
# No access keys are configured anywhere in this repo.
provider "aws" {
  region = "eu-west-2"
}
