terraform {
  required_version = "~> 1.16"

  # ---------------------------------------------------------------------------
  # Remote state — HCP Terraform (Free tier)
  #
  # Organization: to be confirmed after terraform login completes.
  # Preferred name: "frostgate"  Fallback: "frostgate-org"
  #
  # Update the organization value below after terraform login and org creation,
  # then run terraform init.
  # ---------------------------------------------------------------------------
  cloud {
    organization = "Frostgate"
    workspaces {
      name = "frostgate-customer-zero"
    }
  }

  required_providers {
    hcp = {
      source  = "hashicorp/hcp"
      version = "~> 0.96"
    }
    vault = {
      source  = "hashicorp/vault"
      version = "~> 4.4"
    }
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.64"
    }
  }
}
