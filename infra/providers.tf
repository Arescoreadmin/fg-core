# Provider configurations
# Non-secret values only. Credentials are supplied at runtime through
# environment variables or the authenticated CLI session.
# Never hardcode credentials in this file.

provider "hcp" {
  # Credentials supplied via:
  #   HCP_CLIENT_ID     (env)
  #   HCP_CLIENT_SECRET (env — never commit)
  # Or via interactive `hcp auth login` (preferred for operator use).
  project_id = var.hcp_project_id
}

provider "vault" {
  address   = var.vault_address
  namespace = var.vault_namespace
  # Token supplied via VAULT_TOKEN env var or AppRole at runtime.
  # Never hardcode a token here.
  #
  # TWO-PHASE APPLY: vault_address is unknown until the HCP cluster exists.
  # Phase 1 applies HCP + AWS resources only (-target flags; see ceremony-runbook.md §F).
  # Phase 2 sets TF_VAR_vault_address from Phase 1 output, then applies Vault resources.
}

provider "aws" {
  region = var.aws_region
  # Credentials supplied via:
  #   AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY (env — never commit)
  #   or IAM instance profile / SSO
}
