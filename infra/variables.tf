# Non-secret input variables.
# Values are supplied via HCP Terraform workspace variables or .tfvars files
# that are explicitly reviewed before use and never committed to Git.
#
# SENSITIVE variables (marked sensitive = true) must be set as sensitive
# HCP Terraform workspace variables — never in committed .tfvars files.

# ── HCP ───────────────────────────────────────────────────────────────────────

variable "hcp_project_id" {
  type        = string
  description = "HCP project ID for frostgate-production."
  default     = "91e2a673-af09-4638-b561-17e4c0ae4e71"
}

variable "hcp_organization_id" {
  type        = string
  description = "HCP organization ID for Frostgate-org."
  default     = "407fb650-8bea-4232-ab0d-a8f62c7239e6"
}

variable "hcp_hvn_cidr" {
  type        = string
  description = "CIDR block for the HashiCorp Virtual Network in AWS us-east-1."
  default     = "172.25.16.0/20"
}

# ── HCP Vault Dedicated ───────────────────────────────────────────────────────

variable "vault_cluster_name" {
  type        = string
  description = "HCP Vault Dedicated cluster name."
  default     = "frostgate-customer-zero"
}

variable "vault_cluster_tier" {
  type        = string
  description = <<-EOT
    HCP Vault Dedicated tier. Valid values in hcp provider v0.114.0:
      dev, standard_small, standard_medium, standard_large,
      plus_small, plus_medium, plus_large
    "starter_small" was deprecated in v0.102.0 and is rejected at plan time.
    "standard_small" is the smallest production-grade tier.
  EOT
  default     = "standard_small"
}

# ── Vault provider ────────────────────────────────────────────────────────────

variable "vault_address" {
  type        = string
  description = "HTTPS address of the HCP Vault Dedicated cluster public endpoint. Set after cluster creation."
  default     = ""
}

variable "vault_namespace" {
  type        = string
  description = "Vault namespace for Customer-Zero resources. HCP Vault Dedicated uses 'admin'."
  default     = "admin"
}

variable "vault_token_ttl" {
  type        = number
  description = "AppRole token initial TTL in seconds. Consistent with FrostGate bounded-session requirements."
  default     = 3600
}

variable "vault_token_max_ttl" {
  type        = number
  description = "AppRole token maximum TTL in seconds including renewals. Forces re-authentication after expiry."
  default     = 7200
}

# ── AWS ───────────────────────────────────────────────────────────────────────

variable "aws_region" {
  type        = string
  description = "AWS region for CloudWatch audit destination."
  default     = "us-east-1"
}

variable "cloudwatch_log_group_name" {
  type        = string
  description = "CloudWatch log group for Vault audit events."
  default     = "/frostgate/customer-zero/vault-audit"
}

variable "cloudwatch_retention_days" {
  type        = number
  description = "CloudWatch log retention in days."
  default     = 365
}

# ── IAM operator identity ─────────────────────────────────────────────────────

variable "operator_iam_user_arn" {
  type        = string
  description = <<-EOT
    ARN of the MFA-authenticated human operator IAM user trusted for
    FrostGateVaultAuditReader role assumption. Required; no default.
    Must be an IAM user ARN in the form arn:aws:iam::<account>:user/<name>.
    Set via TF_VAR_operator_iam_user_arn before any plan or apply.
    Example: "arn:aws:iam::398915901105:user/frostgate-human"
  EOT

  validation {
    condition     = can(regex("^arn:aws:iam::[0-9]{12}:user/.+$", var.operator_iam_user_arn))
    error_message = "operator_iam_user_arn must be a valid IAM user ARN (arn:aws:iam::<account>:user/<name>). Set TF_VAR_operator_iam_user_arn before planning."
  }
}

# ── Ceremony metadata ─────────────────────────────────────────────────────────

variable "ceremony_id" {
  type        = string
  description = "Ceremony identifier for evidence manifest and resource tagging."
  default     = "customer-zero-trust-2026-10-02-001"
}
