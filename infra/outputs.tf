# Non-secret outputs only.
# Values marked sensitive = true are excluded from terraform output display.
# NEVER output: tokens, SecretIDs, private keys, access keys, or any credential.

# ── HCP cluster ───────────────────────────────────────────────────────────────

output "hcp_organization_id" {
  description = "HCP organization ID."
  value       = var.hcp_organization_id
}

output "hcp_project_id" {
  description = "HCP project ID (frostgate-production)."
  value       = var.hcp_project_id
}

output "vault_cluster_id" {
  description = "HCP Vault Dedicated cluster ID."
  value       = hcp_vault_cluster.customer_zero.cluster_id
}

output "vault_cluster_tier" {
  description = "HCP Vault Dedicated cluster tier."
  value       = hcp_vault_cluster.customer_zero.tier
}

output "vault_address" {
  description = "Vault cluster public HTTPS endpoint (non-secret)."
  value       = hcp_vault_cluster.customer_zero.vault_public_endpoint_url
}

output "vault_namespace" {
  description = "Vault namespace for Customer-Zero resources."
  value       = var.vault_namespace
}

output "vault_version" {
  description = "Vault version deployed on the cluster."
  value       = hcp_vault_cluster.customer_zero.vault_version
}

output "hcp_hvn_id" {
  description = "HVN identifier."
  value       = hcp_hvn.frostgate.hvn_id
}

# ── Transit keys (non-secret key identifiers) ─────────────────────────────────
# Key names are non-secret identifiers. Private key material never leaves Vault.

output "transit_key_identity" {
  description = "Transit key name for customer-zero-identity trust role."
  value       = vault_transit_secret_backend_key.customer_zero_identity.name
}

output "transit_key_acceptance" {
  description = "Transit key name for customer-zero-acceptance trust role."
  value       = vault_transit_secret_backend_key.customer_zero_acceptance.name
}

output "transit_key_approval" {
  description = "Transit key name for customer-zero-approval trust role."
  value       = vault_transit_secret_backend_key.customer_zero_approval.name
}

# ── AppRole role IDs (non-secret identifiers) ─────────────────────────────────
# Role IDs are non-secret. They are required in the trust evidence manifest.
# SecretIDs are NOT output — they are generated via the Vault CLI/API and
# transferred directly to Railway secret storage.

output "approle_role_id_identity" {
  description = "AppRole role ID for frostgate-cz-identity (non-secret identifier)."
  value       = vault_approle_auth_backend_role.identity.role_id
}

output "approle_role_id_acceptance" {
  description = "AppRole role ID for frostgate-cz-acceptance (non-secret identifier)."
  value       = vault_approle_auth_backend_role.acceptance.role_id
}

output "approle_role_id_approval" {
  description = "AppRole role ID for frostgate-cz-approval (non-secret identifier)."
  value       = vault_approle_auth_backend_role.approval.role_id
}

# ── Policies ──────────────────────────────────────────────────────────────────

output "policy_name_identity" {
  description = "Vault policy name for customer-zero-identity."
  value       = vault_policy.identity.name
}

output "policy_name_acceptance" {
  description = "Vault policy name for customer-zero-acceptance."
  value       = vault_policy.acceptance.name
}

output "policy_name_approval" {
  description = "Vault policy name for customer-zero-approval."
  value       = vault_policy.approval.name
}

# ── AWS audit ─────────────────────────────────────────────────────────────────

output "cloudwatch_log_group_name" {
  description = "CloudWatch log group name for Vault audit events."
  value       = aws_cloudwatch_log_group.vault_audit.name
}

output "cloudwatch_log_group_arn" {
  description = "CloudWatch log group ARN."
  value       = aws_cloudwatch_log_group.vault_audit.arn
}

output "iam_audit_user_arn" {
  description = "IAM user ARN for HCP Vault audit streaming."
  value       = aws_iam_user.vault_audit.arn
}

output "iam_audit_user_name" {
  description = "IAM user name for HCP Vault audit streaming."
  value       = aws_iam_user.vault_audit.name
}

output "iam_audit_policy_arn" {
  description = "IAM policy ARN for HCP Vault audit streaming."
  value       = aws_iam_policy.vault_audit.arn
}

# ── Ceremony metadata ─────────────────────────────────────────────────────────

output "ceremony_id" {
  description = "Trust ceremony identifier."
  value       = var.ceremony_id
}
