# =============================================================================
# HCP infrastructure — HashiCorp Virtual Network + Vault Dedicated cluster
#
# COST-BEARING RESOURCES — DO NOT APPLY without operator approval.
# HCP Vault Dedicated (Essentials/Small, AWS us-east-1) incurs hourly charges.
# See the cost gate in CHECKPOINT before running terraform apply.
# =============================================================================

# HCP project data source — references the already-created frostgate-production
data "hcp_project" "frostgate_production" {
  project = var.hcp_project_id
}

# HashiCorp Virtual Network — prerequisite for Vault Dedicated cluster.
# An HVN itself does not incur a direct line-item charge; cost is billed
# through the Vault Dedicated cluster that runs inside it.
resource "hcp_hvn" "frostgate" {
  hvn_id         = "frostgate-us-east-1"
  cloud_provider = "aws"
  region         = var.aws_region
  cidr_block     = var.hcp_hvn_cidr

  lifecycle {
    # Destroying the HVN destroys the cluster and all keys within it.
    # Require explicit override before destruction.
    prevent_destroy = true
  }
}

# HCP Vault Dedicated cluster — Customer-Zero trust infrastructure.
#
# Tier: "standard_small" is the smallest production-grade tier in hcp provider
# v0.114.0. "starter_small" was disabled in v0.102.0 and causes a plan error.
#
# Audit log config is deliberately absent from this resource. CloudWatch
# streaming is configured out-of-band via HCP UI (Cluster → Audit Logging)
# after the IAM user and access key are created manually. This keeps IAM
# credentials out of Terraform state entirely.
resource "hcp_vault_cluster" "customer_zero" {
  cluster_id      = var.vault_cluster_name
  hvn_id          = hcp_hvn.frostgate.hvn_id
  tier            = var.vault_cluster_tier
  public_endpoint = true

  # audit_log_config is configured out-of-band via HCP UI after cluster creation.
  # The IAM access key for CloudWatch is created manually and entered directly
  # in HCP Vault cluster settings — it never passes through Terraform state.

  lifecycle {
    prevent_destroy = true
  }

  depends_on = [hcp_hvn.frostgate]
}
