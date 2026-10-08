"""CUSTOMER-ZERO-RUN3-PREAUTH-001 — Machine-readable resource inventory.

Derived from the canonical infra/ Terraform sources.  Every Terraform-managed
resource is classified by lifecycle.  Unknown mutable resources block execution
authorization.

SAFETY BOUNDARY
---------------
  No live cloud queries.  All data is derived by static analysis of infra/*.tf.
  Live planability is DEFERRED — requires authorized operator preflight.
  This module is offline-only, read-only, and zero-cost.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Lifecycle classification
# ---------------------------------------------------------------------------


class LifecycleClass(str, Enum):
    CREATE_FOR_CEREMONY = "CREATE_FOR_CEREMONY"
    """Created during ceremony provisioning; does not exist beforehand."""

    REUSE_PRESERVED = "REUSE_PRESERVED"
    """Already exists from prior ceremonies; reused, not recreated."""

    DATA_REFERENCE_ONLY = "DATA_REFERENCE_ONLY"
    """Terraform data source — read-only reference, no mutation."""

    DESTROY_AFTER_CEREMONY = "DESTROY_AFTER_CEREMONY"
    """Must be absent after controlled teardown."""

    PRESERVE_AFTER_CEREMONY = "PRESERVE_AFTER_CEREMONY"
    """Must remain present after teardown — audit authority, never destroyed."""


class CostRelevance(str, Enum):
    COST_BEARING = "COST_BEARING"
    """Incurs hourly/per-operation charges when running."""

    NEGLIGIBLE_COST = "NEGLIGIBLE_COST"
    """No direct line-item or negligible cost (IAM, policy, etc.)."""

    ZERO_COST = "ZERO_COST"
    """No charge for existence (data source, already preserved)."""


@dataclass(frozen=True)
class ResourceInventoryEntry:
    """A single Terraform-managed resource or data source in the inventory."""

    terraform_address: str
    provider: str
    resource_type: str
    purpose: str
    lifecycle_class: LifecycleClass
    creation_authority: str
    expected_destroy_stage: str
    preservation_policy: str
    cost_relevance: CostRelevance
    evidence_source: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "terraform_address": self.terraform_address,
            "provider": self.provider,
            "resource_type": self.resource_type,
            "purpose": self.purpose,
            "lifecycle_class": self.lifecycle_class.value,
            "creation_authority": self.creation_authority,
            "expected_destroy_stage": self.expected_destroy_stage,
            "preservation_policy": self.preservation_policy,
            "cost_relevance": self.cost_relevance.value,
            "evidence_source": self.evidence_source,
        }


# ---------------------------------------------------------------------------
# Canonical resource inventory (derived from infra/*.tf static analysis)
# ---------------------------------------------------------------------------

RESOURCE_INVENTORY: list[ResourceInventoryEntry] = [
    # ── Data sources ────────────────────────────────────────────────────────
    ResourceInventoryEntry(
        terraform_address="data.hcp_project.frostgate_production",
        provider="hashicorp/hcp",
        resource_type="hcp_project (data)",
        purpose="Reference to pre-existing HCP frostgate-production project; no mutation",
        lifecycle_class=LifecycleClass.DATA_REFERENCE_ONLY,
        creation_authority="HCP console — pre-existing, operator-created",
        expected_destroy_stage="NOT_APPLICABLE",
        preservation_policy="External to Terraform; not managed by infra/",
        cost_relevance=CostRelevance.ZERO_COST,
        evidence_source="infra/hcp_cluster.tf:data.hcp_project.frostgate_production",
    ),
    # ── HCP infrastructure (cost-bearing, ephemeral) ─────────────────────
    ResourceInventoryEntry(
        terraform_address="hcp_hvn.frostgate",
        provider="hashicorp/hcp",
        resource_type="hcp_hvn",
        purpose="HashiCorp Virtual Network in AWS us-east-1; prerequisite for Vault cluster",
        lifecycle_class=LifecycleClass.CREATE_FOR_CEREMONY,
        creation_authority="FrostGateTerraformOperator (MFA-backed) with explicit human authorization",
        expected_destroy_stage="TEARDOWN_STAGE_4_HVN",
        preservation_policy="ABSENT after teardown; no audit authority depends on HVN retention",
        cost_relevance=CostRelevance.NEGLIGIBLE_COST,
        evidence_source="infra/hcp_cluster.tf:hcp_hvn.frostgate",
    ),
    ResourceInventoryEntry(
        terraform_address="hcp_vault_cluster.customer_zero",
        provider="hashicorp/hcp",
        resource_type="hcp_vault_cluster",
        purpose="HCP Vault Dedicated cluster (standard_small); Customer-Zero trust infrastructure",
        lifecycle_class=LifecycleClass.CREATE_FOR_CEREMONY,
        creation_authority="FrostGateTerraformOperator (MFA-backed) with explicit human authorization",
        expected_destroy_stage="TEARDOWN_STAGE_3_HCP_CLUSTER",
        preservation_policy="ABSENT after teardown; all keys and AppRoles destroyed with cluster",
        cost_relevance=CostRelevance.COST_BEARING,
        evidence_source="infra/hcp_cluster.tf:hcp_vault_cluster.customer_zero",
    ),
    # ── Vault Transit (ephemeral, destroyed with cluster) ─────────────────
    ResourceInventoryEntry(
        terraform_address="vault_mount.transit",
        provider="hashicorp/vault",
        resource_type="vault_mount",
        purpose="Transit secrets engine mount; parent of all three trust signing keys",
        lifecycle_class=LifecycleClass.CREATE_FOR_CEREMONY,
        creation_authority="FrostGateTerraformOperator via Vault provider post-cluster creation",
        expected_destroy_stage="TEARDOWN_STAGE_2_VAULT_CHILDREN",
        preservation_policy="ABSENT after teardown",
        cost_relevance=CostRelevance.ZERO_COST,
        evidence_source="infra/vault_transit.tf:vault_mount.transit",
    ),
    ResourceInventoryEntry(
        terraform_address="vault_transit_secret_backend_key.customer_zero_identity",
        provider="hashicorp/vault",
        resource_type="vault_transit_secret_backend_key",
        purpose="Non-exportable Ed25519 IDENTITY trust signing key",
        lifecycle_class=LifecycleClass.CREATE_FOR_CEREMONY,
        creation_authority="FrostGateTerraformOperator via Vault provider",
        expected_destroy_stage="TEARDOWN_STAGE_1_ENABLE_KEY_DELETION then STAGE_2_VAULT_CHILDREN",
        preservation_policy="ABSENT after teardown; key history not required post-ceremony (historical verification uses pre-enrolled public material)",
        cost_relevance=CostRelevance.ZERO_COST,
        evidence_source="infra/vault_transit.tf:vault_transit_secret_backend_key.customer_zero_identity",
    ),
    ResourceInventoryEntry(
        terraform_address="vault_transit_secret_backend_key.customer_zero_acceptance",
        provider="hashicorp/vault",
        resource_type="vault_transit_secret_backend_key",
        purpose="Non-exportable Ed25519 ACCEPTANCE trust signing key",
        lifecycle_class=LifecycleClass.CREATE_FOR_CEREMONY,
        creation_authority="FrostGateTerraformOperator via Vault provider",
        expected_destroy_stage="TEARDOWN_STAGE_1_ENABLE_KEY_DELETION then STAGE_2_VAULT_CHILDREN",
        preservation_policy="ABSENT after teardown",
        cost_relevance=CostRelevance.ZERO_COST,
        evidence_source="infra/vault_transit.tf:vault_transit_secret_backend_key.customer_zero_acceptance",
    ),
    ResourceInventoryEntry(
        terraform_address="vault_transit_secret_backend_key.customer_zero_approval",
        provider="hashicorp/vault",
        resource_type="vault_transit_secret_backend_key",
        purpose="Non-exportable Ed25519 APPROVAL trust signing key",
        lifecycle_class=LifecycleClass.CREATE_FOR_CEREMONY,
        creation_authority="FrostGateTerraformOperator via Vault provider",
        expected_destroy_stage="TEARDOWN_STAGE_1_ENABLE_KEY_DELETION then STAGE_2_VAULT_CHILDREN",
        preservation_policy="ABSENT after teardown",
        cost_relevance=CostRelevance.ZERO_COST,
        evidence_source="infra/vault_transit.tf:vault_transit_secret_backend_key.customer_zero_approval",
    ),
    # ── Vault AppRole (ephemeral) ─────────────────────────────────────────
    ResourceInventoryEntry(
        terraform_address="vault_auth_backend.approle",
        provider="hashicorp/vault",
        resource_type="vault_auth_backend",
        purpose="AppRole authentication backend; three separated runtime principals",
        lifecycle_class=LifecycleClass.CREATE_FOR_CEREMONY,
        creation_authority="FrostGateTerraformOperator via Vault provider",
        expected_destroy_stage="TEARDOWN_STAGE_2_VAULT_CHILDREN",
        preservation_policy="ABSENT after teardown",
        cost_relevance=CostRelevance.ZERO_COST,
        evidence_source="infra/vault_approle.tf:vault_auth_backend.approle",
    ),
    ResourceInventoryEntry(
        terraform_address="vault_approle_auth_backend_role.identity",
        provider="hashicorp/vault",
        resource_type="vault_approle_auth_backend_role",
        purpose="IDENTITY AppRole — bound to frostgate-cz-identity policy only",
        lifecycle_class=LifecycleClass.CREATE_FOR_CEREMONY,
        creation_authority="FrostGateTerraformOperator via Vault provider",
        expected_destroy_stage="TEARDOWN_STAGE_2_VAULT_CHILDREN",
        preservation_policy="ABSENT after teardown",
        cost_relevance=CostRelevance.ZERO_COST,
        evidence_source="infra/vault_approle.tf:vault_approle_auth_backend_role.identity",
    ),
    ResourceInventoryEntry(
        terraform_address="vault_approle_auth_backend_role.acceptance",
        provider="hashicorp/vault",
        resource_type="vault_approle_auth_backend_role",
        purpose="ACCEPTANCE AppRole — bound to frostgate-cz-acceptance policy only",
        lifecycle_class=LifecycleClass.CREATE_FOR_CEREMONY,
        creation_authority="FrostGateTerraformOperator via Vault provider",
        expected_destroy_stage="TEARDOWN_STAGE_2_VAULT_CHILDREN",
        preservation_policy="ABSENT after teardown",
        cost_relevance=CostRelevance.ZERO_COST,
        evidence_source="infra/vault_approle.tf:vault_approle_auth_backend_role.acceptance",
    ),
    ResourceInventoryEntry(
        terraform_address="vault_approle_auth_backend_role.approval",
        provider="hashicorp/vault",
        resource_type="vault_approle_auth_backend_role",
        purpose="APPROVAL AppRole — bound to frostgate-cz-approval policy only",
        lifecycle_class=LifecycleClass.CREATE_FOR_CEREMONY,
        creation_authority="FrostGateTerraformOperator via Vault provider",
        expected_destroy_stage="TEARDOWN_STAGE_2_VAULT_CHILDREN",
        preservation_policy="ABSENT after teardown",
        cost_relevance=CostRelevance.ZERO_COST,
        evidence_source="infra/vault_approle.tf:vault_approle_auth_backend_role.approval",
    ),
    # ── Vault policies (ephemeral) ────────────────────────────────────────
    ResourceInventoryEntry(
        terraform_address="vault_policy.identity",
        provider="hashicorp/vault",
        resource_type="vault_policy",
        purpose="Least-privilege policy for IDENTITY AppRole — sign+read customer-zero-identity only",
        lifecycle_class=LifecycleClass.CREATE_FOR_CEREMONY,
        creation_authority="FrostGateTerraformOperator via Vault provider",
        expected_destroy_stage="TEARDOWN_STAGE_2_VAULT_CHILDREN",
        preservation_policy="ABSENT after teardown",
        cost_relevance=CostRelevance.ZERO_COST,
        evidence_source="infra/vault_policies.tf:vault_policy.identity",
    ),
    ResourceInventoryEntry(
        terraform_address="vault_policy.acceptance",
        provider="hashicorp/vault",
        resource_type="vault_policy",
        purpose="Least-privilege policy for ACCEPTANCE AppRole — sign+read customer-zero-acceptance only",
        lifecycle_class=LifecycleClass.CREATE_FOR_CEREMONY,
        creation_authority="FrostGateTerraformOperator via Vault provider",
        expected_destroy_stage="TEARDOWN_STAGE_2_VAULT_CHILDREN",
        preservation_policy="ABSENT after teardown",
        cost_relevance=CostRelevance.ZERO_COST,
        evidence_source="infra/vault_policies.tf:vault_policy.acceptance",
    ),
    ResourceInventoryEntry(
        terraform_address="vault_policy.approval",
        provider="hashicorp/vault",
        resource_type="vault_policy",
        purpose="Least-privilege policy for APPROVAL AppRole — sign+read customer-zero-approval only",
        lifecycle_class=LifecycleClass.CREATE_FOR_CEREMONY,
        creation_authority="FrostGateTerraformOperator via Vault provider",
        expected_destroy_stage="TEARDOWN_STAGE_2_VAULT_CHILDREN",
        preservation_policy="ABSENT after teardown",
        cost_relevance=CostRelevance.ZERO_COST,
        evidence_source="infra/vault_policies.tf:vault_policy.approval",
    ),
    # ── AWS audit infrastructure (PRESERVED — never destroyed) ───────────
    ResourceInventoryEntry(
        terraform_address="aws_cloudwatch_log_group.vault_audit",
        provider="hashicorp/aws",
        resource_type="aws_cloudwatch_log_group",
        purpose="CloudWatch log group for HCP Vault audit events; 365-day retention; PERSISTENT AUDIT AUTHORITY",
        lifecycle_class=LifecycleClass.PRESERVE_AFTER_CEREMONY,
        creation_authority="FrostGateTerraformOperator (MFA-backed); reused from prior ceremonies",
        expected_destroy_stage="NEVER — persistent audit authority; no teardown stage applies",
        preservation_policy="MUST remain present indefinitely; required for historical audit verification",
        cost_relevance=CostRelevance.NEGLIGIBLE_COST,
        evidence_source="infra/aws_audit.tf:aws_cloudwatch_log_group.vault_audit; ceremony_state.yaml:preserved_aws_resources",
    ),
    ResourceInventoryEntry(
        terraform_address="aws_iam_user.vault_audit",
        provider="hashicorp/aws",
        resource_type="aws_iam_user",
        purpose="WRITER IAM user — streams Vault audit events to CloudWatch; no read authority",
        lifecycle_class=LifecycleClass.PRESERVE_AFTER_CEREMONY,
        creation_authority="FrostGateTerraformOperator (MFA-backed); reused from prior ceremonies",
        expected_destroy_stage="NEVER — persistent audit authority",
        preservation_policy="MUST remain present; required for future ceremony audit streaming",
        cost_relevance=CostRelevance.ZERO_COST,
        evidence_source="infra/aws_audit.tf:aws_iam_user.vault_audit; ceremony_state.yaml:preserved_aws_resources",
    ),
    ResourceInventoryEntry(
        terraform_address="aws_iam_policy.vault_audit",
        provider="hashicorp/aws",
        resource_type="aws_iam_policy",
        purpose="Minimum IAM policy for HCP Vault audit streaming to CloudWatch",
        lifecycle_class=LifecycleClass.PRESERVE_AFTER_CEREMONY,
        creation_authority="FrostGateTerraformOperator (MFA-backed); reused from prior ceremonies",
        expected_destroy_stage="NEVER — persistent audit authority",
        preservation_policy="MUST remain present",
        cost_relevance=CostRelevance.ZERO_COST,
        evidence_source="infra/aws_audit.tf:aws_iam_policy.vault_audit; ceremony_state.yaml:preserved_aws_resources",
    ),
    ResourceInventoryEntry(
        terraform_address="aws_iam_user_policy_attachment.vault_audit",
        provider="hashicorp/aws",
        resource_type="aws_iam_user_policy_attachment",
        purpose="Attaches vault_audit policy to vault_audit IAM user",
        lifecycle_class=LifecycleClass.PRESERVE_AFTER_CEREMONY,
        creation_authority="FrostGateTerraformOperator (MFA-backed); reused from prior ceremonies",
        expected_destroy_stage="NEVER — persistent audit authority",
        preservation_policy="MUST remain present",
        cost_relevance=CostRelevance.ZERO_COST,
        evidence_source="infra/aws_audit.tf:aws_iam_user_policy_attachment.vault_audit; ceremony_state.yaml:preserved_aws_resources",
    ),
    # ── AWS IAM audit reader (ephemeral for ceremony verification) ────────
    ResourceInventoryEntry(
        terraform_address="aws_iam_role.vault_audit_reader",
        provider="hashicorp/aws",
        resource_type="aws_iam_role",
        purpose="FrostGateVaultAuditReader — MFA-gated read-only role for ceremony audit evidence verification",
        lifecycle_class=LifecycleClass.REUSE_PRESERVED,
        creation_authority="FrostGateTerraformOperator (MFA-backed); present from prior ceremonies",
        expected_destroy_stage="PRESERVE — audit reader is needed for future verification",
        preservation_policy="PRESERVE; required for independent audit evidence verification",
        cost_relevance=CostRelevance.ZERO_COST,
        evidence_source="infra/aws_audit.tf:aws_iam_role.vault_audit_reader",
    ),
    ResourceInventoryEntry(
        terraform_address="aws_iam_policy.vault_audit_reader",
        provider="hashicorp/aws",
        resource_type="aws_iam_policy",
        purpose="Read-only CloudWatch policy for FrostGateVaultAuditReader",
        lifecycle_class=LifecycleClass.REUSE_PRESERVED,
        creation_authority="FrostGateTerraformOperator (MFA-backed); present from prior ceremonies",
        expected_destroy_stage="PRESERVE",
        preservation_policy="PRESERVE",
        cost_relevance=CostRelevance.ZERO_COST,
        evidence_source="infra/aws_audit.tf:aws_iam_policy.vault_audit_reader",
    ),
    ResourceInventoryEntry(
        terraform_address="aws_iam_role_policy_attachment.vault_audit_reader",
        provider="hashicorp/aws",
        resource_type="aws_iam_role_policy_attachment",
        purpose="Attaches vault_audit_reader policy to FrostGateVaultAuditReader role",
        lifecycle_class=LifecycleClass.REUSE_PRESERVED,
        creation_authority="FrostGateTerraformOperator (MFA-backed); present from prior ceremonies",
        expected_destroy_stage="PRESERVE",
        preservation_policy="PRESERVE",
        cost_relevance=CostRelevance.ZERO_COST,
        evidence_source="infra/aws_audit.tf:aws_iam_role_policy_attachment.vault_audit_reader",
    ),
]


# ---------------------------------------------------------------------------
# Out-of-band resources (human-only, never in Terraform state)
# ---------------------------------------------------------------------------

OUT_OF_BAND_RESOURCES = [
    {
        "identifier": "HCP_VAULT_IAM_ACCESS_KEY",
        "description": (
            "AWS access key for vault_audit IAM user — created out-of-band via AWS Console "
            "and entered directly into HCP Vault cluster audit log settings. "
            "Never passes through Terraform state."
        ),
        "classification": "HUMAN_ONLY_SECRET_CONFIGURATION",
        "evidence_source": "infra/aws_audit.tf comment; infra/hcp_cluster.tf comment",
    },
    {
        "identifier": "APPROLE_SECRET_IDS",
        "description": (
            "SecretIDs for three AppRole principals (identity, acceptance, approval) — "
            "generated separately, transferred directly to Railway runtime secret storage. "
            "Never committed to any file or passed through Terraform state."
        ),
        "classification": "HUMAN_ONLY_SECRET_CONFIGURATION",
        "evidence_source": "infra/vault_approle.tf comment",
    },
    {
        "identifier": "VAULT_ADMIN_BOOTSTRAP_TOKEN",
        "description": (
            "Bootstrap admin token for initial Vault configuration — used once for "
            "terraform apply of vault resources, then revoked. Never stored."
        ),
        "classification": "HUMAN_ONLY_EPHEMERAL_SECRET",
        "evidence_source": "infra/vault_transit.tf comment; infra/providers.tf",
    },
]


# ---------------------------------------------------------------------------
# Inventory helper functions
# ---------------------------------------------------------------------------


def get_inventory() -> list[ResourceInventoryEntry]:
    """Return the canonical resource inventory."""
    return list(RESOURCE_INVENTORY)


def get_preserved_resources() -> list[ResourceInventoryEntry]:
    """Return resources that must be preserved after teardown."""
    return [
        r for r in RESOURCE_INVENTORY
        if r.lifecycle_class == LifecycleClass.PRESERVE_AFTER_CEREMONY
    ]


def get_ephemeral_resources() -> list[ResourceInventoryEntry]:
    """Return resources that must be absent after teardown."""
    return [
        r for r in RESOURCE_INVENTORY
        if r.lifecycle_class in (
            LifecycleClass.CREATE_FOR_CEREMONY,
            LifecycleClass.DESTROY_AFTER_CEREMONY,
        )
    ]


def get_cost_bearing_resources() -> list[ResourceInventoryEntry]:
    """Return resources with COST_BEARING classification."""
    return [
        r for r in RESOURCE_INVENTORY
        if r.cost_relevance == CostRelevance.COST_BEARING
    ]


def compute_inventory_fingerprint() -> str:
    """Compute a deterministic fingerprint of the canonical inventory.

    Excludes wall-clock timestamps.  Same inventory content always produces
    the same fingerprint.
    """
    canonical = sorted(
        [r.to_dict() for r in RESOURCE_INVENTORY],
        key=lambda x: x["terraform_address"],
    )
    return hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


RESOURCE_INVENTORY_FINGERPRINT = compute_inventory_fingerprint()
