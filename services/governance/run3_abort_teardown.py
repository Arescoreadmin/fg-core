"""CUSTOMER-ZERO-RUN3-PREAUTH-001 — Abort matrix and teardown contract.

Abort families: PRE_PROVISIONING, POST_PROVISIONING, DURING_CEREMONY,
DURING_TEARDOWN.

SAFETY INVARIANT: No abort condition is translatable to PROVEN.
Every abort results in STOP and controlled teardown — not retry.

Teardown contract is STAGED and NARROW:
  STAGE_1: Enable key deletion
  STAGE_2: Destroy Vault children
  STAGE_3: Destroy HCP Vault cluster
  STAGE_4: Destroy HVN

POST_CEREMONY_PRESERVED resources are NEVER destroyed:
  - aws_cloudwatch_log_group.vault_audit
  - aws_iam_user.vault_audit
  - aws_iam_policy.vault_audit
  - aws_iam_user_policy_attachment.vault_audit

POST_CEREMONY_ABSENT resources must be gone after teardown:
  - hcp_vault_cluster.customer_zero
  - hcp_hvn.frostgate
  - vault_mount.transit (and all Transit keys within)
  - vault_auth_backend.approle (and all AppRoles within)
  - vault_policy.identity/acceptance/approval
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from typing import Any


class AbortStage(str, Enum):
    PRE_PROVISIONING = "PRE_PROVISIONING"
    POST_PROVISIONING = "POST_PROVISIONING"
    DURING_CEREMONY = "DURING_CEREMONY"
    DURING_TEARDOWN = "DURING_TEARDOWN"


class AbortSeverity(str, Enum):
    P0_HARD_STOP = "P0_HARD_STOP"
    """Immediate stop — do NOT proceed under any circumstances."""

    COST_CONTROL = "COST_CONTROL"
    """Cost ceiling or runtime ceiling exceeded — stop immediately."""

    EVIDENCE_INTEGRITY = "EVIDENCE_INTEGRITY"
    """Ceremony evidence cannot be trusted — stop."""


@dataclass(frozen=True)
class AbortCondition:
    """A single abort condition in the abort matrix."""

    abort_id: str
    stage: AbortStage
    title: str
    trigger: str
    response: str
    severity: AbortSeverity
    blocks_proven: bool  # Must always be False — no abort is PROVEN
    teardown_required: bool

    def __post_init__(self) -> None:
        if self.blocks_proven:
            raise ValueError(
                f"AbortCondition {self.abort_id!r}: blocks_proven must be False — "
                "no abort condition is translatable to PROVEN"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "abort_id": self.abort_id,
            "stage": self.stage.value,
            "title": self.title,
            "trigger": self.trigger,
            "response": self.response,
            "severity": self.severity.value,
            "blocks_proven": self.blocks_proven,
            "teardown_required": self.teardown_required,
        }


def _a(
    abort_id: str,
    stage: AbortStage,
    title: str,
    trigger: str,
    response: str,
    severity: AbortSeverity = AbortSeverity.P0_HARD_STOP,
    teardown_required: bool = True,
) -> AbortCondition:
    return AbortCondition(
        abort_id=abort_id,
        stage=stage,
        title=title,
        trigger=trigger,
        response=response,
        severity=severity,
        blocks_proven=False,  # INVARIANT: always False
        teardown_required=teardown_required,
    )


# ---------------------------------------------------------------------------
# Abort matrix
# ---------------------------------------------------------------------------

ABORT_MATRIX: list[AbortCondition] = [
    # ── PRE_PROVISIONING ───────────────────────────────────────────────────
    _a(
        "ABORT-PRE-001",
        AbortStage.PRE_PROVISIONING,
        "candidate_mismatch",
        "Source SHA or candidate fingerprint differs from pre-authorized frozen candidate",
        "STOP. Do not provision. Rerun preauth CLI to obtain a new candidate. Await new human authorization.",
        AbortSeverity.P0_HARD_STOP,
        teardown_required=False,
    ),
    _a(
        "ABORT-PRE-002",
        AbortStage.PRE_PROVISIONING,
        "source_mismatch",
        "Deployed source SHA differs from SHA in cost authorization record",
        "STOP. Do not provision. The authorized SHA must match the deployment SHA exactly.",
        AbortSeverity.P0_HARD_STOP,
        teardown_required=False,
    ),
    _a(
        "ABORT-PRE-003",
        AbortStage.PRE_PROVISIONING,
        "readiness_regression",
        "Final-readiness CLI returns BLOCKED at ceremony time",
        "STOP. Do not provision. Resolve all readiness blockers offline before retrying.",
        AbortSeverity.P0_HARD_STOP,
        teardown_required=False,
    ),
    _a(
        "ABORT-PRE-004",
        AbortStage.PRE_PROVISIONING,
        "missing_human_authorization",
        "authorization_status != AUTHORIZED or no valid authorization record exists",
        "STOP. No paid infrastructure may be created without explicit human authorization. No exceptions.",
        AbortSeverity.P0_HARD_STOP,
        teardown_required=False,
    ),
    _a(
        "ABORT-PRE-005",
        AbortStage.PRE_PROVISIONING,
        "cost_envelope_missing",
        "proposed_max_cost_usd is None or not set in authorization record",
        "STOP. Human must set a maximum cost ceiling before any paid provisioning.",
        AbortSeverity.COST_CONTROL,
        teardown_required=False,
    ),
    _a(
        "ABORT-PRE-006",
        AbortStage.PRE_PROVISIONING,
        "runtime_limit_missing",
        "proposed_max_runtime_hours is None or not set in authorization record",
        "STOP. Human must set a maximum runtime limit before any paid provisioning.",
        AbortSeverity.COST_CONTROL,
        teardown_required=False,
    ),
    _a(
        "ABORT-PRE-007",
        AbortStage.PRE_PROVISIONING,
        "resource_inventory_mismatch",
        "Actual terraform plan creates resources not in approved resource inventory",
        "STOP. Unexpected resources in plan. Reconcile resource inventory before proceeding.",
        AbortSeverity.P0_HARD_STOP,
        teardown_required=False,
    ),
    _a(
        "ABORT-PRE-008",
        AbortStage.PRE_PROVISIONING,
        "operator_authority_failure",
        "FrostGateTerraformOperator MFA-backed auth not confirmed before apply",
        "STOP. Operator must confirm MFA-backed authentication before any apply.",
        AbortSeverity.P0_HARD_STOP,
        teardown_required=False,
    ),
    _a(
        "ABORT-PRE-009",
        AbortStage.PRE_PROVISIONING,
        "missing_audit_prerequisites",
        "aws_cloudwatch_log_group.vault_audit does not exist or is not reachable",
        "STOP. AWS audit infrastructure must be present before cluster creation.",
        AbortSeverity.P0_HARD_STOP,
        teardown_required=False,
    ),
    _a(
        "ABORT-PRE-010",
        AbortStage.PRE_PROVISIONING,
        "live_plan_mismatch",
        "terraform plan output differs from expected resource inventory (unexpected additions or deletions)",
        "STOP. Review plan output against approved resource inventory. Do not apply unexpected changes.",
        AbortSeverity.P0_HARD_STOP,
        teardown_required=False,
    ),
    # ── POST_PROVISIONING ──────────────────────────────────────────────────
    _a(
        "ABORT-POST-001",
        AbortStage.POST_PROVISIONING,
        "unexpected_resources",
        "terraform show reveals resources not in the approved inventory",
        "STOP. Begin staged teardown. Report discrepancy to operator. Do not proceed to ceremony.",
        AbortSeverity.P0_HARD_STOP,
        teardown_required=True,
    ),
    _a(
        "ABORT-POST-002",
        AbortStage.POST_PROVISIONING,
        "vault_health_failure",
        "HCP Vault cluster health check fails after provisioning",
        "STOP. Begin staged teardown. Do not attempt signing with unhealthy Vault.",
        AbortSeverity.P0_HARD_STOP,
        teardown_required=True,
    ),
    _a(
        "ABORT-POST-003",
        AbortStage.POST_PROVISIONING,
        "audit_destination_failure",
        "Checkpoint Q: no audit events visible in CloudWatch after test Vault operation",
        "STOP. Begin staged teardown. Audit delivery is a prerequisite for evidence integrity.",
        AbortSeverity.EVIDENCE_INTEGRITY,
        teardown_required=True,
    ),
    _a(
        "ABORT-POST-004",
        AbortStage.POST_PROVISIONING,
        "key_topology_mismatch",
        "Vault Transit key topology (3 keys, ed25519, non-exportable) does not match spec",
        "STOP. Begin staged teardown. Key topology must exactly match approved configuration.",
        AbortSeverity.P0_HARD_STOP,
        teardown_required=True,
    ),
    _a(
        "ABORT-POST-005",
        AbortStage.POST_PROVISIONING,
        "cost_threshold_breach",
        "HCP portal billing estimate at provisioning exceeds proposed_max_cost_usd",
        "STOP. Begin staged teardown immediately. Cost ceiling is an absolute limit.",
        AbortSeverity.COST_CONTROL,
        teardown_required=True,
    ),
    _a(
        "ABORT-POST-006",
        AbortStage.POST_PROVISIONING,
        "runtime_threshold_breach",
        "Elapsed ceremony time exceeds proposed_max_runtime_hours",
        "STOP. Begin staged teardown immediately. Runtime ceiling is an absolute limit.",
        AbortSeverity.COST_CONTROL,
        teardown_required=True,
    ),
    _a(
        "ABORT-POST-007",
        AbortStage.POST_PROVISIONING,
        "secret_exposure",
        "Any secret material (AppRole SecretID, Vault token, IAM access key) appears in logs, "
        "output files, or terminal history",
        "STOP. Rotate all exposed secrets immediately. Begin staged teardown. Report disclosure.",
        AbortSeverity.P0_HARD_STOP,
        teardown_required=True,
    ),
    _a(
        "ABORT-POST-008",
        AbortStage.POST_PROVISIONING,
        "provenance_mismatch",
        "Source SHA of running service does not match frozen candidate source_sha",
        "STOP. Begin staged teardown. The wrong source SHA is running.",
        AbortSeverity.P0_HARD_STOP,
        teardown_required=True,
    ),
    # ── DURING_CEREMONY ────────────────────────────────────────────────────
    _a(
        "ABORT-CER-001",
        AbortStage.DURING_CEREMONY,
        "signing_failure",
        "Any trust domain sign_* operation fails unexpectedly (non-test failure)",
        "STOP. Begin staged teardown. Do not claim partial signing as evidence.",
        AbortSeverity.P0_HARD_STOP,
        teardown_required=True,
    ),
    _a(
        "ABORT-CER-002",
        AbortStage.DURING_CEREMONY,
        "cross_domain_isolation_failure",
        "Cross-domain proof substitution returns True (isolation broken)",
        "STOP. Begin staged teardown immediately. This is a P0 security failure.",
        AbortSeverity.P0_HARD_STOP,
        teardown_required=True,
    ),
    _a(
        "ABORT-CER-003",
        AbortStage.DURING_CEREMONY,
        "replay_failure",
        "Replayed/mutated payload is accepted as valid (returns True)",
        "STOP. Begin staged teardown immediately. This is a P0 security failure.",
        AbortSeverity.P0_HARD_STOP,
        teardown_required=True,
    ),
    _a(
        "ABORT-CER-004",
        AbortStage.DURING_CEREMONY,
        "historical_verification_failure",
        "Historical key version verification fails when it should succeed",
        "STOP. Begin staged teardown. Historical verification is a required proof.",
        AbortSeverity.P0_HARD_STOP,
        teardown_required=True,
    ),
    _a(
        "ABORT-CER-005",
        AbortStage.DURING_CEREMONY,
        "audit_proof_failure",
        "Audit events cannot be independently read from CloudWatch during ceremony",
        "STOP. Begin staged teardown. Audit evidence is required for Customer-Zero acceptance.",
        AbortSeverity.EVIDENCE_INTEGRITY,
        teardown_required=True,
    ),
    _a(
        "ABORT-CER-006",
        AbortStage.DURING_CEREMONY,
        "tenant_isolation_failure",
        "Cross-tenant signing succeeds when it should fail",
        "STOP. Begin staged teardown immediately. This is a P0 security failure.",
        AbortSeverity.P0_HARD_STOP,
        teardown_required=True,
    ),
    _a(
        "ABORT-CER-007",
        AbortStage.DURING_CEREMONY,
        "report_provenance_failure",
        "Mutated report_json passes verification (PROVENANCE-INTEGRITY regression)",
        "STOP. Begin staged teardown immediately. This is a P0 security failure.",
        AbortSeverity.P0_HARD_STOP,
        teardown_required=True,
    ),
    _a(
        "ABORT-CER-008",
        AbortStage.DURING_CEREMONY,
        "portable_verification_failure",
        "PortableVerificationAuthority.verify_offline() fails on a valid historical artifact",
        "STOP. Historical verification must succeed before teardown. Do not proceed.",
        AbortSeverity.EVIDENCE_INTEGRITY,
        teardown_required=True,
    ),
    # ── DURING_TEARDOWN ────────────────────────────────────────────────────
    _a(
        "ABORT-TEAR-001",
        AbortStage.DURING_TEARDOWN,
        "required_evidence_not_preserved",
        "Pre-teardown checklist: CloudWatch audit evidence, portable verification bundles, "
        "ceremony evidence manifest not captured before teardown begins",
        "STOP teardown. Capture all required evidence first. Do not proceed with any teardown stage.",
        AbortSeverity.EVIDENCE_INTEGRITY,
        teardown_required=False,
    ),
    _a(
        "ABORT-TEAR-002",
        AbortStage.DURING_TEARDOWN,
        "unexpected_retained_paid_resources",
        "After staged teardown completion, hcp_vault_cluster or hcp_hvn still exists in provider state",
        "STOP. Investigate and destroy remaining paid resources. Verify billing evidence after.",
        AbortSeverity.COST_CONTROL,
        teardown_required=True,
    ),
    _a(
        "ABORT-TEAR-003",
        AbortStage.DURING_TEARDOWN,
        "preserved_aws_audit_targeted_for_destruction",
        "Teardown stage attempts to destroy aws_cloudwatch_log_group.vault_audit, "
        "aws_iam_user.vault_audit, aws_iam_policy.vault_audit, or aws_iam_user_policy_attachment.vault_audit",
        "STOP immediately. These resources must NEVER be destroyed. Abort teardown stage.",
        AbortSeverity.P0_HARD_STOP,
        teardown_required=False,
    ),
    _a(
        "ABORT-TEAR-004",
        AbortStage.DURING_TEARDOWN,
        "historical_proof_not_verifiable",
        "Post-teardown: PortableVerificationAuthority.verify_offline() returns False on a "
        "captured ceremony artifact",
        "STOP. Historical proof is broken. Do not declare CUSTOMER-ZERO-TRUST proven. "
        "Investigate before ACCEPT-001.",
        AbortSeverity.EVIDENCE_INTEGRITY,
        teardown_required=False,
    ),
]


# ---------------------------------------------------------------------------
# Teardown contract
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TeardownContractEntry:
    """A single resource in the teardown contract."""

    terraform_address: str
    post_ceremony_state: str  # "ABSENT" or "PRESERVED"
    teardown_stage: str
    note: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "terraform_address": self.terraform_address,
            "post_ceremony_state": self.post_ceremony_state,
            "teardown_stage": self.teardown_stage,
            "note": self.note,
        }


TEARDOWN_CONTRACT: dict[str, Any] = {
    "method": "four-stage-narrow-teardown",
    "stages": [
        {
            "stage": "STAGE_1_ENABLE_KEY_DELETION",
            "description": "Enable deletion_allowed=true on all three Transit keys (required before key destroy)",
            "terraform_targets": [
                "vault_transit_secret_backend_key.customer_zero_identity",
                "vault_transit_secret_backend_key.customer_zero_acceptance",
                "vault_transit_secret_backend_key.customer_zero_approval",
            ],
            "command_note": (
                "terraform apply -target=vault_transit_secret_backend_key.customer_zero_identity "
                "-target=vault_transit_secret_backend_key.customer_zero_acceptance "
                "-target=vault_transit_secret_backend_key.customer_zero_approval "
                "(with deletion_allowed=true override)"
            ),
        },
        {
            "stage": "STAGE_2_VAULT_CHILDREN",
            "description": (
                "Destroy all Vault child resources: Transit mount (3 keys), AppRole backend "
                "(3 roles), 3 policies"
            ),
            "terraform_targets": [
                "vault_mount.transit",
                "vault_transit_secret_backend_key.customer_zero_identity",
                "vault_transit_secret_backend_key.customer_zero_acceptance",
                "vault_transit_secret_backend_key.customer_zero_approval",
                "vault_auth_backend.approle",
                "vault_approle_auth_backend_role.identity",
                "vault_approle_auth_backend_role.acceptance",
                "vault_approle_auth_backend_role.approval",
                "vault_policy.identity",
                "vault_policy.acceptance",
                "vault_policy.approval",
            ],
            "command_note": "terraform destroy -target=vault_mount.transit [+targets]",
        },
        {
            "stage": "STAGE_3_HCP_CLUSTER",
            "description": "Destroy HCP Vault Dedicated cluster (cost-bearing resource)",
            "terraform_targets": ["hcp_vault_cluster.customer_zero"],
            "command_note": "terraform destroy -target=hcp_vault_cluster.customer_zero",
        },
        {
            "stage": "STAGE_4_HVN",
            "description": "Destroy HCP HVN (network container; requires cluster absent first)",
            "terraform_targets": ["hcp_hvn.frostgate"],
            "command_note": "terraform destroy -target=hcp_hvn.frostgate",
        },
    ],
    "post_ceremony_absent": [
        TeardownContractEntry(
            "hcp_vault_cluster.customer_zero",
            "ABSENT",
            "STAGE_3_HCP_CLUSTER",
            "Cost-bearing resource; must be absent after teardown",
        ).to_dict(),
        TeardownContractEntry(
            "hcp_hvn.frostgate",
            "ABSENT",
            "STAGE_4_HVN",
            "HCP network container; must be absent after teardown",
        ).to_dict(),
        TeardownContractEntry(
            "vault_mount.transit",
            "ABSENT",
            "STAGE_2_VAULT_CHILDREN",
            "Vault Transit engine; destroyed with Vault children",
        ).to_dict(),
        TeardownContractEntry(
            "vault_auth_backend.approle",
            "ABSENT",
            "STAGE_2_VAULT_CHILDREN",
            "AppRole auth backend; destroyed with Vault children",
        ).to_dict(),
    ],
    "post_ceremony_preserved": [
        TeardownContractEntry(
            "aws_cloudwatch_log_group.vault_audit",
            "PRESERVED",
            "NEVER",
            "PERSISTENT AUDIT AUTHORITY — must NEVER be destroyed",
        ).to_dict(),
        TeardownContractEntry(
            "aws_iam_user.vault_audit",
            "PRESERVED",
            "NEVER",
            "PERSISTENT AUDIT AUTHORITY — must NEVER be destroyed",
        ).to_dict(),
        TeardownContractEntry(
            "aws_iam_policy.vault_audit",
            "PRESERVED",
            "NEVER",
            "PERSISTENT AUDIT AUTHORITY — must NEVER be destroyed",
        ).to_dict(),
        TeardownContractEntry(
            "aws_iam_user_policy_attachment.vault_audit",
            "PRESERVED",
            "NEVER",
            "PERSISTENT AUDIT AUTHORITY — must NEVER be destroyed",
        ).to_dict(),
    ],
    "prohibition": (
        "DO NOT use generic `terraform destroy` (destroys ALL resources). "
        "Teardown MUST be staged and narrow as specified above. "
        "AWS audit resources (aws_cloudwatch_log_group.vault_audit, "
        "aws_iam_user.vault_audit, aws_iam_policy.vault_audit, "
        "aws_iam_user_policy_attachment.vault_audit) must NEVER be included "
        "in any destroy target."
    ),
}


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def get_abort_matrix() -> list[AbortCondition]:
    """Return the canonical abort matrix."""
    return list(ABORT_MATRIX)


def get_abort_by_stage(stage: AbortStage) -> list[AbortCondition]:
    """Return abort conditions for a specific stage."""
    return [a for a in ABORT_MATRIX if a.stage == stage]


def get_teardown_contract() -> dict[str, Any]:
    """Return the canonical teardown contract."""
    return TEARDOWN_CONTRACT


def compute_abort_teardown_fingerprint() -> str:
    """Deterministic fingerprint of abort matrix + teardown contract."""
    canonical = {
        "abort_matrix": sorted(
            [a.to_dict() for a in ABORT_MATRIX],
            key=lambda x: x["abort_id"],
        ),
        "teardown_contract": {
            "method": TEARDOWN_CONTRACT["method"],
            "post_ceremony_absent": sorted(
                TEARDOWN_CONTRACT["post_ceremony_absent"],
                key=lambda x: x["terraform_address"],
            ),
            "post_ceremony_preserved": sorted(
                TEARDOWN_CONTRACT["post_ceremony_preserved"],
                key=lambda x: x["terraform_address"],
            ),
        },
    }
    return hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


ABORT_TEARDOWN_FINGERPRINT = compute_abort_teardown_fingerprint()
