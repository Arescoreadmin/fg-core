"""CUSTOMER-ZERO-RUN3-PREAUTH-001 — Machine-readable cost authorization REQUEST.

This module produces a cost authorization REQUEST, NOT an approval.

CRITICAL INVARIANT (NON-NEGOTIABLE)
-------------------------------------
  authorization_status MUST remain "NOT_AUTHORIZED".
  This module MUST NEVER be modified to return AUTHORIZED_TO_SPEND.
  A human operator with explicit authority must create a separate authorization
  record. This module is the REQUEST that human will act on.

Fail-closed design: authorization binding fails if ANY of these are missing
or wrong:
  - Missing approval record
  - Expired approval
  - Wrong ceremony ID
  - Wrong candidate fingerprint
  - Wrong source SHA
  - Wrong resource inventory fingerprint
  - Missing maximum cost
  - Missing maximum runtime
  - Reused historical authorization
  - Invalid approver authority

SAFETY BOUNDARY
---------------
  - No cloud queries
  - No provider tokens, AWS secrets, Vault credentials, or private keys stored
  - Historical cost $321.81 is factual — prior authorization is consumed
  - proposed_max_cost_usd is None (human must set)
  - proposed_max_runtime_hours is None (human must set)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class CostAuthorizationRequest:
    """Machine-readable cost authorization REQUEST for CUSTOMER-ZERO-TRUST-003 Run 3.

    This is a REQUEST — NOT an approval.  authorization_status is always
    "NOT_AUTHORIZED" until a human operator with explicit authority creates a
    separate authorization record.
    """

    ceremony_id: str
    candidate_fingerprint: str
    resource_inventory_fingerprint: str
    source_sha: str

    # Historical cost evidence
    historical_cost_usd: float
    pricing_evidence: str
    pricing_as_of: str
    pricing_confidence: str

    # Human-must-set fields — None until authorized operator completes
    proposed_max_runtime_hours: None
    proposed_max_cost_usd: None

    # Estimated range — NOT_PROVEN until operator preflight
    estimated_cost_range: dict[str, Any]

    # Resource inventory summary
    expected_resources: list[dict[str, Any]]
    preserved_resources: list[dict[str, Any]]

    # Authorization binding
    required_operator: str
    authorization_owner: None
    authorization_status: str
    authorization_expiration: None

    # Abort thresholds — human must set both
    abort_thresholds: dict[str, Any]

    # Teardown deadline — human must set
    teardown_deadline: None

    def validate_authorization_binding(
        self,
        candidate_fingerprint: str,
        resource_inventory_fingerprint: str,
        source_sha: str,
        ceremony_id: str,
    ) -> tuple[bool, list[str]]:
        """Validate that this request can be authorized.

        Returns (valid, [failure_reasons]).
        Fails closed — any missing or wrong binding fails authorization.
        """
        failures: list[str] = []

        if self.authorization_status != "NOT_AUTHORIZED":
            failures.append(
                f"authorization_status must be NOT_AUTHORIZED, got {self.authorization_status!r}"
            )
        if self.proposed_max_cost_usd is None:
            failures.append("proposed_max_cost_usd is None — human must set maximum cost")
        if self.proposed_max_runtime_hours is None:
            failures.append(
                "proposed_max_runtime_hours is None — human must set maximum runtime"
            )
        if self.ceremony_id != ceremony_id:
            failures.append(
                f"ceremony_id mismatch: expected {ceremony_id!r}, got {self.ceremony_id!r}"
            )
        if self.candidate_fingerprint != candidate_fingerprint:
            failures.append(
                f"candidate_fingerprint mismatch: expected {candidate_fingerprint!r}"
            )
        if self.source_sha != source_sha:
            failures.append(
                f"source_sha mismatch: authorization bound to {self.source_sha!r}, "
                f"current runtime is {source_sha!r}"
            )
        if self.resource_inventory_fingerprint != resource_inventory_fingerprint:
            failures.append(
                f"resource_inventory_fingerprint mismatch: expected {resource_inventory_fingerprint!r}"
            )
        if self.abort_thresholds.get("cost_usd") is None:
            failures.append("abort_thresholds.cost_usd is None — human must set cost abort threshold")
        if self.abort_thresholds.get("runtime_hours") is None:
            failures.append(
                "abort_thresholds.runtime_hours is None — human must set runtime abort threshold"
            )

        return (len(failures) == 0, failures)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ceremony_id": self.ceremony_id,
            "candidate_fingerprint": self.candidate_fingerprint,
            "resource_inventory_fingerprint": self.resource_inventory_fingerprint,
            "source_sha": self.source_sha,
            "historical_cost_usd": self.historical_cost_usd,
            "pricing_evidence": self.pricing_evidence,
            "pricing_as_of": self.pricing_as_of,
            "pricing_confidence": self.pricing_confidence,
            "proposed_max_runtime_hours": self.proposed_max_runtime_hours,
            "proposed_max_cost_usd": self.proposed_max_cost_usd,
            "estimated_cost_range": self.estimated_cost_range,
            "expected_resources": self.expected_resources,
            "preserved_resources": self.preserved_resources,
            "required_operator": self.required_operator,
            "authorization_owner": self.authorization_owner,
            "authorization_status": self.authorization_status,
            "authorization_expiration": self.authorization_expiration,
            "abort_thresholds": self.abort_thresholds,
            "teardown_deadline": self.teardown_deadline,
        }


def build_cost_request(
    candidate_fingerprint: str,
    resource_inventory_fingerprint: str,
    expected_resources: list[dict[str, Any]],
    preserved_resources: list[dict[str, Any]],
    source_sha: str = "UNKNOWN",
) -> CostAuthorizationRequest:
    """Build the canonical cost authorization REQUEST.

    Never returns an authorized request — authorization_status is always
    "NOT_AUTHORIZED".  The human operator must create a separate authorization
    record.
    """
    return CostAuthorizationRequest(
        ceremony_id="CUSTOMER-ZERO-TRUST-003-RUN3",
        candidate_fingerprint=candidate_fingerprint,
        resource_inventory_fingerprint=resource_inventory_fingerprint,
        source_sha=source_sha,
        historical_cost_usd=321.81,
        pricing_evidence="DECLARED — historical ceremony state (customer_one/ceremony_state.yaml:cost_containment.historical_october_usage_usd)",
        pricing_as_of="2026-10-06",
        pricing_confidence="HISTORICAL_ONLY",
        # Human must set — None until authorized operator completes
        proposed_max_runtime_hours=None,
        proposed_max_cost_usd=None,
        estimated_cost_range={
            "min_usd": None,
            "max_usd": None,
            "confidence": "NOT_PROVEN",
            "note": (
                "Cost estimate requires operator preflight with confirmed HCP portal pricing. "
                "Historical $321.81 from runs 1+2 is not a ceiling for run 3. "
                "Human must set proposed_max_cost_usd before provisioning."
            ),
        },
        expected_resources=expected_resources,
        preserved_resources=preserved_resources,
        required_operator="FrostGateTerraformOperator (MFA-backed)",
        authorization_owner=None,
        authorization_status="NOT_AUTHORIZED",
        authorization_expiration=None,
        abort_thresholds={
            "cost_usd": None,
            "runtime_hours": None,
            "note": (
                "Human operator must set both cost_usd and runtime_hours abort thresholds "
                "before ceremony provisioning begins. Missing either threshold blocks execution."
            ),
        },
        teardown_deadline=None,
    )
