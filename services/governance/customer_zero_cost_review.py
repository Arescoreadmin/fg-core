"""CUSTOMER-ZERO-RUN3-HUMAN-COST-REVIEW-001 — Independent cost-authorization verifier.

This module is a standalone Python CLI that verifies the human cost review package
for the third Customer-Zero trust ceremony (CUSTOMER-ZERO-TRUST-003).

SAFETY INVARIANTS (NON-NEGOTIABLE)
------------------------------------
1. This module NEVER returns APPROVED. APPROVED is not a reachable state from this
   module — it requires a separate verified human decision mechanism that does not
   exist in this file.
2. This module fails CLOSED on all 22 conditions listed in _VERIFICATION_CONDITIONS.
3. No cloud queries, no provider tokens, no network calls of any kind.
4. No secrets, credentials, API keys, or private keys are read or written.
5. No authorization is granted, advanced, or implied by this module.

VERIFICATION STATES
--------------------
  SCHEMA_VALID          — Authorization request structure is correct (all required
                          fields present and of correct type).
  PRICING_VERIFIED      — Pricing evidence present, valid, and not expired.
  READY_FOR_HUMAN_DECISION — All non-human inputs are complete. Package may be
                          presented to the human approver for review.
  BLOCKED               — One or more required inputs are missing or invalid.
                          Package MUST NOT be presented for approval.
  APPROVED              — MUST NEVER BE RETURNED by this module. If this state
                          ever appears, it is a bug.

CANONICAL TRUTH PRESERVED
--------------------------
  CUSTOMER_ZERO_TRUST = NOT_PROVEN
  THIRD_PAID_CEREMONY = NOT_AUTHORIZED
  PAID_HCP_INFRASTRUCTURE = ABSENT
  COST_AUTHORIZATION = NOT_AUTHORIZED

USAGE
-----
  python services/governance/customer_zero_cost_review.py --repo .
  python services/governance/customer_zero_cost_review.py --repo . --json
  python services/governance/customer_zero_cost_review.py \\
      --request customer_one/run3_cost_authorization_request.json \\
      --pricing customer_one/run3_pricing_evidence_schema.json \\
      --json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CANONICAL_SOURCE_SHA = "873148e84b9d9163bb13c8e3e185f5c47d43225e"
WORK_ITEM_ID = "CUSTOMER-ZERO-RUN3-HUMAN-COST-REVIEW-001"

EXPECTED_PRESERVED_RESOURCES = frozenset([
    "aws_cloudwatch_log_group.vault_audit",
    "aws_iam_policy.vault_audit",
    "aws_iam_user.vault_audit",
    "aws_iam_user_policy_attachment.vault_audit",
    "aws_iam_role.vault_audit_reader",
    "aws_iam_role_policy_attachment.vault_audit_reader",
])

REQUIRED_REQUEST_FIELDS = [
    "request_id",
    "schema_version",
    "canonical_source_sha",
    "candidate_fingerprint",
    "infrastructure_fingerprint",
    "pricing_evidence_fingerprint",
    "pricing_valid_until",
    "hcp_organization",
    "hcp_project",
    "hcp_tier",
    "hcp_region",
    "aws_account",
    "terraform_workspace",
    "operator_identity",
    "approver_identity",
    "requested_max_cost_usd",
    "requested_max_runtime_minutes",
    "teardown_reserve_minutes",
    "authorization_expires_at",
    "abort_conditions",
    "audit_smoke_test_contract",
    "preserved_aws_resources",
    "evidence_manifest_reference",
    "request_created_at",
    "request_status",
]

# Fields that must be non-null for pricing verification
REQUIRED_PRICING_EVIDENCE_FIELDS = [
    "source",
    "product_tier_confirmed",
    "region_confirmed",
    "currency",
    "hourly_rate_usd",
    "billing_unit",
    "rate_confirmed_at",
    "rate_valid_until",
    "verifier_identity",
    "fingerprint",
]


# ---------------------------------------------------------------------------
# Condition identifiers
# ---------------------------------------------------------------------------

class Condition:
    """22 fail-closed conditions. All must pass for READY_FOR_HUMAN_DECISION."""

    # C1: Schema completeness
    REQUEST_FILE_EXISTS = "C01_REQUEST_FILE_EXISTS"
    PRICING_FILE_EXISTS = "C02_PRICING_FILE_EXISTS"
    REQUEST_SCHEMA_VALID = "C03_REQUEST_SCHEMA_VALID"
    PRICING_SCHEMA_VALID = "C04_PRICING_SCHEMA_VALID"

    # C2: Source SHA binding
    CANONICAL_SHA_BOUND = "C05_CANONICAL_SHA_BOUND"

    # C3: Pricing evidence
    PRICING_FP001_NOT_OPEN = "C06_PRICING_FP001_NOT_OPEN"
    PRICING_EVIDENCE_POPULATED = "C07_PRICING_EVIDENCE_POPULATED"
    PRICING_NOT_EXPIRED = "C08_PRICING_NOT_EXPIRED"
    PRICING_FINGERPRINT_PRESENT = "C09_PRICING_FINGERPRINT_PRESENT"

    # C4: Financial fields
    MAX_COST_SET = "C10_MAX_COST_SET"
    MAX_RUNTIME_SET = "C11_MAX_RUNTIME_SET"
    TEARDOWN_RESERVE_SET = "C12_TEARDOWN_RESERVE_SET"
    AUTHORIZATION_EXPIRY_SET = "C13_AUTHORIZATION_EXPIRY_SET"

    # C5: Identity fields
    OPERATOR_IDENTITY_SET = "C14_OPERATOR_IDENTITY_SET"
    APPROVER_IDENTITY_SET = "C15_APPROVER_IDENTITY_SET"

    # C6: Infrastructure
    PRESERVED_RESOURCES_COMPLETE = "C16_PRESERVED_RESOURCES_COMPLETE"
    INFRA_FINGERPRINT_PRESENT = "C17_INFRA_FINGERPRINT_PRESENT"

    # C7: Smoke test binding
    SMOKE_TEST_BOUND = "C18_SMOKE_TEST_BOUND"

    # C8: Authorization state
    STATUS_NOT_BLOCKED = "C19_STATUS_NOT_BLOCKED"
    STATUS_NEVER_APPROVED = "C20_STATUS_NEVER_APPROVED"
    HISTORICAL_COST_NOT_USED_AS_CEILING = "C21_HISTORICAL_COST_NOT_USED_AS_CEILING"

    # C9: Canonical truth
    CANONICAL_TRUTH_PRESERVED = "C22_CANONICAL_TRUTH_PRESERVED"

    ALL = [
        REQUEST_FILE_EXISTS,
        PRICING_FILE_EXISTS,
        REQUEST_SCHEMA_VALID,
        PRICING_SCHEMA_VALID,
        CANONICAL_SHA_BOUND,
        PRICING_FP001_NOT_OPEN,
        PRICING_EVIDENCE_POPULATED,
        PRICING_NOT_EXPIRED,
        PRICING_FINGERPRINT_PRESENT,
        MAX_COST_SET,
        MAX_RUNTIME_SET,
        TEARDOWN_RESERVE_SET,
        AUTHORIZATION_EXPIRY_SET,
        OPERATOR_IDENTITY_SET,
        APPROVER_IDENTITY_SET,
        PRESERVED_RESOURCES_COMPLETE,
        INFRA_FINGERPRINT_PRESENT,
        SMOKE_TEST_BOUND,
        STATUS_NOT_BLOCKED,
        STATUS_NEVER_APPROVED,
        HISTORICAL_COST_NOT_USED_AS_CEILING,
        CANONICAL_TRUTH_PRESERVED,
    ]


# ---------------------------------------------------------------------------
# Verification result types
# ---------------------------------------------------------------------------

@dataclass
class ConditionResult:
    id: str
    passed: bool
    detail: str


@dataclass
class CostReviewVerification:
    """Result of the independent cost review verification."""

    generated_at: str
    request_file: str
    pricing_file: str
    conditions: list[ConditionResult] = field(default_factory=list)
    overall_state: str = "BLOCKED"
    blocker_count: int = 0
    blockers: list[str] = field(default_factory=list)

    # Canonical truth — always preserved, never modified by this module
    canonical_truth: dict[str, str] = field(default_factory=lambda: {
        "CUSTOMER_ZERO_TRUST": "NOT_PROVEN",
        "THIRD_PAID_CEREMONY": "NOT_AUTHORIZED",
        "PAID_HCP_INFRASTRUCTURE": "ABSENT",
        "COST_AUTHORIZATION": "NOT_AUTHORIZED",
    })

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "work_item": WORK_ITEM_ID,
            "request_file": self.request_file,
            "pricing_file": self.pricing_file,
            "overall_state": self.overall_state,
            "blocker_count": self.blocker_count,
            "blockers": self.blockers,
            "canonical_truth": self.canonical_truth,
            "conditions": [
                {"id": c.id, "passed": c.passed, "detail": c.detail}
                for c in self.conditions
            ],
        }


# ---------------------------------------------------------------------------
# Individual condition checks
# ---------------------------------------------------------------------------

def _check_file_exists(path: Path, condition_id: str, label: str) -> ConditionResult:
    if path.exists() and path.is_file():
        return ConditionResult(condition_id, True, f"{label} exists: {path}")
    return ConditionResult(condition_id, False, f"{label} not found: {path}")


def _check_request_schema(req: dict) -> ConditionResult:
    missing = [f for f in REQUIRED_REQUEST_FIELDS if f not in req]
    if missing:
        return ConditionResult(
            Condition.REQUEST_SCHEMA_VALID, False,
            f"Missing required fields: {', '.join(missing)}"
        )
    return ConditionResult(Condition.REQUEST_SCHEMA_VALID, True, "All required fields present")


def _check_pricing_schema(pricing: dict) -> ConditionResult:
    evidence = pricing.get("evidence", {})
    if not isinstance(evidence, dict):
        return ConditionResult(
            Condition.PRICING_SCHEMA_VALID, False,
            "pricing.evidence is not a dict"
        )
    missing = [f for f in REQUIRED_PRICING_EVIDENCE_FIELDS if f not in evidence]
    if missing:
        return ConditionResult(
            Condition.PRICING_SCHEMA_VALID, False,
            f"Missing pricing evidence fields: {', '.join(missing)}"
        )
    return ConditionResult(Condition.PRICING_SCHEMA_VALID, True, "Pricing schema is valid")


def _check_canonical_sha(req: dict) -> ConditionResult:
    bound = req.get("canonical_source_sha")
    if bound == CANONICAL_SOURCE_SHA:
        return ConditionResult(
            Condition.CANONICAL_SHA_BOUND, True,
            f"canonical_source_sha correctly bound to {CANONICAL_SOURCE_SHA}"
        )
    return ConditionResult(
        Condition.CANONICAL_SHA_BOUND, False,
        f"canonical_source_sha mismatch: expected {CANONICAL_SOURCE_SHA!r}, got {bound!r}"
    )


def _check_fp001_not_open(pricing: dict, req: dict) -> ConditionResult:
    """FP-001 is open when pricing.fp_001_status == 'OPEN' or request.fp_001_status == 'OPEN'."""
    pricing_open = pricing.get("fp_001_status") == "OPEN"
    req_open = req.get("fp_001_status") == "OPEN"
    req_status = req.get("request_status", "")
    blocked = req_status == "BLOCKED_PRICING_UNVERIFIED"
    if pricing_open or req_open or blocked:
        return ConditionResult(
            Condition.PRICING_FP001_NOT_OPEN, False,
            "FP-001 is OPEN — HCP pricing unverified. Human operator must confirm pricing from HCP portal."
        )
    return ConditionResult(
        Condition.PRICING_FP001_NOT_OPEN, True,
        "FP-001 is not open"
    )


def _check_pricing_evidence_populated(pricing: dict) -> ConditionResult:
    evidence = pricing.get("evidence", {})
    nulls = [f for f in REQUIRED_PRICING_EVIDENCE_FIELDS if evidence.get(f) is None]
    if nulls:
        return ConditionResult(
            Condition.PRICING_EVIDENCE_POPULATED, False,
            f"Pricing evidence fields are null (not yet confirmed): {', '.join(nulls)}"
        )
    return ConditionResult(
        Condition.PRICING_EVIDENCE_POPULATED, True,
        "All required pricing evidence fields are populated"
    )


def _check_pricing_not_expired(pricing: dict) -> ConditionResult:
    evidence = pricing.get("evidence", {})
    valid_until = evidence.get("rate_valid_until")
    if valid_until is None:
        return ConditionResult(
            Condition.PRICING_NOT_EXPIRED, False,
            "rate_valid_until is null — cannot determine pricing validity"
        )
    try:
        expiry = datetime.fromisoformat(valid_until.replace("Z", "+00:00"))
        now = datetime.now(UTC)
        if expiry < now:
            return ConditionResult(
                Condition.PRICING_NOT_EXPIRED, False,
                f"Pricing evidence has expired: {valid_until}"
            )
        return ConditionResult(
            Condition.PRICING_NOT_EXPIRED, True,
            f"Pricing evidence valid until {valid_until}"
        )
    except (ValueError, AttributeError):
        return ConditionResult(
            Condition.PRICING_NOT_EXPIRED, False,
            f"rate_valid_until is not a parseable date: {valid_until!r}"
        )


def _check_pricing_fingerprint(pricing: dict, req: dict) -> ConditionResult:
    evidence_fp = pricing.get("evidence", {}).get("fingerprint")
    req_fp = req.get("pricing_evidence_fingerprint")
    if evidence_fp is None or req_fp is None:
        return ConditionResult(
            Condition.PRICING_FINGERPRINT_PRESENT, False,
            "Pricing evidence fingerprint missing from pricing schema or authorization request"
        )
    if evidence_fp != req_fp:
        return ConditionResult(
            Condition.PRICING_FINGERPRINT_PRESENT, False,
            f"Pricing fingerprint mismatch: pricing has {evidence_fp!r}, request has {req_fp!r}"
        )
    return ConditionResult(
        Condition.PRICING_FINGERPRINT_PRESENT, True,
        f"Pricing fingerprint consistent: {evidence_fp[:16]}..."
    )


def _check_financial_field(req: dict, field_name: str, condition_id: str, label: str) -> ConditionResult:
    val = req.get(field_name)
    if val is None:
        return ConditionResult(condition_id, False, f"{label} is null — human must set")
    if isinstance(val, (int, float)) and val <= 0:
        return ConditionResult(condition_id, False, f"{label} must be > 0, got {val}")
    return ConditionResult(condition_id, True, f"{label} = {val}")


def _check_identity_field(req: dict, field_name: str, condition_id: str, label: str) -> ConditionResult:
    val = req.get(field_name)
    if val is None or str(val).strip() == "":
        return ConditionResult(condition_id, False, f"{label} is null — human must set")
    return ConditionResult(condition_id, True, f"{label} is set")


def _check_preserved_resources(req: dict) -> ConditionResult:
    resources = req.get("preserved_aws_resources", [])
    if not resources:
        return ConditionResult(
            Condition.PRESERVED_RESOURCES_COMPLETE, False,
            "preserved_aws_resources is empty or missing"
        )
    present = frozenset(r.get("address", "") for r in resources)
    missing = EXPECTED_PRESERVED_RESOURCES - present
    extra = present - EXPECTED_PRESERVED_RESOURCES - {""}
    issues = []
    if missing:
        issues.append(f"Missing: {', '.join(sorted(missing))}")
    if extra:
        issues.append(f"Unexpected: {', '.join(sorted(extra))}")
    if issues:
        return ConditionResult(
            Condition.PRESERVED_RESOURCES_COMPLETE, False,
            f"Preserved resources mismatch — {'; '.join(issues)}"
        )
    return ConditionResult(
        Condition.PRESERVED_RESOURCES_COMPLETE, True,
        f"All 6 preserved AWS resources present"
    )


def _check_infra_fingerprint(req: dict) -> ConditionResult:
    fp = req.get("infrastructure_fingerprint")
    if not fp:
        return ConditionResult(
            Condition.INFRA_FINGERPRINT_PRESENT, False,
            "infrastructure_fingerprint is null or missing"
        )
    return ConditionResult(
        Condition.INFRA_FINGERPRINT_PRESENT, True,
        f"infrastructure_fingerprint present: {fp[:16]}..."
    )


def _check_smoke_test_bound(req: dict) -> ConditionResult:
    contract = req.get("audit_smoke_test_contract")
    if not contract or not isinstance(contract, dict):
        return ConditionResult(
            Condition.SMOKE_TEST_BOUND, False,
            "audit_smoke_test_contract is missing or not a dict"
        )
    doc_id = contract.get("document_id")
    ref_file = contract.get("reference_file")
    if doc_id != "SMOKE-TEST-RUN3-001":
        return ConditionResult(
            Condition.SMOKE_TEST_BOUND, False,
            f"audit_smoke_test_contract.document_id expected 'SMOKE-TEST-RUN3-001', got {doc_id!r}"
        )
    if not ref_file:
        return ConditionResult(
            Condition.SMOKE_TEST_BOUND, False,
            "audit_smoke_test_contract.reference_file is missing"
        )
    return ConditionResult(
        Condition.SMOKE_TEST_BOUND, True,
        f"Smoke test contract bound: {doc_id}"
    )


def _check_status_not_blocked(req: dict) -> ConditionResult:
    status = req.get("request_status", "")
    if status == "BLOCKED_PRICING_UNVERIFIED":
        return ConditionResult(
            Condition.STATUS_NOT_BLOCKED, False,
            "request_status is BLOCKED_PRICING_UNVERIFIED — pricing must be confirmed before review"
        )
    if not status:
        return ConditionResult(
            Condition.STATUS_NOT_BLOCKED, False,
            "request_status is missing"
        )
    return ConditionResult(
        Condition.STATUS_NOT_BLOCKED, True,
        f"request_status is {status!r}"
    )


def _check_status_never_approved(req: dict) -> ConditionResult:
    """APPROVED must never appear in any status field — it is not reachable by this module."""
    status = req.get("request_status", "")
    canonical_truth = req.get("canonical_truth_preserved", {})
    cost_auth = canonical_truth.get("COST_AUTHORIZATION", "")
    third_ceremony = canonical_truth.get("THIRD_PAID_CEREMONY", "")
    if "APPROVED" in str(status).upper():
        return ConditionResult(
            Condition.STATUS_NEVER_APPROVED, False,
            f"CRITICAL: request_status contains 'APPROVED' ({status!r}) — this module cannot produce APPROVED"
        )
    if cost_auth == "AUTHORIZED":
        return ConditionResult(
            Condition.STATUS_NEVER_APPROVED, False,
            "CRITICAL: canonical_truth.COST_AUTHORIZATION is AUTHORIZED — this must not be set by this module"
        )
    if third_ceremony == "AUTHORIZED":
        return ConditionResult(
            Condition.STATUS_NEVER_APPROVED, False,
            "CRITICAL: canonical_truth.THIRD_PAID_CEREMONY is AUTHORIZED — this must not be set by this module"
        )
    return ConditionResult(
        Condition.STATUS_NEVER_APPROVED, True,
        "No unauthorized approval state detected"
    )


def _check_historical_cost_not_ceiling(req: dict) -> ConditionResult:
    """The $321.81 historical figure must never appear as requested_max_cost_usd."""
    max_cost = req.get("requested_max_cost_usd")
    if max_cost == 321.81 or max_cost == "321.81":
        return ConditionResult(
            Condition.HISTORICAL_COST_NOT_USED_AS_CEILING, False,
            "requested_max_cost_usd is set to 321.81 (historical Runs 1+2 total) — "
            "this figure is CONSUMED and must not be used as a cost ceiling for Run 3"
        )
    return ConditionResult(
        Condition.HISTORICAL_COST_NOT_USED_AS_CEILING, True,
        "Historical $321.81 figure is not used as cost ceiling"
    )


def _check_canonical_truth(req: dict) -> ConditionResult:
    ct = req.get("canonical_truth_preserved", {})
    expected = {
        "CUSTOMER_ZERO_TRUST": "NOT_PROVEN",
        "THIRD_PAID_CEREMONY": "NOT_AUTHORIZED",
        "PAID_HCP_INFRASTRUCTURE": "ABSENT",
        "COST_AUTHORIZATION": "NOT_AUTHORIZED",
    }
    violations = []
    for key, expected_val in expected.items():
        actual = ct.get(key)
        if actual != expected_val:
            violations.append(f"{key}: expected {expected_val!r}, got {actual!r}")
    if violations:
        return ConditionResult(
            Condition.CANONICAL_TRUTH_PRESERVED, False,
            f"Canonical truth violations: {'; '.join(violations)}"
        )
    return ConditionResult(
        Condition.CANONICAL_TRUTH_PRESERVED, True,
        "All canonical truth invariants preserved"
    )


# ---------------------------------------------------------------------------
# Main verifier
# ---------------------------------------------------------------------------

def verify_cost_review(
    request_path: Path,
    pricing_path: Path,
) -> CostReviewVerification:
    """Run all 22 conditions and return the verification result.

    Fails closed on every condition. APPROVED is never returned.
    """
    result = CostReviewVerification(
        generated_at=datetime.now(UTC).isoformat(),
        request_file=str(request_path),
        pricing_file=str(pricing_path),
    )
    conditions = result.conditions

    # C01 / C02: File existence
    c01 = _check_file_exists(request_path, Condition.REQUEST_FILE_EXISTS, "Authorization request")
    c02 = _check_file_exists(pricing_path, Condition.PRICING_FILE_EXISTS, "Pricing evidence schema")
    conditions.extend([c01, c02])

    # Short-circuit if files don't exist — remaining checks would fail with confusing errors
    if not c01.passed or not c02.passed:
        for cond_id in Condition.ALL[2:]:
            conditions.append(ConditionResult(
                cond_id, False, "Skipped — prerequisite files missing"
            ))
        _finalize(result)
        return result

    # Load files
    try:
        req = json.loads(request_path.read_text())
    except Exception as exc:
        conditions.append(ConditionResult(
            Condition.REQUEST_SCHEMA_VALID, False, f"Failed to parse request JSON: {exc}"
        ))
        for cond_id in Condition.ALL[3:]:
            conditions.append(ConditionResult(cond_id, False, "Skipped — request parse failed"))
        _finalize(result)
        return result

    try:
        pricing = json.loads(pricing_path.read_text())
    except Exception as exc:
        conditions.append(ConditionResult(
            Condition.PRICING_SCHEMA_VALID, False, f"Failed to parse pricing JSON: {exc}"
        ))
        for cond_id in Condition.ALL[4:]:
            conditions.append(ConditionResult(cond_id, False, "Skipped — pricing parse failed"))
        _finalize(result)
        return result

    # C03/C04: Schema validity
    conditions.append(_check_request_schema(req))
    conditions.append(_check_pricing_schema(pricing))

    # C05: Canonical SHA binding
    conditions.append(_check_canonical_sha(req))

    # C06: FP-001 status
    conditions.append(_check_fp001_not_open(pricing, req))

    # C07: Pricing evidence populated
    conditions.append(_check_pricing_evidence_populated(pricing))

    # C08: Pricing not expired
    conditions.append(_check_pricing_not_expired(pricing))

    # C09: Pricing fingerprint
    conditions.append(_check_pricing_fingerprint(pricing, req))

    # C10–C12: Financial fields
    conditions.append(_check_financial_field(
        req, "requested_max_cost_usd",
        Condition.MAX_COST_SET, "requested_max_cost_usd"
    ))
    conditions.append(_check_financial_field(
        req, "requested_max_runtime_minutes",
        Condition.MAX_RUNTIME_SET, "requested_max_runtime_minutes"
    ))
    conditions.append(_check_financial_field(
        req, "teardown_reserve_minutes",
        Condition.TEARDOWN_RESERVE_SET, "teardown_reserve_minutes"
    ))

    # C13: Authorization expiry
    expiry = req.get("authorization_expires_at")
    if not expiry:
        conditions.append(ConditionResult(
            Condition.AUTHORIZATION_EXPIRY_SET, False,
            "authorization_expires_at is null — human approver must set"
        ))
    else:
        conditions.append(ConditionResult(
            Condition.AUTHORIZATION_EXPIRY_SET, True,
            f"authorization_expires_at = {expiry}"
        ))

    # C14–C15: Identity fields
    conditions.append(_check_identity_field(
        req, "operator_identity", Condition.OPERATOR_IDENTITY_SET, "operator_identity"
    ))
    conditions.append(_check_identity_field(
        req, "approver_identity", Condition.APPROVER_IDENTITY_SET, "approver_identity"
    ))

    # C16: Preserved resources
    conditions.append(_check_preserved_resources(req))

    # C17: Infrastructure fingerprint
    conditions.append(_check_infra_fingerprint(req))

    # C18: Smoke test bound
    conditions.append(_check_smoke_test_bound(req))

    # C19: Status not blocked
    conditions.append(_check_status_not_blocked(req))

    # C20: Status never approved (safety check)
    conditions.append(_check_status_never_approved(req))

    # C21: Historical cost not used as ceiling
    conditions.append(_check_historical_cost_not_ceiling(req))

    # C22: Canonical truth
    conditions.append(_check_canonical_truth(req))

    _finalize(result)
    return result


def _finalize(result: CostReviewVerification) -> None:
    """Compute overall state from individual conditions."""
    failed = [c for c in result.conditions if not c.passed]
    result.blocker_count = len(failed)
    result.blockers = [f"{c.id}: {c.detail}" for c in failed]

    if result.blocker_count == 0:
        # All 22 conditions passed — package is ready for human review
        result.overall_state = "READY_FOR_HUMAN_DECISION"
    else:
        result.overall_state = "BLOCKED"

    # SAFETY: APPROVED must NEVER be set here
    if result.overall_state == "APPROVED":
        raise RuntimeError(
            "BUG: customer_zero_cost_review.py produced APPROVED state. "
            "This module MUST NEVER return APPROVED. "
            "This is a critical defect — do not proceed."
        )


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Independent verifier for Customer-Zero Run-3 human cost review package."
    )
    parser.add_argument(
        "--repo", type=Path, default=Path("."),
        help="Path to repository root (default: .)"
    )
    parser.add_argument(
        "--request", type=Path, default=None,
        help="Path to authorization request JSON (default: <repo>/customer_one/run3_cost_authorization_request.json)"
    )
    parser.add_argument(
        "--pricing", type=Path, default=None,
        help="Path to pricing evidence schema JSON (default: <repo>/customer_one/run3_pricing_evidence_schema.json)"
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Output machine-readable JSON"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    repo = args.repo.resolve()

    request_path = args.request or (repo / "customer_one" / "run3_cost_authorization_request.json")
    pricing_path = args.pricing or (repo / "customer_one" / "run3_pricing_evidence_schema.json")

    result = verify_cost_review(request_path, pricing_path)

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        _print_human(result)

    # Exit 0 only when READY_FOR_HUMAN_DECISION
    return 0 if result.overall_state == "READY_FOR_HUMAN_DECISION" else 1


def _print_human(result: CostReviewVerification) -> None:
    print(f"\n{'=' * 70}")
    print(f"  Cost Review Verification — {WORK_ITEM_ID}")
    print(f"{'=' * 70}")
    print(f"  Generated:    {result.generated_at}")
    print(f"  Request:      {result.request_file}")
    print(f"  Pricing:      {result.pricing_file}")
    print(f"  Overall:      {result.overall_state}")
    print(f"  Blockers:     {result.blocker_count}")
    print()

    for cond in result.conditions:
        mark = "PASS" if cond.passed else "FAIL"
        print(f"  [{mark}] {cond.id}")
        if not cond.passed:
            print(f"         {cond.detail}")

    if result.blockers:
        print()
        print("  BLOCKERS:")
        for b in result.blockers:
            print(f"    - {b}")

    print()
    print("  Canonical truth:")
    for k, v in result.canonical_truth.items():
        print(f"    {k} = {v}")
    print(f"{'=' * 70}\n")


if __name__ == "__main__":
    sys.exit(main())
