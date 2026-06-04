"""Deterministic Third-Party AI Governance Engine (PR 4).

Not standalone. This module is not standalone. It requires the fg-core API,
auth layer, and Postgres substrate.

Consumes PR 1 (AI Tool Discovery), PR 2 (AI Data Access Mapping), and
PR 3 (External AI Risk Register) evidence to generate:

  - FaAiVendorGovernanceRecord entries — one per (tenant, engagement, tool)
  - Governance findings — 16 finding types mapped to NIST AI RMF controls
  - Governance readiness score — deterministic, no LLM
  - Executive dashboard summary — build_summary()

All outputs are deterministic. No AI scoring. No LLM calls. No speculative values.
Every governance record traces back to PR1/PR2/PR3 scan evidence.

Governance readiness rules:
  complete  — both owners set + security review done + DPA/BAA resolved +
               risk acceptance resolved + review not overdue
  partial   — at least one owner + some evidence present, not all complete criteria met
  minimal   — at least one owner, most governance gaps present
  unknown   — no owner set (both null/"Unknown")

Finding generation:
  16 finding types (see _FINDING_NIST_MAP)
  generated only for high/critical risk tools, with exceptions for shadow AI
  (always generated regardless of risk score)
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

from services.connectors.ai_vendor_governance.state_machine import (
    determine_initial_state,
)

GOVERNANCE_ENGINE_VERSION = "ai-vendor-governance-engine-v1"
SCHEMA_VERSION = "1.0"

# ---------------------------------------------------------------------------
# Finding type → NIST AI RMF control mappings
# ---------------------------------------------------------------------------

_FINDING_NIST_MAP: dict[str, list[dict[str, str]]] = {
    "ai_vendor_governance.no_business_owner": [
        {"framework": "NIST-AI-RMF", "control": "GOVERN 1.1"},
        {"framework": "NIST-AI-RMF", "control": "GOVERN 1.2"},
    ],
    "ai_vendor_governance.no_technical_owner": [
        {"framework": "NIST-AI-RMF", "control": "GOVERN 1.1"},
    ],
    "ai_vendor_governance.no_executive_sponsor": [
        {"framework": "NIST-AI-RMF", "control": "GOVERN 1.2"},
    ],
    "ai_vendor_governance.no_security_review": [
        {"framework": "NIST-AI-RMF", "control": "GOVERN 6.2"},
        {"framework": "NIST-AI-RMF", "control": "MAP 1.1"},
    ],
    "ai_vendor_governance.no_privacy_review": [
        {"framework": "NIST-AI-RMF", "control": "GOVERN 6.2"},
    ],
    "ai_vendor_governance.no_dpa": [
        {"framework": "NIST-AI-RMF", "control": "GOVERN 6.2"},
        {"framework": "NIST-AI-RMF", "control": "MAP 1.1"},
    ],
    "ai_vendor_governance.no_baa": [
        {"framework": "NIST-AI-RMF", "control": "GOVERN 6.2"},
    ],
    "ai_vendor_governance.no_contract": [
        {"framework": "NIST-AI-RMF", "control": "GOVERN 1.3"},
    ],
    "ai_vendor_governance.no_soc2_evidence": [
        {"framework": "NIST-AI-RMF", "control": "MAP 1.1"},
    ],
    "ai_vendor_governance.no_iso27001_evidence": [
        {"framework": "NIST-AI-RMF", "control": "MAP 1.1"},
    ],
    "ai_vendor_governance.review_overdue": [
        {"framework": "NIST-AI-RMF", "control": "GOVERN 1.3"},
        {"framework": "NIST-AI-RMF", "control": "GOVERN 6.1"},
    ],
    "ai_vendor_governance.risk_acceptance_expired": [
        {"framework": "NIST-AI-RMF", "control": "MANAGE 2.2"},
    ],
    "ai_vendor_governance.restricted_still_active": [
        {"framework": "NIST-AI-RMF", "control": "MANAGE 2.2"},
        {"framework": "NIST-AI-RMF", "control": "MANAGE 2.4"},
    ],
    "ai_vendor_governance.rejected_still_active": [
        {"framework": "NIST-AI-RMF", "control": "MANAGE 2.2"},
        {"framework": "NIST-AI-RMF", "control": "MANAGE 2.4"},
    ],
    "ai_vendor_governance.exception_expired": [
        {"framework": "NIST-AI-RMF", "control": "GOVERN 1.4"},
    ],
    "ai_vendor_governance.shadow_ai_unreviewed": [
        {"framework": "NIST-AI-RMF", "control": "GOVERN 1.1"},
        {"framework": "NIST-AI-RMF", "control": "MAP 1.1"},
    ],
}

_FINDING_SEVERITY: dict[str, str] = {
    "ai_vendor_governance.no_business_owner": "high",
    "ai_vendor_governance.no_technical_owner": "high",
    "ai_vendor_governance.no_executive_sponsor": "moderate",
    "ai_vendor_governance.no_security_review": "high",
    "ai_vendor_governance.no_privacy_review": "high",
    "ai_vendor_governance.no_dpa": "critical",
    "ai_vendor_governance.no_baa": "critical",
    "ai_vendor_governance.no_contract": "moderate",
    "ai_vendor_governance.no_soc2_evidence": "moderate",
    "ai_vendor_governance.no_iso27001_evidence": "low",
    "ai_vendor_governance.review_overdue": "high",
    "ai_vendor_governance.risk_acceptance_expired": "critical",
    "ai_vendor_governance.restricted_still_active": "high",
    "ai_vendor_governance.rejected_still_active": "critical",
    "ai_vendor_governance.exception_expired": "critical",
    "ai_vendor_governance.shadow_ai_unreviewed": "high",
}

_FINDING_TITLES: dict[str, str] = {
    "ai_vendor_governance.no_business_owner": "No Business Owner Assigned",
    "ai_vendor_governance.no_technical_owner": "No Technical Owner Assigned",
    "ai_vendor_governance.no_executive_sponsor": "No Executive Sponsor Assigned",
    "ai_vendor_governance.no_security_review": "Security Review Not Completed",
    "ai_vendor_governance.no_privacy_review": "Privacy Review Not Completed",
    "ai_vendor_governance.no_dpa": "Data Processing Agreement Missing",
    "ai_vendor_governance.no_baa": "Business Associate Agreement Missing",
    "ai_vendor_governance.no_contract": "No Vendor Contract on File",
    "ai_vendor_governance.no_soc2_evidence": "SOC 2 Evidence Not Available",
    "ai_vendor_governance.no_iso27001_evidence": "ISO 27001 Evidence Not Available",
    "ai_vendor_governance.review_overdue": "Governance Review Overdue",
    "ai_vendor_governance.risk_acceptance_expired": "Risk Acceptance Has Expired",
    "ai_vendor_governance.restricted_still_active": "Restricted Vendor Remains Active",
    "ai_vendor_governance.rejected_still_active": "Rejected Vendor Remains Active",
    "ai_vendor_governance.exception_expired": "Governance Exception Has Expired",
    "ai_vendor_governance.shadow_ai_unreviewed": "Shadow AI Remains Unreviewed",
}

_FINDING_RECOMMENDATIONS: dict[str, str] = {
    "ai_vendor_governance.no_business_owner": (
        "Assign a business owner responsible for approving and reviewing this AI tool's "
        "use within business processes."
    ),
    "ai_vendor_governance.no_technical_owner": (
        "Assign a technical owner responsible for the security posture and integration "
        "of this AI tool."
    ),
    "ai_vendor_governance.no_executive_sponsor": (
        "Designate an executive sponsor to provide organizational accountability for "
        "this AI tool's governance."
    ),
    "ai_vendor_governance.no_security_review": (
        "Complete a security review assessing the vendor's security controls, data "
        "handling, and incident response capabilities."
    ),
    "ai_vendor_governance.no_privacy_review": (
        "Complete a privacy review assessing data collection, retention, and processing "
        "practices relative to applicable privacy regulations."
    ),
    "ai_vendor_governance.no_dpa": (
        "Execute a Data Processing Agreement with this vendor before allowing continued "
        "processing of organizational data."
    ),
    "ai_vendor_governance.no_baa": (
        "Execute a Business Associate Agreement before allowing this vendor to process "
        "any protected health information."
    ),
    "ai_vendor_governance.no_contract": (
        "Establish a formal vendor contract defining SLAs, data rights, liability, "
        "and termination conditions."
    ),
    "ai_vendor_governance.no_soc2_evidence": (
        "Request and review the vendor's SOC 2 Type II report to assess controls "
        "over security, availability, and confidentiality."
    ),
    "ai_vendor_governance.no_iso27001_evidence": (
        "Request ISO 27001 certification evidence or equivalent third-party assurance "
        "from the vendor."
    ),
    "ai_vendor_governance.review_overdue": (
        "Schedule and complete an overdue governance review. Update review_due_date "
        "and last_review_date upon completion."
    ),
    "ai_vendor_governance.risk_acceptance_expired": (
        "Re-evaluate and renew the risk acceptance decision for this vendor. Update "
        "risk_acceptance_expiration after review."
    ),
    "ai_vendor_governance.restricted_still_active": (
        "Verify that usage restrictions are being enforced. Complete a re-review to "
        "determine whether restrictions can be lifted or usage should be rejected."
    ),
    "ai_vendor_governance.rejected_still_active": (
        "Immediately disable or block access to this vendor tool. Rejected vendors "
        "must not remain active in the environment."
    ),
    "ai_vendor_governance.exception_expired": (
        "Review the expired governance exception. Either renew the exception with a "
        "new expiration date and justification, or transition the vendor to rejected."
    ),
    "ai_vendor_governance.shadow_ai_unreviewed": (
        "Initiate a governance review for this unreviewed shadow AI tool. Assign an "
        "owner and complete the formal review process."
    ),
}


# ---------------------------------------------------------------------------
# Governance readiness
# ---------------------------------------------------------------------------


def _owner_set(v: str | None) -> bool:
    return v is not None and v.strip().lower() not in ("unknown", "")


def _is_date_overdue(date_str: str | None, now: datetime) -> bool:
    if not date_str:
        return False
    try:
        due = datetime.fromisoformat(date_str.rstrip("Z")).replace(tzinfo=timezone.utc)
        return due < now
    except (ValueError, TypeError):
        return False


def compute_governance_readiness(record: dict[str, Any]) -> str:
    """Compute governance_readiness deterministically from record fields.

    This function is called by both the engine (at generation) and the
    bridge (after upsert) to ensure the stored value stays current.
    """
    has_business_owner = _owner_set(record.get("business_owner"))
    has_technical_owner = _owner_set(record.get("technical_owner"))
    has_any_owner = has_business_owner or has_technical_owner

    if not has_any_owner:
        return "unknown"

    security_ok = record.get("security_review_status") in (
        "completed",
        "not_required",
    )
    dpa_required = record.get("dpa_required", False)
    dpa_ok = (
        record.get("dpa_status") in ("executed", "not_required") or not dpa_required
    )
    baa_required = record.get("baa_required", False)
    baa_ok = (
        record.get("baa_status") in ("executed", "not_required") or not baa_required
    )
    risk_acc_required = record.get("risk_acceptance_required", False)
    risk_acc_ok = (
        record.get("risk_acceptance_status") in ("accepted", "not_required")
        or not risk_acc_required
    )

    now = datetime.now(tz=timezone.utc)
    review_overdue = _is_date_overdue(record.get("review_due_date"), now)

    if (
        has_business_owner
        and has_technical_owner
        and security_ok
        and dpa_ok
        and baa_ok
        and risk_acc_ok
        and not review_overdue
    ):
        return "complete"

    # partial: both owners OR one owner + at least one reviewed item
    if has_business_owner and has_technical_owner:
        return "partial"

    reviewed_count = sum(
        [
            security_ok,
            dpa_ok and dpa_required,
            baa_ok and baa_required,
        ]
    )
    if has_any_owner and reviewed_count >= 1:
        return "partial"

    if has_any_owner:
        return "minimal"

    return "unknown"


# ---------------------------------------------------------------------------
# Finding generation
# ---------------------------------------------------------------------------


def _should_generate_findings(risk_score: str, risk_categories: list[str]) -> bool:
    """Generate findings for high/critical tools, or always for shadow AI."""
    if risk_score in ("high", "critical"):
        return True
    if "shadow_ai" in risk_categories:
        return True
    return False


def generate_findings(
    record: dict[str, Any],
    now_str: str,
) -> list[dict[str, Any]]:
    """Generate governance findings for a single governance record.

    Returns a list of finding dicts matching the create_finding() call shape.
    Only called for high/critical risk tools or shadow AI (per PR3 pattern).
    """
    risk_score = record.get("risk_score", "unknown")
    risk_categories = record.get("risk_categories", [])
    workflow_state = record.get("workflow_state", "discovered")
    tool_name = record.get("tool_name", "")
    vendor = record.get("vendor", "")

    if not _should_generate_findings(risk_score, risk_categories):
        return []

    findings: list[dict[str, Any]] = []
    now = datetime.now(tz=timezone.utc)

    def _f(finding_type: str, description: str) -> dict[str, Any]:
        nist = _FINDING_NIST_MAP.get(finding_type, [])
        return {
            "type": finding_type,
            "title": f"{_FINDING_TITLES[finding_type]}: {tool_name}",
            "description": description,
            "severity": _FINDING_SEVERITY[finding_type],
            "recommendation": _FINDING_RECOMMENDATIONS[finding_type],
            "nist_controls": nist,
            "vendor": vendor,
            "tool_name": tool_name,
        }

    if not _owner_set(record.get("business_owner")):
        findings.append(
            _f(
                "ai_vendor_governance.no_business_owner",
                f"{tool_name} has no business owner assigned. "
                "No organizational accountability exists for this AI tool.",
            )
        )

    if not _owner_set(record.get("technical_owner")):
        findings.append(
            _f(
                "ai_vendor_governance.no_technical_owner",
                f"{tool_name} has no technical owner assigned. "
                "Security posture and integration risk are unowned.",
            )
        )

    if not _owner_set(record.get("executive_sponsor")):
        findings.append(
            _f(
                "ai_vendor_governance.no_executive_sponsor",
                f"{tool_name} has no executive sponsor. "
                "Organizational risk accountability is incomplete.",
            )
        )

    if record.get("security_review_status") in ("not_started", "unknown", None):
        findings.append(
            _f(
                "ai_vendor_governance.no_security_review",
                f"No security review has been completed for {vendor} ({tool_name}). "
                "Vendor security controls are unvalidated.",
            )
        )

    if record.get("privacy_review_status") in ("not_started", "unknown", None):
        findings.append(
            _f(
                "ai_vendor_governance.no_privacy_review",
                f"No privacy review has been completed for {vendor} ({tool_name}). "
                "Data collection and retention practices are unverified.",
            )
        )

    dpa_required = record.get("dpa_required", False)
    regulated = record.get("regulated_data_present", False)
    if (dpa_required or regulated) and record.get("dpa_status") not in (
        "executed",
        "not_required",
    ):
        findings.append(
            _f(
                "ai_vendor_governance.no_dpa",
                f"{vendor} ({tool_name}) processes regulated data but no Data "
                "Processing Agreement is in place.",
            )
        )

    baa_required = record.get("baa_required", False)
    if baa_required and record.get("baa_status") not in ("executed", "not_required"):
        findings.append(
            _f(
                "ai_vendor_governance.no_baa",
                f"{vendor} ({tool_name}) requires a Business Associate Agreement "
                "but none is executed.",
            )
        )

    if record.get("contract_status") in ("none", "unknown", None):
        findings.append(
            _f(
                "ai_vendor_governance.no_contract",
                f"No formal vendor contract is on file for {vendor} ({tool_name}).",
            )
        )

    if not record.get("soc2_available") and not record.get("soc2_reviewed"):
        findings.append(
            _f(
                "ai_vendor_governance.no_soc2_evidence",
                f"No SOC 2 report is available or has been reviewed for {vendor}.",
            )
        )

    if not record.get("iso27001_available") and not record.get("iso27001_reviewed"):
        findings.append(
            _f(
                "ai_vendor_governance.no_iso27001_evidence",
                f"No ISO 27001 certification evidence is available for {vendor}.",
            )
        )

    if _is_date_overdue(record.get("review_due_date"), now):
        findings.append(
            _f(
                "ai_vendor_governance.review_overdue",
                f"The governance review for {tool_name} is overdue "
                f"(due: {record.get('review_due_date')}).",
            )
        )

    if record.get("risk_acceptance_required") and _is_date_overdue(
        record.get("risk_acceptance_expiration"), now
    ):
        findings.append(
            _f(
                "ai_vendor_governance.risk_acceptance_expired",
                f"The risk acceptance for {tool_name} has expired "
                f"(expiration: {record.get('risk_acceptance_expiration')}).",
            )
        )

    if workflow_state == "restricted":
        findings.append(
            _f(
                "ai_vendor_governance.restricted_still_active",
                f"{tool_name} is marked as restricted but remains active. "
                "Verify that usage restrictions are being enforced.",
            )
        )

    if workflow_state == "rejected":
        findings.append(
            _f(
                "ai_vendor_governance.rejected_still_active",
                f"{tool_name} has been rejected but may still be active. "
                "Immediately disable access.",
            )
        )

    if workflow_state == "exception_granted" and _is_date_overdue(
        record.get("risk_acceptance_expiration"), now
    ):
        findings.append(
            _f(
                "ai_vendor_governance.exception_expired",
                f"The governance exception for {tool_name} has expired. "
                "Renew or transition to rejected.",
            )
        )

    is_shadow = "shadow_ai" in risk_categories
    if is_shadow and workflow_state in ("discovered", "needs_owner"):
        findings.append(
            _f(
                "ai_vendor_governance.shadow_ai_unreviewed",
                f"{tool_name} is identified as shadow AI (unconfirmed/unsanctioned) "
                "and has not entered the formal governance review process.",
            )
        )

    return findings


# ---------------------------------------------------------------------------
# Record generation
# ---------------------------------------------------------------------------


def _derive_record_id(tenant_id: str, engagement_id: str, tool_name: str) -> str:
    raw = f"{tenant_id}:{engagement_id}:{tool_name}"
    return hashlib.sha256(raw.encode()).hexdigest()[:64]


def _derive_node_id(prefix: str, tenant_id: str, record_id: str) -> str:
    return f"{prefix}:{tenant_id}:{record_id}"


def generate_governance_records(
    risk_records: list[dict[str, Any]],
    *,
    tenant_id: str,
    engagement_id: str,
    pr1_scan_result_id: str | None,
    pr2_scan_result_id: str | None,
    pr3_scan_result_id: str | None,
    now_str: str,
) -> list[dict[str, Any]]:
    """Generate one governance record dict per risk record.

    Deterministic: same inputs always produce same output.
    All governance evidence fields default to unknown/empty — operators
    populate them via PATCH after generation.
    """
    records = []
    for rr in risk_records:
        tool_name = str(rr.get("tool_name") or "")
        vendor = str(rr.get("vendor") or "")
        risk_score = str(rr.get("risk_score") or "unknown")
        risk_categories = list(rr.get("risk_categories") or [])
        regulatory_flags = list(rr.get("regulatory_flags") or [])

        business_owner = rr.get("business_owner") or None
        technical_owner = rr.get("technical_owner") or None
        # Treat PR3 default "Unknown" as absent for initial state
        if business_owner and business_owner.strip().lower() == "unknown":
            business_owner = None
        if technical_owner and technical_owner.strip().lower() == "unknown":
            technical_owner = None

        record_id = _derive_record_id(tenant_id, engagement_id, tool_name)
        initial_state = determine_initial_state(business_owner, technical_owner)

        record: dict[str, Any] = {
            "id": record_id,
            "tenant_id": tenant_id,
            "engagement_id": engagement_id,
            "vendor": vendor,
            "tool_name": tool_name,
            "tool_id": rr.get("tool_id"),
            "target_type": "ai_tool",
            "workflow_state": initial_state,
            # Ownership — seeded from PR3, will be None if PR3 had "Unknown"
            "business_owner": business_owner,
            "technical_owner": technical_owner,
            "executive_sponsor": None,
            # Business context — empty at generation
            "business_justification": None,
            "business_process": None,
            "department": None,
            "criticality": "unknown",
            # Data governance — seeded from PR3 evidence
            "data_processed": list(rr.get("permissions") or []),
            "sensitive_data_types": list(rr.get("sensitive_data_exposure") or []),
            "regulated_data_present": len(list(rr.get("sensitive_data_exposure") or []))
            > 0,
            "data_residency_notes": None,
            # Contract governance
            "contract_status": "unknown",
            "contract_owner": None,
            "contract_expiration": None,
            "renewal_date": None,
            # DPA
            "dpa_required": False,
            "dpa_status": "unknown",
            "dpa_review_date": None,
            # BAA
            "baa_required": False,
            "baa_status": "unknown",
            "baa_review_date": None,
            # Security
            "security_review_status": "not_started",
            "security_review_date": None,
            "security_reviewer": None,
            # Privacy
            "privacy_review_status": "not_started",
            "privacy_review_date": None,
            "privacy_reviewer": None,
            # Compliance evidence
            "soc2_available": False,
            "soc2_reviewed": False,
            "soc2_review_date": None,
            "iso27001_available": False,
            "iso27001_reviewed": False,
            "iso_review_date": None,
            # Risk governance
            "risk_acceptance_required": risk_score in ("high", "critical"),
            "risk_acceptance_status": "unknown",
            "risk_acceptance_owner": None,
            "risk_acceptance_expiration": None,
            # Lifecycle
            "review_due_date": None,
            "last_review_date": None,
            "renewal_due_date": None,
            "retirement_date": None,
            # Governance readiness — computed below
            "governance_readiness": "unknown",
            # Source cross-references
            "pr1_scan_result_id": pr1_scan_result_id,
            "pr2_scan_result_id": pr2_scan_result_id,
            "pr3_risk_record_id": rr.get("id"),
            "risk_score": risk_score,
            "risk_categories": risk_categories,
            "regulatory_flags": regulatory_flags,
            # Evidence / finding refs
            "evidence_refs": [
                r
                for r in [pr1_scan_result_id, pr2_scan_result_id, pr3_scan_result_id]
                if r
            ],
            "finding_refs": [],
            # Graph node IDs
            "graph_node_id": _derive_node_id(
                "ai_vendor_governance", tenant_id, record_id
            ),
            "vendor_node_id": _derive_node_id(
                "vendor", tenant_id, vendor.lower().replace(" ", "_")
            ),
            "owner_node_id": _derive_node_id("owner", tenant_id, record_id),
            "contract_node_id": _derive_node_id("contract", tenant_id, record_id),
            "evidence_node_id": _derive_node_id("evidence", tenant_id, record_id),
            "decision_node_id": _derive_node_id("decision", tenant_id, record_id),
            "governance_node_id": _derive_node_id("governance", tenant_id, record_id),
            # Source
            "source_scan_result_id": pr3_scan_result_id,
            # Timestamps
            "created_at": now_str,
            "updated_at": now_str,
            "last_reviewed_at": None,
        }

        record["governance_readiness"] = compute_governance_readiness(record)
        records.append(record)

    # Deterministic ordering: critical → high → moderate → low, then alpha
    _score_order = {"critical": 0, "high": 1, "moderate": 2, "low": 3, "unknown": 4}
    records.sort(
        key=lambda r: (
            _score_order.get(r["risk_score"], 4),
            r["tool_name"].lower(),
        )
    )
    return records


# ---------------------------------------------------------------------------
# Summary / dashboard metrics
# ---------------------------------------------------------------------------


def build_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute executive dashboard metrics from governance records.

    Deterministic: no external I/O.
    """
    from collections import Counter

    now = datetime.now(tz=timezone.utc)

    state_counts: Counter[str] = Counter()
    readiness_counts: Counter[str] = Counter()
    criticality_counts: Counter[str] = Counter()

    needs_owner = 0
    needs_review = 0
    overdue_review = 0
    expiring_renewals_30d = 0
    rejected_count = 0
    restricted_count = 0
    exception_count = 0
    no_dpa = 0
    no_baa = 0
    no_contract = 0
    no_security_review = 0

    for r in records:
        state = r.get("workflow_state", "discovered")
        readiness = r.get("governance_readiness", "unknown")
        criticality = r.get("criticality", "unknown")

        state_counts[state] += 1
        readiness_counts[readiness] += 1
        criticality_counts[criticality] += 1

        if state == "needs_owner":
            needs_owner += 1
        if state == "needs_review":
            needs_review += 1
        if state == "rejected":
            rejected_count += 1
        if state == "restricted":
            restricted_count += 1
        if state == "exception_granted":
            exception_count += 1

        if _is_date_overdue(r.get("review_due_date"), now):
            overdue_review += 1

        # Expiring renewals within 30 days
        renewal = r.get("renewal_due_date")
        if renewal and not _is_date_overdue(renewal, now):
            try:
                rd = datetime.fromisoformat(renewal.rstrip("Z")).replace(
                    tzinfo=timezone.utc
                )
                delta = (rd - now).days
                if 0 <= delta <= 30:
                    expiring_renewals_30d += 1
            except (ValueError, TypeError):
                pass

        dpa_required = r.get("dpa_required", False)
        regulated = r.get("regulated_data_present", False)
        if (dpa_required or regulated) and r.get("dpa_status") not in (
            "executed",
            "not_required",
        ):
            no_dpa += 1

        if r.get("baa_required") and r.get("baa_status") not in (
            "executed",
            "not_required",
        ):
            no_baa += 1

        if r.get("contract_status") in ("none", "unknown", None):
            no_contract += 1

        if r.get("security_review_status") in ("not_started", "unknown", None):
            no_security_review += 1

    return {
        "total_vendors": len(records),
        "workflow_distribution": dict(state_counts),
        "readiness_distribution": dict(readiness_counts),
        "criticality_distribution": dict(criticality_counts),
        "needs_owner_count": needs_owner,
        "needs_review_count": needs_review,
        "overdue_review_count": overdue_review,
        "expiring_renewals_30d": expiring_renewals_30d,
        "rejected_count": rejected_count,
        "restricted_count": restricted_count,
        "exception_count": exception_count,
        "no_dpa_count": no_dpa,
        "no_baa_count": no_baa,
        "no_contract_count": no_contract,
        "no_security_review_count": no_security_review,
    }
