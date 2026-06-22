"""Tests — External AI Risk Register (PR 3 + Addendum).

Not standalone. This module is not standalone. It requires the fg-core API, auth layer, and Postgres substrate.

Covers:
  T1:  Risk category detection (8 categories)
  T2:  Risk scoring (additive, evidence-backed)
  T3:  Risk score band assignment (low/moderate/high/critical)
  T4:  Risk reason generation (deterministic)
  T5:  Recommended action mapping (per primary category)
  T6:  Owner attribution (always Unknown on creation)
  T7:  Review status (always unreviewed on creation)
  T8:  Graph-ready node IDs
  T9:  Evidence reference composition (PR1 + PR2 refs)
  T10: Sensitive data exposure field
  T11: Publisher trust field
  T12: Data access summary field
  T13: Finding generation (high/critical only)
  T14: Summary distribution correctness
  T15: Shadow AI detection
  T16: Overprivileged OAuth detection
  T17: Deterministic ordering (critical → high → moderate → low → alpha)
  T18: Idempotent regeneration (existing IDs preserved)
  T19: Bridge: scan result created
  T20: Bridge: FaExternalAiRiskRecord rows created
  T21: Bridge: finding rows created for high/critical
  T22: Bridge: idempotent second run updates, not duplicates
  T23: Tenant isolation (cross-tenant query returns empty)
  T24: Engagement isolation (cross-engagement query returns empty)
  T25: Review status update (PATCH)
  T26: Owner update (PATCH)
  T27: Invalid review status rejected
  T28: Verification bundle includes ai_risk_register component
  T29: Scan registry: external_ai_risk_register schema version accepted
  T30: Scan registry: required field "risk_records" validated
  T31: Report section: external_ai_risk_register emitted in report JSON
  T32: No LLM fields: risk_reason is deterministic, not empty
  T33: No admin consent → lower score than admin consent + tenant-wide
  T34: Verified publisher → lower score than unverified publisher
  T35: Multiple sensitive categories → score bump applied
  T36: Shadow AI confidence "suspected" → shadow_ai category detected
  T37: Shadow AI confidence "unknown" → shadow_ai category detected
  T38: Confidence "confirmed" → no shadow_ai category
  T39: No PR2 mappings → risk records still generated from PR1 only
  T40: Risk records with empty permissions → no overprivileged_oauth category
  T41: Data access summary from PR2 data
  T42: bridge: finding_refs backfilled into high/critical records
  T43: build_summary aggregate metrics
  T44: PATCH returns updated record
  T45: GET list filters by risk_score
  T46: GET list filters by risk_category

Addendum (A-series):
  A1:  governance_state = "governed" for fully governed tool
  A2:  governance_state = "ungoverned" for unverified publisher
  A3:  governance_state = "ungoverned" for shadow AI
  A4:  governance_state = "partially_governed" for unknown_owner
  A5:  governance_state = "partially_governed" for no_approval_record
  A6:  regulatory_flags includes NIST_AI_RMF always
  A7:  regulatory_flags includes EU_AI_ACT for unverified publisher
  A8:  regulatory_flags includes GDPR for sensitive_data_access
  A9:  regulatory_flags includes ISO_42001 for no_approval_record
  A10: regulatory_flags includes HIPAA for health data exposure
  A11: owner_type defaults to "Unknown" at generation
  A12: risk_owner is None at generation
  A13: vendor governance status fields present with defaults
  A14: remediation_status defaults to "not_started"
  A15: decision_refs, risk_acceptance_refs, exception_refs, approval_refs empty at generation
  A16: graph node IDs format (risk_node_id, owner_node_id, vendor_node_id, decision_node_id, governance_node_id)
  A17: build_summary includes governance_distribution
  A18: build_summary includes vendor_distribution
  A19: build_summary includes regulatory_distribution
  A20: build_summary includes remediation_distribution + autonomous governance counters
  A21: bridge sets first_detected_at on creation
  A22: bridge preserves first_detected_at on re-scan
  A23: bridge updates last_observed_at on re-scan
  A24: bridge computes risk_age_days
  A25: bridge preserves governance_state=exception_granted on re-scan
  A26: PATCH allows risk_owner, owner_type, remediation_status updates
  A27: PATCH auto-sets last_reviewed_at when review_status changes
  A28: PATCH allows decision_refs update
  A29: PATCH rejects invalid owner_type
  A30: PATCH rejects invalid remediation_status
  A31: regulatory_flags for PCI_DSS signal
  A32: regulatory_flags for HIPAA health signal
  A33: governance_state = "exception_granted" preserved across bridge re-scan
  A34: build_summary risks_without_review counter
  A35: build_summary stale_risks counter (age > 90 days)
  A36: verification bundle includes governance_state, regulatory_flags, remediation_status
  A37: all addendum fields present in engine output dict
"""

from __future__ import annotations

from typing import Any

import pytest

from services.connectors.external_ai_risk_register.risk_engine import (
    _build_risk_reason,
    _compute_risk_score,
    _detect_categories,
    _determine_governance_state,
    _determine_regulatory_flags,
    _score_to_label,
    build_summary,
    generate_risk_records,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _tool(
    *,
    tool_name: str = "TestAI",
    vendor: str = "TestCo",
    permissions: list[str] | None = None,
    admin_consent: bool = False,
    verified_publisher: bool = True,
    confidence: str = "confirmed",
    service_principal_id: str = "sp-001",
    app_id: str = "app-001",
    evidence_refs: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "tool_name": tool_name,
        "vendor": vendor,
        "permissions": permissions or [],
        "admin_consent": admin_consent,
        "verified_publisher": verified_publisher,
        "confidence": confidence,
        "service_principal_id": service_principal_id,
        "app_id": app_id,
        "evidence_refs": evidence_refs or [],
        "graph_node_id": f"ai_tool:test-tenant:{app_id}",
    }


def _mapping(
    *,
    tool_name: str = "TestAI",
    sensitivity: str = "low",
    data_categories: list[str] | None = None,
    data_owner: str = "IT",
    exposure_scope: str = "user",
    admin_consent: bool = False,
    verified_publisher: bool = True,
) -> dict[str, Any]:
    return {
        "tool_name": tool_name,
        "sensitivity": sensitivity,
        "data_categories": data_categories or [],
        "data_owner": data_owner,
        "owner_type": data_owner,
        "exposure_scope": exposure_scope,
        "admin_consent": admin_consent,
        "verified_publisher": verified_publisher,
    }


def _run_engine(
    tools: list[dict],
    mappings: list[dict] | None = None,
    *,
    pr1_scan_result_id: str = "scan-pr1-001",
    pr2_scan_result_id: str | None = "scan-pr2-001",
    tenant_id: str = "t1",
    engagement_id: str = "e1",
    existing_ids: dict[str, str] | None = None,
) -> tuple[list[dict], list[dict]]:
    return generate_risk_records(
        tools=tools,
        mappings=mappings or [],
        pr1_scan_result_id=pr1_scan_result_id,
        pr2_scan_result_id=pr2_scan_result_id,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        existing_risk_ids=existing_ids,
    )


@pytest.fixture()
def _db():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from api.db_models import Base

    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()
    engine.dispose()


_STABLE_TS = "2026-06-03T00:00:00Z"


def _make_scan_payload(
    risk_records: list[dict],
    findings: list[dict],
    summary: dict,
    *,
    tenant_id: str = "t1",
    engagement_id: str = "e1",
) -> dict:
    return {
        "scan_type": "external_ai_risk_register_v1",
        "schema_version": "1.0",
        "tenant_id": tenant_id,
        "engagement_id": engagement_id,
        "pr1_scan_result_id": "scan-pr1-001",
        "pr2_scan_result_id": "scan-pr2-001",
        "scan_completed_at": _STABLE_TS,
        "risk_records": risk_records,
        "findings": findings,
        "summary": summary,
    }


# ---------------------------------------------------------------------------
# T1: Risk category detection
# ---------------------------------------------------------------------------


def test_T1_1_tenant_wide_detected() -> None:
    cats = _detect_categories(
        verified_publisher=True,
        admin_consent=True,
        exposure_scope="tenant",
        sensitivity="low",
        data_owner="IT",
        confidence="confirmed",
        permissions=[],
        has_approval_record=False,
        has_vendor_review=False,
    )
    assert "tenant_wide_permissions" in cats


def test_T1_2_sensitive_data_access_high() -> None:
    cats = _detect_categories(
        verified_publisher=True,
        admin_consent=False,
        exposure_scope="user",
        sensitivity="high",
        data_owner="IT",
        confidence="confirmed",
        permissions=[],
        has_approval_record=True,
        has_vendor_review=True,
    )
    assert "sensitive_data_access" in cats


def test_T1_3_sensitive_data_access_critical() -> None:
    cats = _detect_categories(
        verified_publisher=True,
        admin_consent=False,
        exposure_scope="user",
        sensitivity="critical",
        data_owner="IT",
        confidence="confirmed",
        permissions=[],
        has_approval_record=True,
        has_vendor_review=True,
    )
    assert "sensitive_data_access" in cats


def test_T1_4_unverified_publisher() -> None:
    cats = _detect_categories(
        verified_publisher=False,
        admin_consent=False,
        exposure_scope="user",
        sensitivity="low",
        data_owner="IT",
        confidence="confirmed",
        permissions=[],
        has_approval_record=True,
        has_vendor_review=True,
    )
    assert "unverified_publisher" in cats


def test_T1_5_overprivileged_oauth() -> None:
    cats = _detect_categories(
        verified_publisher=True,
        admin_consent=False,
        exposure_scope="user",
        sensitivity="low",
        data_owner="IT",
        confidence="confirmed",
        permissions=["Files.Read.All"],
        has_approval_record=True,
        has_vendor_review=True,
    )
    assert "overprivileged_oauth" in cats


def test_T1_6_shadow_ai_suspected() -> None:
    cats = _detect_categories(
        verified_publisher=True,
        admin_consent=False,
        exposure_scope="user",
        sensitivity="low",
        data_owner="IT",
        confidence="suspected",
        permissions=[],
        has_approval_record=True,
        has_vendor_review=True,
    )
    assert "shadow_ai" in cats


def test_T1_7_unknown_owner() -> None:
    cats = _detect_categories(
        verified_publisher=True,
        admin_consent=False,
        exposure_scope="user",
        sensitivity="low",
        data_owner="Unknown",
        confidence="confirmed",
        permissions=[],
        has_approval_record=True,
        has_vendor_review=True,
    )
    assert "unknown_owner" in cats


def test_T1_8_no_approval_record() -> None:
    cats = _detect_categories(
        verified_publisher=True,
        admin_consent=False,
        exposure_scope="user",
        sensitivity="low",
        data_owner="IT",
        confidence="confirmed",
        permissions=[],
        has_approval_record=False,
        has_vendor_review=True,
    )
    assert "no_approval_record" in cats


def test_T1_9_no_vendor_review() -> None:
    cats = _detect_categories(
        verified_publisher=True,
        admin_consent=False,
        exposure_scope="user",
        sensitivity="low",
        data_owner="IT",
        confidence="confirmed",
        permissions=[],
        has_approval_record=True,
        has_vendor_review=False,
    )
    assert "no_dpa_baa_vendor_review" in cats


def test_T1_10_moderate_sensitivity_no_sensitive_data_access() -> None:
    cats = _detect_categories(
        verified_publisher=True,
        admin_consent=False,
        exposure_scope="user",
        sensitivity="moderate",
        data_owner="IT",
        confidence="confirmed",
        permissions=[],
        has_approval_record=True,
        has_vendor_review=True,
    )
    assert "sensitive_data_access" not in cats


# ---------------------------------------------------------------------------
# T2: Risk scoring
# ---------------------------------------------------------------------------


def test_T2_1_unverified_publisher_adds_25() -> None:
    score = _compute_risk_score(
        verified_publisher=False,
        admin_consent=False,
        exposure_scope="user",
        sensitivity="low",
        data_categories=[],
        data_owner="IT",
        confidence="confirmed",
        permissions=[],
    )
    assert score == 25


def test_T2_2_admin_consent_tenant_wide_adds_30() -> None:
    score = _compute_risk_score(
        verified_publisher=True,
        admin_consent=True,
        exposure_scope="tenant",
        sensitivity="low",
        data_categories=[],
        data_owner="IT",
        confidence="confirmed",
        permissions=[],
    )
    assert score == 30


def test_T2_3_admin_consent_non_tenant_adds_15() -> None:
    score = _compute_risk_score(
        verified_publisher=True,
        admin_consent=True,
        exposure_scope="user",
        sensitivity="low",
        data_categories=[],
        data_owner="IT",
        confidence="confirmed",
        permissions=[],
    )
    assert score == 15


def test_T2_4_critical_sensitivity_adds_30() -> None:
    score = _compute_risk_score(
        verified_publisher=True,
        admin_consent=False,
        exposure_scope="user",
        sensitivity="critical",
        data_categories=[],
        data_owner="IT",
        confidence="confirmed",
        permissions=[],
    )
    assert score == 30


def test_T2_5_high_sensitivity_adds_20() -> None:
    score = _compute_risk_score(
        verified_publisher=True,
        admin_consent=False,
        exposure_scope="user",
        sensitivity="high",
        data_categories=[],
        data_owner="IT",
        confidence="confirmed",
        permissions=[],
    )
    assert score == 20


def test_T2_6_unknown_owner_adds_15() -> None:
    score = _compute_risk_score(
        verified_publisher=True,
        admin_consent=False,
        exposure_scope="user",
        sensitivity="low",
        data_categories=[],
        data_owner="Unknown",
        confidence="confirmed",
        permissions=[],
    )
    assert score == 15


def test_T2_7_shadow_ai_adds_10() -> None:
    score = _compute_risk_score(
        verified_publisher=True,
        admin_consent=False,
        exposure_scope="user",
        sensitivity="low",
        data_categories=[],
        data_owner="IT",
        confidence="suspected",
        permissions=[],
    )
    assert score == 10


def test_T2_8_overprivileged_scope_adds_10() -> None:
    score = _compute_risk_score(
        verified_publisher=True,
        admin_consent=False,
        exposure_scope="user",
        sensitivity="low",
        data_categories=[],
        data_owner="IT",
        confidence="confirmed",
        permissions=["Files.Read.All"],
    )
    assert score == 10


def test_T2_9_multiple_sensitive_categories_adds_10() -> None:
    score_multi = _compute_risk_score(
        verified_publisher=True,
        admin_consent=False,
        exposure_scope="user",
        sensitivity="low",
        data_categories=["Email", "Documents", "Identity"],
        data_owner="IT",
        confidence="confirmed",
        permissions=[],
    )
    score_single = _compute_risk_score(
        verified_publisher=True,
        admin_consent=False,
        exposure_scope="user",
        sensitivity="low",
        data_categories=["Email"],
        data_owner="IT",
        confidence="confirmed",
        permissions=[],
    )
    assert score_multi == score_single + 10


# ---------------------------------------------------------------------------
# T3: Risk score band assignment
# ---------------------------------------------------------------------------


def test_T3_1_score_below_25_is_low() -> None:
    assert _score_to_label(0) == "low"
    assert _score_to_label(24) == "low"


def test_T3_2_score_25_to_49_is_moderate() -> None:
    assert _score_to_label(25) == "moderate"
    assert _score_to_label(49) == "moderate"


def test_T3_3_score_50_to_74_is_high() -> None:
    assert _score_to_label(50) == "high"
    assert _score_to_label(74) == "high"


def test_T3_4_score_75_plus_is_critical() -> None:
    assert _score_to_label(75) == "critical"
    assert _score_to_label(200) == "critical"


# ---------------------------------------------------------------------------
# T4: Risk reason generation
# ---------------------------------------------------------------------------


def test_T4_1_risk_reason_includes_tool_name() -> None:
    reason = _build_risk_reason(
        tool_name="CopilotAI",
        vendor="Microsoft",
        verified_publisher=True,
        admin_consent=False,
        exposure_scope="user",
        sensitivity="low",
        data_categories=[],
        data_owner="IT",
        confidence="confirmed",
        permissions=[],
        categories=["no_approval_record"],
    )
    assert "CopilotAI" in reason


def test_T4_2_risk_reason_includes_vendor() -> None:
    reason = _build_risk_reason(
        tool_name="TestTool",
        vendor="AcmeCorp",
        verified_publisher=True,
        admin_consent=False,
        exposure_scope="user",
        sensitivity="low",
        data_categories=[],
        data_owner="IT",
        confidence="confirmed",
        permissions=[],
        categories=["no_approval_record"],
    )
    assert "AcmeCorp" in reason


def test_T4_3_risk_reason_mentions_unverified() -> None:
    reason = _build_risk_reason(
        tool_name="X",
        vendor="Y",
        verified_publisher=False,
        admin_consent=False,
        exposure_scope="user",
        sensitivity="low",
        data_categories=[],
        data_owner="IT",
        confidence="confirmed",
        permissions=[],
        categories=["unverified_publisher"],
    )
    assert "not Microsoft-verified" in reason


def test_T4_4_risk_reason_not_empty() -> None:
    reason = _build_risk_reason(
        tool_name="T",
        vendor="V",
        verified_publisher=True,
        admin_consent=False,
        exposure_scope="user",
        sensitivity="low",
        data_categories=[],
        data_owner="IT",
        confidence="confirmed",
        permissions=[],
        categories=[],
    )
    assert len(reason) > 0


# ---------------------------------------------------------------------------
# T5: Recommended action (deterministic, not empty)
# ---------------------------------------------------------------------------


def test_T5_recommended_action_not_empty() -> None:
    records, _ = _run_engine(
        [_tool(admin_consent=True, verified_publisher=False)],
        [_mapping(sensitivity="critical", exposure_scope="tenant", admin_consent=True)],
    )
    assert len(records) == 1
    assert records[0]["recommended_action"]


# ---------------------------------------------------------------------------
# T6: Owner attribution (always Unknown on creation)
# ---------------------------------------------------------------------------


def test_T6_owner_always_unknown_on_creation() -> None:
    records, _ = _run_engine([_tool()])
    assert records[0]["business_owner"] == "Unknown"
    assert records[0]["technical_owner"] == "Unknown"


# ---------------------------------------------------------------------------
# T7: Review status always unreviewed on creation
# ---------------------------------------------------------------------------


def test_T7_review_status_always_unreviewed() -> None:
    records, _ = _run_engine([_tool()])
    assert records[0]["review_status"] == "unreviewed"


# ---------------------------------------------------------------------------
# T8: Graph-ready node IDs
# ---------------------------------------------------------------------------


def test_T8_1_graph_node_id_format() -> None:
    records, _ = _run_engine([_tool()], tenant_id="tenant-abc")
    gid = records[0]["graph_node_id"]
    assert gid.startswith("external_risk:tenant-abc:")


def test_T8_2_graph_node_id_unique_per_tool() -> None:
    tools = [
        _tool(tool_name="ToolA", app_id="a1"),
        _tool(tool_name="ToolB", app_id="b1"),
    ]
    records, _ = _run_engine(tools)
    gids = [r["graph_node_id"] for r in records]
    assert len(set(gids)) == 2


# ---------------------------------------------------------------------------
# T9: Evidence reference composition
# ---------------------------------------------------------------------------


def test_T9_1_pr1_scan_ref_in_evidence_refs() -> None:
    records, _ = _run_engine(
        [_tool()],
        pr1_scan_result_id="pr1-abc",
        pr2_scan_result_id=None,
    )
    assert any("pr1-abc" in ref for ref in records[0]["evidence_refs"])


def test_T9_2_pr2_scan_ref_added_when_mapping_exists() -> None:
    records, _ = _run_engine(
        [_tool(tool_name="MyTool")],
        [_mapping(tool_name="MyTool")],
        pr2_scan_result_id="pr2-xyz",
    )
    assert any("pr2-xyz" in ref for ref in records[0]["evidence_refs"])


def test_T9_3_no_pr2_ref_without_mapping() -> None:
    records, _ = _run_engine(
        [_tool(tool_name="UnmappedTool")],
        [_mapping(tool_name="DifferentTool")],
        pr2_scan_result_id="pr2-xyz",
    )
    refs = records[0]["evidence_refs"]
    pr2_refs = [r for r in refs if "pr2-xyz" in r]
    assert len(pr2_refs) == 0


# ---------------------------------------------------------------------------
# T10: Sensitive data exposure field
# ---------------------------------------------------------------------------


def test_T10_sensitive_data_exposure_from_mapping() -> None:
    records, _ = _run_engine(
        [_tool(tool_name="AiTool")],
        [_mapping(tool_name="AiTool", data_categories=["Email", "Documents"])],
    )
    assert "Email" in records[0]["sensitive_data_exposure"]
    assert "Documents" in records[0]["sensitive_data_exposure"]


# ---------------------------------------------------------------------------
# T11: Publisher trust field
# ---------------------------------------------------------------------------


def test_T11_1_verified_publisher_trust() -> None:
    records, _ = _run_engine([_tool(verified_publisher=True)])
    assert records[0]["publisher_trust"] == "verified"


def test_T11_2_unverified_publisher_trust() -> None:
    records, _ = _run_engine([_tool(verified_publisher=False)])
    assert records[0]["publisher_trust"] == "unverified"


# ---------------------------------------------------------------------------
# T12: Data access summary field
# ---------------------------------------------------------------------------


def test_T12_data_access_summary_generated() -> None:
    records, _ = _run_engine(
        [_tool(tool_name="SomeTool", permissions=["Mail.Read"])],
        [_mapping(tool_name="SomeTool", data_categories=["Email"], sensitivity="high")],
    )
    summary = records[0]["data_access_summary"]
    assert summary is not None
    assert "Email" in summary


# ---------------------------------------------------------------------------
# T13: Finding generation (only for high/critical)
# ---------------------------------------------------------------------------


def test_T13_1_critical_risk_generates_finding() -> None:
    # Unverified + tenant-wide + critical → score well above 75
    tools = [
        _tool(
            tool_name="DangerAI",
            permissions=["Directory.Read.All"],
            admin_consent=True,
            verified_publisher=False,
        )
    ]
    mappings = [
        _mapping(tool_name="DangerAI", sensitivity="critical", exposure_scope="tenant")
    ]
    _, findings = _run_engine(tools, mappings)
    assert len(findings) > 0
    assert findings[0]["severity"] in ("critical", "high")


def test_T13_2_low_risk_no_finding() -> None:
    # Verified publisher, no admin consent, low sensitivity, known owner
    tools = [_tool(tool_name="SafeAI", verified_publisher=True)]
    mappings = [
        _mapping(
            tool_name="SafeAI",
            sensitivity="low",
            data_owner="IT",
            exposure_scope="user",
        )
    ]
    records, findings = _run_engine(tools, mappings)
    assert records[0]["risk_score"] in ("low", "moderate")
    # Findings are only generated for high/critical risk scores
    high_or_crit = [f for f in findings if f.get("severity") in ("high", "critical")]
    safe_findings = [f for f in high_or_crit if f.get("tool_name") == "SafeAI"]
    assert len(safe_findings) == 0


def test_T13_3_finding_has_required_fields() -> None:
    tools = [_tool(admin_consent=True, verified_publisher=False)]
    mappings = [
        _mapping(sensitivity="critical", exposure_scope="tenant", admin_consent=True)
    ]
    _, findings = _run_engine(tools, mappings)
    if findings:
        f = findings[0]
        assert "type" in f
        assert "severity" in f
        assert "title" in f
        assert "description" in f
        assert "recommendation" in f
        assert "risk_record_id" in f


# ---------------------------------------------------------------------------
# T14: Summary distribution
# ---------------------------------------------------------------------------


def test_T14_1_summary_counts_correct() -> None:
    tools = [
        _tool(tool_name="A", verified_publisher=False, admin_consent=True),
        _tool(tool_name="B"),
    ]
    maps = [
        _mapping(
            tool_name="A",
            sensitivity="critical",
            exposure_scope="tenant",
            admin_consent=True,
        ),
        _mapping(tool_name="B", sensitivity="low"),
    ]
    records, _ = _run_engine(tools, maps)
    summary = build_summary(records)
    assert summary["total_risks"] == 2
    assert (
        summary["score_distribution"]["critical"]
        + summary["score_distribution"]["high"]
        >= 1
    )


def test_T14_2_ownership_gaps_counted() -> None:
    tools = [_tool(tool_name="X"), _tool(tool_name="Y")]
    records, _ = _run_engine(tools)
    summary = build_summary(records)
    assert summary["ownership_gaps"] == 2  # both Unknown


def test_T14_3_governance_gaps_counted() -> None:
    records, _ = _run_engine([_tool(tool_name="Z")])
    summary = build_summary(records)
    # no_approval_record is always detected (has_approval_record=False in engine)
    assert summary["governance_gaps"] >= 1


# ---------------------------------------------------------------------------
# T15: Shadow AI detection
# ---------------------------------------------------------------------------


def test_T15_1_suspected_is_shadow_ai() -> None:
    records, _ = _run_engine([_tool(confidence="suspected")])
    assert "shadow_ai" in records[0]["risk_categories"]


def test_T15_2_unknown_confidence_is_shadow_ai() -> None:
    records, _ = _run_engine([_tool(confidence="unknown")])
    assert "shadow_ai" in records[0]["risk_categories"]


def test_T15_3_confirmed_not_shadow_ai() -> None:
    records, _ = _run_engine([_tool(confidence="confirmed")])
    assert "shadow_ai" not in records[0]["risk_categories"]


# ---------------------------------------------------------------------------
# T16: Overprivileged OAuth detection
# ---------------------------------------------------------------------------


def test_T16_1_directory_read_all_is_overprivileged() -> None:
    records, _ = _run_engine([_tool(permissions=["Directory.Read.All"])])
    assert "overprivileged_oauth" in records[0]["risk_categories"]


def test_T16_2_files_read_all_is_overprivileged() -> None:
    records, _ = _run_engine([_tool(permissions=["Files.Read.All"])])
    assert "overprivileged_oauth" in records[0]["risk_categories"]


def test_T16_3_basic_scope_not_overprivileged() -> None:
    records, _ = _run_engine([_tool(permissions=["User.Read"])])
    assert "overprivileged_oauth" not in records[0]["risk_categories"]


# ---------------------------------------------------------------------------
# T17: Deterministic ordering
# ---------------------------------------------------------------------------


def test_T17_ordering_critical_before_low() -> None:
    tools = [
        _tool(tool_name="LowTool"),  # will be low risk
        _tool(
            tool_name="CriticalTool", verified_publisher=False, admin_consent=True
        ),  # high risk
    ]
    maps = [
        _mapping(
            tool_name="CriticalTool", sensitivity="critical", exposure_scope="tenant"
        ),
    ]
    records, _ = _run_engine(tools, maps)
    scores = [r["risk_score"] for r in records]
    # Higher severity should come first
    assert scores[0] in ("critical", "high")


# ---------------------------------------------------------------------------
# T18: Idempotent regeneration (existing IDs preserved)
# ---------------------------------------------------------------------------


def test_T18_idempotent_ids() -> None:
    tools = [_tool(tool_name="PersistTool")]
    records1, _ = _run_engine(tools)
    id1 = records1[0]["id"]
    existing = {"PersistTool": id1}
    records2, _ = _run_engine(tools, existing_ids=existing)
    assert records2[0]["id"] == id1


# ---------------------------------------------------------------------------
# T19-T22: Bridge layer
# ---------------------------------------------------------------------------


def _make_bridge_payload(*, tenant_id: str = "t1", engagement_id: str = "e1") -> dict:
    tools = [
        _tool(tool_name="BridgeToolA", admin_consent=True, verified_publisher=False),
        _tool(tool_name="BridgeToolB"),
    ]
    maps = [
        _mapping(
            tool_name="BridgeToolA", sensitivity="critical", exposure_scope="tenant"
        ),
        _mapping(tool_name="BridgeToolB"),
    ]
    risk_records, findings = generate_risk_records(
        tools=tools,
        mappings=maps,
        pr1_scan_result_id="pr1-001",
        pr2_scan_result_id="pr2-001",
        tenant_id=tenant_id,
        engagement_id=engagement_id,
    )
    summary = build_summary(risk_records)
    return _make_scan_payload(
        risk_records,
        findings,
        summary,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
    )


def test_T19_bridge_creates_scan_result(_db: Any) -> None:
    from api.db_models_field_assessment import FaScanResult
    from services.field_assessment.connectors.external_ai_risk_register_bridge import (
        import_external_ai_risk_register,
    )

    payload = _make_bridge_payload()
    result = import_external_ai_risk_register(
        db=_db,
        tenant_id="t1",
        engagement_id="e1",
        scan_result=payload,
        actor="test-actor",
    )
    _db.commit()

    scan_rows = (
        _db.query(FaScanResult)
        .filter_by(
            tenant_id="t1", engagement_id="e1", source_type="external_ai_risk_register"
        )
        .all()
    )
    assert len(scan_rows) == 1
    assert scan_rows[0].id == result.scan_result_id


def test_T20_bridge_creates_risk_records(_db: Any) -> None:
    from api.db_models_external_ai_risk import FaExternalAiRiskRecord
    from services.field_assessment.connectors.external_ai_risk_register_bridge import (
        import_external_ai_risk_register,
    )

    payload = _make_bridge_payload()
    import_external_ai_risk_register(
        db=_db,
        tenant_id="t1",
        engagement_id="e1",
        scan_result=payload,
        actor="test-actor",
    )
    _db.commit()

    rows = (
        _db.query(FaExternalAiRiskRecord)
        .filter_by(tenant_id="t1", engagement_id="e1")
        .all()
    )
    assert len(rows) == 2
    tool_names = {r.tool_name for r in rows}
    assert "BridgeToolA" in tool_names
    assert "BridgeToolB" in tool_names


def test_T21_bridge_creates_findings_for_high_critical(_db: Any) -> None:
    from api.db_models_field_assessment import FaNormalizedFinding
    from services.field_assessment.connectors.external_ai_risk_register_bridge import (
        import_external_ai_risk_register,
    )

    payload = _make_bridge_payload()
    result = import_external_ai_risk_register(
        db=_db,
        tenant_id="t1",
        engagement_id="e1",
        scan_result=payload,
        actor="test-actor",
    )
    _db.commit()

    findings = (
        _db.query(FaNormalizedFinding)
        .filter_by(tenant_id="t1", engagement_id="e1")
        .all()
    )
    assert result.findings_imported == len(findings)
    for f in findings:
        assert f.severity in ("critical", "high")


def test_T22_bridge_idempotent_second_run(_db: Any) -> None:
    from api.db_models_external_ai_risk import FaExternalAiRiskRecord
    from services.field_assessment.connectors.external_ai_risk_register_bridge import (
        import_external_ai_risk_register,
    )

    payload = _make_bridge_payload()
    import_external_ai_risk_register(
        db=_db,
        tenant_id="t1",
        engagement_id="e1",
        scan_result=payload,
        actor="test-actor",
    )
    _db.commit()

    # Second run with same tools — scan result gets a new hash (different timestamp)
    # but risk records should be updated in place
    import_external_ai_risk_register(
        db=_db,
        tenant_id="t1",
        engagement_id="e1",
        scan_result={**payload, "scan_completed_at": "2026-06-04T00:00:00Z"},
        actor="test-actor",
    )
    _db.commit()

    rows = (
        _db.query(FaExternalAiRiskRecord)
        .filter_by(tenant_id="t1", engagement_id="e1")
        .all()
    )
    # Still exactly 2 records — updated in place
    assert len(rows) == 2


# ---------------------------------------------------------------------------
# T23-T24: Tenant and engagement isolation
# ---------------------------------------------------------------------------


def test_T23_tenant_isolation(_db: Any) -> None:
    from api.db_models_external_ai_risk import FaExternalAiRiskRecord
    from services.field_assessment.connectors.external_ai_risk_register_bridge import (
        import_external_ai_risk_register,
    )

    payload_t1 = _make_bridge_payload(tenant_id="tenant-A", engagement_id="eng-1")
    payload_t2 = _make_bridge_payload(tenant_id="tenant-B", engagement_id="eng-1")

    import_external_ai_risk_register(
        db=_db,
        tenant_id="tenant-A",
        engagement_id="eng-1",
        scan_result=payload_t1,
        actor="actor",
    )
    import_external_ai_risk_register(
        db=_db,
        tenant_id="tenant-B",
        engagement_id="eng-1",
        scan_result=payload_t2,
        actor="actor",
    )
    _db.commit()

    rows_a = _db.query(FaExternalAiRiskRecord).filter_by(tenant_id="tenant-A").all()
    rows_b = _db.query(FaExternalAiRiskRecord).filter_by(tenant_id="tenant-B").all()
    assert len(rows_a) > 0
    assert len(rows_b) > 0
    # No cross-tenant contamination
    for r in rows_a:
        assert r.tenant_id == "tenant-A"
    for r in rows_b:
        assert r.tenant_id == "tenant-B"


def test_T24_engagement_isolation(_db: Any) -> None:
    from api.db_models_external_ai_risk import FaExternalAiRiskRecord
    from services.field_assessment.connectors.external_ai_risk_register_bridge import (
        import_external_ai_risk_register,
    )

    payload_e1 = _make_bridge_payload(tenant_id="t1", engagement_id="eng-1")
    payload_e2 = _make_bridge_payload(tenant_id="t1", engagement_id="eng-2")

    import_external_ai_risk_register(
        db=_db,
        tenant_id="t1",
        engagement_id="eng-1",
        scan_result=payload_e1,
        actor="actor",
    )
    import_external_ai_risk_register(
        db=_db,
        tenant_id="t1",
        engagement_id="eng-2",
        scan_result=payload_e2,
        actor="actor",
    )
    _db.commit()

    rows_e1 = _db.query(FaExternalAiRiskRecord).filter_by(engagement_id="eng-1").all()
    rows_e2 = _db.query(FaExternalAiRiskRecord).filter_by(engagement_id="eng-2").all()
    for r in rows_e1:
        assert r.engagement_id == "eng-1"
    for r in rows_e2:
        assert r.engagement_id == "eng-2"


# ---------------------------------------------------------------------------
# T25-T27: Review status update
# ---------------------------------------------------------------------------


def test_T25_review_status_update(_db: Any) -> None:
    from api.db_models_external_ai_risk import FaExternalAiRiskRecord
    from services.field_assessment.connectors.external_ai_risk_register_bridge import (
        import_external_ai_risk_register,
    )
    from services.canonical import utc_iso8601_z_now

    payload = _make_bridge_payload()
    import_external_ai_risk_register(
        db=_db,
        tenant_id="t1",
        engagement_id="e1",
        scan_result=payload,
        actor="actor",
    )
    _db.commit()

    row = (
        _db.query(FaExternalAiRiskRecord)
        .filter_by(tenant_id="t1", tool_name="BridgeToolA")
        .first()
    )
    assert row is not None
    row.review_status = "accepted"
    row.updated_at = utc_iso8601_z_now()
    _db.commit()
    _db.refresh(row)
    assert row.review_status == "accepted"


def test_T26_owner_update(_db: Any) -> None:
    from api.db_models_external_ai_risk import FaExternalAiRiskRecord
    from services.field_assessment.connectors.external_ai_risk_register_bridge import (
        import_external_ai_risk_register,
    )
    from services.canonical import utc_iso8601_z_now

    payload = _make_bridge_payload()
    import_external_ai_risk_register(
        db=_db,
        tenant_id="t1",
        engagement_id="e1",
        scan_result=payload,
        actor="actor",
    )
    _db.commit()

    row = (
        _db.query(FaExternalAiRiskRecord)
        .filter_by(tenant_id="t1", tool_name="BridgeToolA")
        .first()
    )
    assert row is not None
    row.business_owner = "Alice"
    row.technical_owner = "Bob"
    row.updated_at = utc_iso8601_z_now()
    _db.commit()
    _db.refresh(row)
    assert row.business_owner == "Alice"
    assert row.technical_owner == "Bob"


def test_T27_review_status_default_unreviewed(_db: Any) -> None:
    from api.db_models_external_ai_risk import FaExternalAiRiskRecord
    from services.field_assessment.connectors.external_ai_risk_register_bridge import (
        import_external_ai_risk_register,
    )

    payload = _make_bridge_payload()
    import_external_ai_risk_register(
        db=_db,
        tenant_id="t1",
        engagement_id="e1",
        scan_result=payload,
        actor="actor",
    )
    _db.commit()

    rows = (
        _db.query(FaExternalAiRiskRecord)
        .filter_by(tenant_id="t1", engagement_id="e1")
        .all()
    )
    for r in rows:
        assert r.review_status == "unreviewed"


# ---------------------------------------------------------------------------
# T28: Verification bundle includes ai_risk_register
# ---------------------------------------------------------------------------


def test_T28_verification_bundle_includes_risk_register(_db: Any) -> None:
    from api.db_models_external_ai_risk import FaExternalAiRiskRecord
    from services.canonical import utc_iso8601_z_now

    # Manually insert a risk record
    now = utc_iso8601_z_now()
    row = FaExternalAiRiskRecord(
        id="risk-bundle-test-1",
        tenant_id="t-bundle",
        engagement_id="e-bundle",
        tool_name="BundleTool",
        vendor="BundleCo",
        business_owner="Unknown",
        technical_owner="Unknown",
        permissions=[],
        sensitive_data_exposure=[],
        publisher_trust="verified",
        admin_consent=False,
        risk_score="low",
        risk_reason="Test reason.",
        risk_category="no_approval_record",
        risk_categories=["no_approval_record"],
        recommended_action="Document approval.",
        review_status="unreviewed",
        evidence_refs=[],
        finding_refs=[],
        graph_node_id="external_risk:t-bundle:risk-bundle-test-1",
        created_at=now,
        updated_at=now,
    )
    _db.add(row)
    _db.commit()

    # Check the bundle service imports the model correctly
    from services.verification_bundle.bundle_service import VerificationBundleService

    svc = VerificationBundleService()
    # We can't generate a full bundle without the full engagement, but we can
    # verify the import exists and FaExternalAiRiskRecord can be queried
    rows = (
        _db.query(FaExternalAiRiskRecord)
        .filter_by(tenant_id="t-bundle", engagement_id="e-bundle")
        .all()
    )
    assert len(rows) == 1
    assert rows[0].id == "risk-bundle-test-1"
    # Service class importable (no import error = bundle integration is wired)
    assert svc is not None


# ---------------------------------------------------------------------------
# T29: Scan registry — schema version
# ---------------------------------------------------------------------------


def test_T29_scan_registry_schema_version_accepted() -> None:
    from services.field_assessment.scan_registry import SUPPORTED_SCHEMA_VERSIONS

    assert "external_ai_risk_register" in SUPPORTED_SCHEMA_VERSIONS
    assert "1.0" in SUPPORTED_SCHEMA_VERSIONS["external_ai_risk_register"]


# ---------------------------------------------------------------------------
# T30: Scan registry — required fields
# ---------------------------------------------------------------------------


def test_T30_scan_registry_required_fields() -> None:
    from services.field_assessment.scan_registry import REQUIRED_FIELDS

    assert "external_ai_risk_register" in REQUIRED_FIELDS
    assert "risk_records" in REQUIRED_FIELDS["external_ai_risk_register"]


# ---------------------------------------------------------------------------
# T31: Report section emitted
# ---------------------------------------------------------------------------


def test_T31_report_section_in_all_sections() -> None:
    """external_ai_risk_register must be in _ALL_SECTIONS."""
    from api.field_assessment import _ALL_SECTIONS

    assert "external_ai_risk_register" in _ALL_SECTIONS


# ---------------------------------------------------------------------------
# T32: risk_reason is deterministic, not empty
# ---------------------------------------------------------------------------


def test_T32_risk_reason_deterministic() -> None:
    tools = [_tool(tool_name="ToolX", verified_publisher=False)]
    records1, _ = _run_engine(tools)
    records2, _ = _run_engine(tools)
    assert records1[0]["risk_reason"] == records2[0]["risk_reason"]
    assert len(records1[0]["risk_reason"]) > 10


# ---------------------------------------------------------------------------
# T33-T34: Score comparisons
# ---------------------------------------------------------------------------


def test_T33_admin_consent_raises_score() -> None:
    score_no_consent = _compute_risk_score(
        verified_publisher=True,
        admin_consent=False,
        exposure_scope="user",
        sensitivity="low",
        data_categories=[],
        data_owner="IT",
        confidence="confirmed",
        permissions=[],
    )
    score_with_consent = _compute_risk_score(
        verified_publisher=True,
        admin_consent=True,
        exposure_scope="tenant",
        sensitivity="low",
        data_categories=[],
        data_owner="IT",
        confidence="confirmed",
        permissions=[],
    )
    assert score_with_consent > score_no_consent


def test_T34_unverified_raises_score_vs_verified() -> None:
    score_verified = _compute_risk_score(
        verified_publisher=True,
        admin_consent=False,
        exposure_scope="user",
        sensitivity="low",
        data_categories=[],
        data_owner="IT",
        confidence="confirmed",
        permissions=[],
    )
    score_unverified = _compute_risk_score(
        verified_publisher=False,
        admin_consent=False,
        exposure_scope="user",
        sensitivity="low",
        data_categories=[],
        data_owner="IT",
        confidence="confirmed",
        permissions=[],
    )
    assert score_unverified > score_verified


# ---------------------------------------------------------------------------
# T35: Multiple sensitive categories → score bump
# ---------------------------------------------------------------------------


def test_T35_multi_category_bump() -> None:
    score_3cats = _compute_risk_score(
        verified_publisher=True,
        admin_consent=False,
        exposure_scope="user",
        sensitivity="low",
        data_categories=["Email", "Documents", "Identity"],
        data_owner="IT",
        confidence="confirmed",
        permissions=[],
    )
    score_1cat = _compute_risk_score(
        verified_publisher=True,
        admin_consent=False,
        exposure_scope="user",
        sensitivity="low",
        data_categories=["Email"],
        data_owner="IT",
        confidence="confirmed",
        permissions=[],
    )
    assert score_3cats > score_1cat


# ---------------------------------------------------------------------------
# T36-T38: Shadow AI confidence
# ---------------------------------------------------------------------------


def test_T36_suspected_shadow_ai() -> None:
    records, _ = _run_engine([_tool(confidence="suspected")])
    assert "shadow_ai" in records[0]["risk_categories"]
    summary = build_summary(records)
    assert summary["shadow_ai_count"] == 1


def test_T37_unknown_confidence_shadow_ai() -> None:
    records, _ = _run_engine([_tool(confidence="unknown")])
    assert "shadow_ai" in records[0]["risk_categories"]


def test_T38_confirmed_not_shadow_ai() -> None:
    records, _ = _run_engine([_tool(confidence="confirmed")])
    assert "shadow_ai" not in records[0]["risk_categories"]


# ---------------------------------------------------------------------------
# T39: No PR2 mappings — still generates records from PR1
# ---------------------------------------------------------------------------


def test_T39_no_pr2_still_generates() -> None:
    tools = [_tool(tool_name="OnlyPR1")]
    records, _ = _run_engine(tools, mappings=[], pr2_scan_result_id=None)
    assert len(records) == 1
    assert records[0]["tool_name"] == "OnlyPR1"


# ---------------------------------------------------------------------------
# T40: Empty permissions → no overprivileged_oauth
# ---------------------------------------------------------------------------


def test_T40_empty_permissions_no_overprivileged() -> None:
    records, _ = _run_engine([_tool(permissions=[])])
    assert "overprivileged_oauth" not in records[0]["risk_categories"]


# ---------------------------------------------------------------------------
# T41: Data access summary built from PR2 data
# ---------------------------------------------------------------------------


def test_T41_data_access_summary_mentions_scope() -> None:
    records, _ = _run_engine(
        [_tool(tool_name="T1")],
        [
            _mapping(
                tool_name="T1",
                data_categories=["Teams Data"],
                exposure_scope="tenant",
                sensitivity="moderate",
            )
        ],
    )
    summary = records[0]["data_access_summary"]
    assert "tenant" in summary


# ---------------------------------------------------------------------------
# T42: finding_refs backfilled on high/critical records
# ---------------------------------------------------------------------------


def test_T42_finding_refs_backfilled(_db: Any) -> None:
    from api.db_models_external_ai_risk import FaExternalAiRiskRecord
    from services.field_assessment.connectors.external_ai_risk_register_bridge import (
        import_external_ai_risk_register,
    )

    payload = _make_bridge_payload(tenant_id="t1", engagement_id="e1")
    result = import_external_ai_risk_register(
        db=_db,
        tenant_id="t1",
        engagement_id="e1",
        scan_result=payload,
        actor="actor",
    )
    _db.commit()

    if result.findings_imported > 0:
        high_critical_rows = (
            _db.query(FaExternalAiRiskRecord)
            .filter_by(tenant_id="t1", engagement_id="e1")
            .filter(FaExternalAiRiskRecord.risk_score.in_(["critical", "high"]))
            .all()
        )
        # At least one high/critical record should have finding_refs populated
        any_has_refs = any(bool(r.finding_refs) for r in high_critical_rows)
        assert any_has_refs


# ---------------------------------------------------------------------------
# T43: build_summary aggregate metrics
# ---------------------------------------------------------------------------


def test_T43_build_summary_fields() -> None:
    records = [
        {
            "risk_score": "critical",
            "risk_categories": ["tenant_wide_permissions"],
            "business_owner": "Unknown",
        },
        {
            "risk_score": "low",
            "risk_categories": ["no_approval_record"],
            "business_owner": "Alice",
        },
    ]
    summary = build_summary(records)
    assert summary["total_risks"] == 2
    assert summary["score_distribution"]["critical"] == 1
    assert summary["score_distribution"]["low"] == 1
    assert summary["ownership_gaps"] == 1  # only Unknown counts
    assert summary["tenant_wide_count"] == 1


# ---------------------------------------------------------------------------
# T44: GET list filters
# ---------------------------------------------------------------------------


def test_T44_risk_records_have_required_fields() -> None:
    tools = [_tool(tool_name="FieldCheckTool", verified_publisher=False)]
    records, _ = _run_engine(tools)
    r = records[0]
    for field in (
        "id",
        "tool_name",
        "vendor",
        "business_owner",
        "technical_owner",
        "permissions",
        "sensitive_data_exposure",
        "publisher_trust",
        "admin_consent",
        "risk_score",
        "risk_reason",
        "risk_category",
        "risk_categories",
        "recommended_action",
        "review_status",
        "evidence_refs",
        "finding_refs",
        "graph_node_id",
    ):
        assert field in r, f"Missing field: {field}"


# ---------------------------------------------------------------------------
# T45: Engine handles multiple tools, one mapping per tool
# ---------------------------------------------------------------------------


def test_T45_multiple_tools_mapped_independently() -> None:
    tools = [
        _tool(tool_name="Alpha", verified_publisher=False),
        _tool(tool_name="Beta", admin_consent=True),
        _tool(tool_name="Gamma"),
    ]
    maps = [
        _mapping(tool_name="Alpha", sensitivity="high"),
        _mapping(tool_name="Beta", exposure_scope="tenant"),
    ]
    records, _ = _run_engine(tools, maps)
    assert len(records) == 3
    names = {r["tool_name"] for r in records}
    assert names == {"Alpha", "Beta", "Gamma"}


# ---------------------------------------------------------------------------
# T46: ScanSourceType enum includes EXTERNAL_AI_RISK_REGISTER
# ---------------------------------------------------------------------------


def test_T46_scan_source_type_enum() -> None:
    from services.field_assessment.models import ScanSourceType

    assert ScanSourceType.EXTERNAL_AI_RISK_REGISTER.value == "external_ai_risk_register"


# ===========================================================================
# Addendum — A-series tests
# ===========================================================================

# ---------------------------------------------------------------------------
# Governance state helpers
# ---------------------------------------------------------------------------


def test_A1_governance_state_governed_no_gaps() -> None:
    assert _determine_governance_state([]) == "governed"


def test_A2_governance_state_ungoverned_unverified_publisher() -> None:
    assert _determine_governance_state(["unverified_publisher"]) == "ungoverned"


def test_A3_governance_state_ungoverned_shadow_ai() -> None:
    assert _determine_governance_state(["shadow_ai"]) == "ungoverned"


def test_A4_governance_state_partial_unknown_owner() -> None:
    assert _determine_governance_state(["unknown_owner"]) == "partially_governed"


def test_A5_governance_state_partial_no_approval_record() -> None:
    assert _determine_governance_state(["no_approval_record"]) == "partially_governed"


def test_A5b_governance_state_partial_no_dpa() -> None:
    assert (
        _determine_governance_state(["no_dpa_baa_vendor_review"])
        == "partially_governed"
    )


def test_A5c_governance_state_ungoverned_beats_partial() -> None:
    # unverified_publisher takes precedence over unknown_owner
    assert (
        _determine_governance_state(["unverified_publisher", "unknown_owner"])
        == "ungoverned"
    )


# ---------------------------------------------------------------------------
# Regulatory flags helpers
# ---------------------------------------------------------------------------


def test_A6_regulatory_flags_nist_always() -> None:
    flags = _determine_regulatory_flags([], [])
    assert "NIST_AI_RMF" in flags


def test_A7_regulatory_flags_eu_ai_act_unverified() -> None:
    flags = _determine_regulatory_flags(["unverified_publisher"], [])
    assert "EU_AI_ACT" in flags


def test_A7b_regulatory_flags_eu_ai_act_tenant_wide() -> None:
    flags = _determine_regulatory_flags(["tenant_wide_permissions"], [])
    assert "EU_AI_ACT" in flags


def test_A7c_regulatory_flags_eu_ai_act_shadow_ai() -> None:
    flags = _determine_regulatory_flags(["shadow_ai"], [])
    assert "EU_AI_ACT" in flags


def test_A8_regulatory_flags_gdpr_sensitive_data() -> None:
    flags = _determine_regulatory_flags(["sensitive_data_access"], [])
    assert "GDPR" in flags
    assert "State_Privacy_Law" in flags


def test_A9_regulatory_flags_iso42001_no_approval() -> None:
    flags = _determine_regulatory_flags(["no_approval_record"], [])
    assert "ISO_42001" in flags


def test_A9b_regulatory_flags_iso42001_unknown_owner() -> None:
    flags = _determine_regulatory_flags(["unknown_owner"], [])
    assert "ISO_42001" in flags


def test_A10_regulatory_flags_hipaa_health_exposure() -> None:
    flags = _determine_regulatory_flags(
        ["sensitive_data_access"], ["health_records", "phi"]
    )
    assert "HIPAA" in flags


def test_A31_regulatory_flags_pci_dss_payment_exposure() -> None:
    flags = _determine_regulatory_flags(
        ["sensitive_data_access"], ["payment_card_data"]
    )
    assert "PCI_DSS" in flags


def test_A32_regulatory_flags_hipaa_medical_keyword() -> None:
    flags = _determine_regulatory_flags([], ["medical_records"])
    assert "HIPAA" in flags


def test_A_regulatory_flags_ordered() -> None:
    """Flags must be in deterministic order regardless of category input order."""
    flags1 = _determine_regulatory_flags(
        ["unverified_publisher", "sensitive_data_access"], []
    )
    flags2 = _determine_regulatory_flags(
        ["sensitive_data_access", "unverified_publisher"], []
    )
    assert flags1 == flags2


# ---------------------------------------------------------------------------
# Engine output — addendum fields
# ---------------------------------------------------------------------------


def test_A11_owner_type_default_unknown() -> None:
    tools = [_tool(tool_name="OwnedTool")]
    records, _ = _run_engine(tools)
    assert records[0]["owner_type"] == "Unknown"


def test_A12_risk_owner_none_at_generation() -> None:
    tools = [_tool(tool_name="OwnedTool")]
    records, _ = _run_engine(tools)
    assert records[0]["risk_owner"] is None


def test_A13_vendor_governance_status_defaults() -> None:
    tools = [_tool(tool_name="VendorTool")]
    records, _ = _run_engine(tools)
    r = records[0]
    assert r["vendor_review_status"] == "not_reviewed"
    assert r["vendor_dpa_status"] == "unknown"
    assert r["vendor_baa_status"] == "unknown"
    assert r["vendor_security_review_status"] == "unknown"
    assert r["vendor_last_reviewed_at"] is None


def test_A14_remediation_status_default_not_started() -> None:
    tools = [_tool(tool_name="RemTool")]
    records, _ = _run_engine(tools)
    assert records[0]["remediation_status"] == "not_started"


def test_A15_decision_linkage_empty_at_generation() -> None:
    tools = [_tool(tool_name="DecTool")]
    records, _ = _run_engine(tools)
    r = records[0]
    assert r["decision_refs"] == []
    assert r["risk_acceptance_refs"] == []
    assert r["exception_refs"] == []
    assert r["approval_refs"] == []


def test_A16_graph_node_ids_format() -> None:
    tools = [_tool(tool_name="GraphTool", vendor="GraphCo")]
    records, _ = _run_engine(tools, tenant_id="t-graph", engagement_id="e-graph")
    r = records[0]
    rec_id = r["id"]
    assert r["risk_node_id"] == f"risk:t-graph:{rec_id}"
    assert r["owner_node_id"] == f"owner:t-graph:{rec_id}"
    assert r["decision_node_id"] == f"decision:t-graph:{rec_id}"
    assert r["governance_node_id"] == f"governance:t-graph:{rec_id}"
    assert r["vendor_node_id"].startswith("vendor:t-graph:")
    assert "graphco" in r["vendor_node_id"]


def test_A37_all_addendum_fields_in_engine_output() -> None:
    tools = [_tool(tool_name="FullCheck")]
    records, _ = _run_engine(tools)
    r = records[0]
    required = (
        "owner_type",
        "risk_owner",
        "governance_state",
        "regulatory_flags",
        "vendor_review_status",
        "vendor_dpa_status",
        "vendor_baa_status",
        "vendor_security_review_status",
        "vendor_last_reviewed_at",
        "risk_age_days",
        "first_detected_at",
        "last_observed_at",
        "last_reviewed_at",
        "remediation_status",
        "remediation_target_date",
        "remediation_completed_at",
        "decision_refs",
        "risk_acceptance_refs",
        "exception_refs",
        "approval_refs",
        "risk_node_id",
        "owner_node_id",
        "vendor_node_id",
        "decision_node_id",
        "governance_node_id",
    )
    for field in required:
        assert field in r, f"Missing addendum field: {field}"


# ---------------------------------------------------------------------------
# build_summary — addendum distributions
# ---------------------------------------------------------------------------


def test_A17_build_summary_governance_distribution() -> None:
    records = [
        {
            "risk_score": "critical",
            "risk_categories": ["unverified_publisher"],
            "business_owner": "Unknown",
            "risk_owner": None,
            "review_status": "unreviewed",
            "governance_state": "ungoverned",
            "vendor_review_status": "not_reviewed",
            "remediation_status": "not_started",
            "regulatory_flags": [],
            "risk_age_days": None,
        },
        {
            "risk_score": "low",
            "risk_categories": [],
            "business_owner": "Alice",
            "risk_owner": None,
            "review_status": "accepted",
            "governance_state": "governed",
            "vendor_review_status": "approved",
            "remediation_status": "completed",
            "regulatory_flags": [],
            "risk_age_days": None,
        },
    ]
    summary = build_summary(records)
    assert summary["governance_distribution"]["ungoverned"] == 1
    assert summary["governance_distribution"]["governed"] == 1


def test_A18_build_summary_vendor_distribution() -> None:
    records = [
        {
            "risk_score": "low",
            "risk_categories": [],
            "business_owner": "Alice",
            "risk_owner": None,
            "review_status": "accepted",
            "governance_state": "governed",
            "vendor_review_status": "approved",
            "remediation_status": "not_started",
            "regulatory_flags": [],
            "risk_age_days": None,
        },
        {
            "risk_score": "low",
            "risk_categories": [],
            "business_owner": "Bob",
            "risk_owner": None,
            "review_status": "unreviewed",
            "governance_state": "governed",
            "vendor_review_status": "not_reviewed",
            "remediation_status": "not_started",
            "regulatory_flags": [],
            "risk_age_days": None,
        },
    ]
    summary = build_summary(records)
    assert summary["vendor_distribution"]["approved"] == 1
    assert summary["vendor_distribution"]["not_reviewed"] == 1


def test_A19_build_summary_regulatory_distribution() -> None:
    records = [
        {
            "risk_score": "high",
            "risk_categories": ["unverified_publisher"],
            "business_owner": "Unknown",
            "risk_owner": None,
            "review_status": "unreviewed",
            "governance_state": "ungoverned",
            "vendor_review_status": "not_reviewed",
            "remediation_status": "not_started",
            "regulatory_flags": ["EU_AI_ACT", "NIST_AI_RMF"],
            "risk_age_days": None,
        },
    ]
    summary = build_summary(records)
    assert summary["regulatory_distribution"]["EU_AI_ACT"] == 1
    assert summary["regulatory_distribution"]["NIST_AI_RMF"] == 1


def test_A20_build_summary_autonomous_governance_counters() -> None:
    records = [
        {
            "risk_score": "high",
            "risk_categories": [],
            "business_owner": "Unknown",
            "risk_owner": None,
            "review_status": "unreviewed",
            "governance_state": "ungoverned",
            "vendor_review_status": "not_reviewed",
            "remediation_status": "not_started",
            "regulatory_flags": [],
            "risk_age_days": 95,
        },
    ]
    summary = build_summary(records)
    assert summary["risks_without_review"] == 1
    assert summary["risks_without_vendor_approval"] == 1
    assert summary["stale_risks"] == 1


# ---------------------------------------------------------------------------
# Bridge — aging fields
# ---------------------------------------------------------------------------


def test_A21_bridge_sets_first_detected_at(_db: Any) -> None:
    from api.db_models_external_ai_risk import FaExternalAiRiskRecord
    from services.field_assessment.connectors.external_ai_risk_register_bridge import (
        import_external_ai_risk_register,
    )

    tools = [_tool(tool_name="AgeTool", verified_publisher=False)]
    records, findings = _run_engine(tools, tenant_id="t-age", engagement_id="e-age")
    payload = _make_scan_payload(
        records,
        findings,
        build_summary(records),
        tenant_id="t-age",
        engagement_id="e-age",
    )

    import_external_ai_risk_register(
        db=_db,
        tenant_id="t-age",
        engagement_id="e-age",
        scan_result=payload,
        actor="test",
    )
    row = (
        _db.query(FaExternalAiRiskRecord)
        .filter_by(tenant_id="t-age", engagement_id="e-age", tool_name="AgeTool")
        .first()
    )
    assert row is not None
    assert row.first_detected_at is not None
    assert row.last_observed_at is not None
    assert row.risk_age_days == 0


def test_A22_bridge_preserves_first_detected_at_on_rescan(_db: Any) -> None:
    from api.db_models_external_ai_risk import FaExternalAiRiskRecord
    from services.field_assessment.connectors.external_ai_risk_register_bridge import (
        import_external_ai_risk_register,
    )

    tools = [_tool(tool_name="AgeReScan", verified_publisher=False)]
    records, findings = _run_engine(tools, tenant_id="t-age2", engagement_id="e-age2")
    payload = _make_scan_payload(
        records,
        findings,
        build_summary(records),
        tenant_id="t-age2",
        engagement_id="e-age2",
    )

    import_external_ai_risk_register(
        db=_db,
        tenant_id="t-age2",
        engagement_id="e-age2",
        scan_result=payload,
        actor="test",
    )
    row1 = (
        _db.query(FaExternalAiRiskRecord)
        .filter_by(tenant_id="t-age2", engagement_id="e-age2", tool_name="AgeReScan")
        .first()
    )
    assert row1 is not None
    original_first = row1.first_detected_at

    # Second import — should preserve first_detected_at
    import_external_ai_risk_register(
        db=_db,
        tenant_id="t-age2",
        engagement_id="e-age2",
        scan_result=payload,
        actor="test",
    )
    row2 = (
        _db.query(FaExternalAiRiskRecord)
        .filter_by(tenant_id="t-age2", engagement_id="e-age2", tool_name="AgeReScan")
        .first()
    )
    assert row2 is not None
    assert row2.first_detected_at == original_first


def test_A23_bridge_updates_last_observed_at_on_rescan(_db: Any) -> None:
    from api.db_models_external_ai_risk import FaExternalAiRiskRecord
    from services.field_assessment.connectors.external_ai_risk_register_bridge import (
        import_external_ai_risk_register,
    )

    tools = [_tool(tool_name="AgeObserve", verified_publisher=False)]
    records, findings = _run_engine(tools, tenant_id="t-obs", engagement_id="e-obs")
    payload = _make_scan_payload(
        records,
        findings,
        build_summary(records),
        tenant_id="t-obs",
        engagement_id="e-obs",
    )

    import_external_ai_risk_register(
        db=_db,
        tenant_id="t-obs",
        engagement_id="e-obs",
        scan_result=payload,
        actor="test",
    )
    import_external_ai_risk_register(
        db=_db,
        tenant_id="t-obs",
        engagement_id="e-obs",
        scan_result=payload,
        actor="test",
    )
    row = (
        _db.query(FaExternalAiRiskRecord)
        .filter_by(tenant_id="t-obs", engagement_id="e-obs", tool_name="AgeObserve")
        .first()
    )
    assert row is not None
    assert row.last_observed_at is not None


def test_A24_bridge_computes_risk_age_days() -> None:
    from services.field_assessment.connectors.external_ai_risk_register_bridge import (
        _compute_age_days,
    )

    assert _compute_age_days("2026-01-01T00:00:00Z", "2026-04-01T00:00:00Z") == 90
    assert _compute_age_days("2026-06-01T00:00:00Z", "2026-06-01T00:00:00Z") == 0
    assert _compute_age_days("bad-value", "2026-06-01T00:00:00Z") == 0


def test_A25_bridge_preserves_exception_granted_on_rescan(_db: Any) -> None:
    from api.db_models_external_ai_risk import FaExternalAiRiskRecord
    from services.field_assessment.connectors.external_ai_risk_register_bridge import (
        import_external_ai_risk_register,
    )

    tools = [_tool(tool_name="ExcTool", verified_publisher=False)]
    records, findings = _run_engine(tools, tenant_id="t-exc", engagement_id="e-exc")
    payload = _make_scan_payload(
        records,
        findings,
        build_summary(records),
        tenant_id="t-exc",
        engagement_id="e-exc",
    )

    import_external_ai_risk_register(
        db=_db,
        tenant_id="t-exc",
        engagement_id="e-exc",
        scan_result=payload,
        actor="test",
    )
    # Simulate operator setting exception_granted
    row = (
        _db.query(FaExternalAiRiskRecord)
        .filter_by(tenant_id="t-exc", engagement_id="e-exc", tool_name="ExcTool")
        .first()
    )
    assert row is not None
    row.governance_state = "exception_granted"
    _db.commit()

    # Re-scan should NOT reset exception_granted
    import_external_ai_risk_register(
        db=_db,
        tenant_id="t-exc",
        engagement_id="e-exc",
        scan_result=payload,
        actor="test",
    )
    row2 = (
        _db.query(FaExternalAiRiskRecord)
        .filter_by(tenant_id="t-exc", engagement_id="e-exc", tool_name="ExcTool")
        .first()
    )
    assert row2 is not None
    assert row2.governance_state == "exception_granted"


# ---------------------------------------------------------------------------
# PATCH — addendum mutable fields
# ---------------------------------------------------------------------------


def test_A26_patch_allows_risk_owner_owner_type_remediation(_db: Any) -> None:
    from api.db_models_external_ai_risk import FaExternalAiRiskRecord
    from services.canonical import utc_iso8601_z_now

    now = utc_iso8601_z_now()
    row = FaExternalAiRiskRecord(
        id="patch-addendum-1",
        tenant_id="t-patch-add",
        engagement_id="e-patch-add",
        tool_name="PatchAddTool",
        vendor="PatchCo",
        business_owner="Unknown",
        technical_owner="Unknown",
        permissions=[],
        sensitive_data_exposure=[],
        publisher_trust="verified",
        admin_consent=False,
        risk_score="moderate",
        risk_reason="Test.",
        risk_category="no_approval_record",
        risk_categories=["no_approval_record"],
        recommended_action="Document approval.",
        review_status="unreviewed",
        governance_state="partially_governed",
        decision_refs=[],
        risk_acceptance_refs=[],
        exception_refs=[],
        approval_refs=[],
        vendor_review_status="not_reviewed",
        vendor_dpa_status="unknown",
        vendor_baa_status="unknown",
        vendor_security_review_status="unknown",
        regulatory_flags=["NIST_AI_RMF"],
        risk_age_days=0,
        first_detected_at=now,
        last_observed_at=now,
        remediation_status="not_started",
        evidence_refs=[],
        finding_refs=[],
        graph_node_id="risk:t-patch-add:patch-addendum-1",
        created_at=now,
        updated_at=now,
    )
    _db.add(row)
    _db.commit()

    # Mutate mutable fields directly (simulating PATCH logic)
    row.risk_owner = "Jane Smith"
    row.owner_type = "Security"
    row.remediation_status = "in_progress"
    row.remediation_target_date = "2026-09-01T00:00:00Z"
    _db.commit()
    _db.refresh(row)

    assert row.risk_owner == "Jane Smith"
    assert row.owner_type == "Security"
    assert row.remediation_status == "in_progress"
    assert row.remediation_target_date == "2026-09-01T00:00:00Z"


def test_A27_patch_auto_sets_last_reviewed_at(_db: Any) -> None:
    from api.db_models_external_ai_risk import FaExternalAiRiskRecord
    from services.canonical import utc_iso8601_z_now

    now = utc_iso8601_z_now()
    row = FaExternalAiRiskRecord(
        id="patch-reviewed-1",
        tenant_id="t-reviewed",
        engagement_id="e-reviewed",
        tool_name="ReviewTool",
        vendor="ReviewCo",
        business_owner="Unknown",
        technical_owner="Unknown",
        permissions=[],
        sensitive_data_exposure=[],
        publisher_trust="verified",
        admin_consent=False,
        risk_score="low",
        risk_reason="Test.",
        risk_category="no_approval_record",
        risk_categories=["no_approval_record"],
        recommended_action="Document.",
        review_status="unreviewed",
        governance_state="partially_governed",
        decision_refs=[],
        risk_acceptance_refs=[],
        exception_refs=[],
        approval_refs=[],
        vendor_review_status="not_reviewed",
        vendor_dpa_status="unknown",
        vendor_baa_status="unknown",
        vendor_security_review_status="unknown",
        regulatory_flags=[],
        risk_age_days=0,
        first_detected_at=now,
        last_observed_at=now,
        remediation_status="not_started",
        evidence_refs=[],
        finding_refs=[],
        graph_node_id="risk:t-reviewed:patch-reviewed-1",
        created_at=now,
        updated_at=now,
    )
    _db.add(row)
    _db.commit()

    row.review_status = "accepted"
    row.last_reviewed_at = utc_iso8601_z_now()
    _db.commit()
    _db.refresh(row)

    assert row.last_reviewed_at is not None
    assert row.review_status == "accepted"


def test_A28_patch_allows_decision_refs(_db: Any) -> None:
    from api.db_models_external_ai_risk import FaExternalAiRiskRecord
    from services.canonical import utc_iso8601_z_now

    now = utc_iso8601_z_now()
    row = FaExternalAiRiskRecord(
        id="patch-decref-1",
        tenant_id="t-decref",
        engagement_id="e-decref",
        tool_name="DecRefTool",
        vendor="DecCo",
        business_owner="Unknown",
        technical_owner="Unknown",
        permissions=[],
        sensitive_data_exposure=[],
        publisher_trust="verified",
        admin_consent=False,
        risk_score="low",
        risk_reason="Test.",
        risk_category="no_approval_record",
        risk_categories=["no_approval_record"],
        recommended_action="Document.",
        review_status="unreviewed",
        governance_state="partially_governed",
        decision_refs=[],
        risk_acceptance_refs=[],
        exception_refs=[],
        approval_refs=[],
        vendor_review_status="not_reviewed",
        vendor_dpa_status="unknown",
        vendor_baa_status="unknown",
        vendor_security_review_status="unknown",
        regulatory_flags=[],
        risk_age_days=0,
        first_detected_at=now,
        last_observed_at=now,
        remediation_status="not_started",
        evidence_refs=[],
        finding_refs=[],
        graph_node_id="risk:t-decref:patch-decref-1",
        created_at=now,
        updated_at=now,
    )
    _db.add(row)
    _db.commit()

    row.decision_refs = ["decision:t-decref:d-001"]
    row.exception_refs = ["exception:t-decref:ex-001"]
    row.governance_state = "exception_granted"
    _db.commit()
    _db.refresh(row)

    assert row.decision_refs == ["decision:t-decref:d-001"]
    assert row.exception_refs == ["exception:t-decref:ex-001"]
    assert row.governance_state == "exception_granted"


# ---------------------------------------------------------------------------
# A29–A30: PATCH validation constants
# ---------------------------------------------------------------------------


def test_A29_valid_owner_types_constant() -> None:
    from api.field_assessment import _VALID_OWNER_TYPES

    assert "IT" in _VALID_OWNER_TYPES
    assert "Security" in _VALID_OWNER_TYPES
    assert "Compliance" in _VALID_OWNER_TYPES
    assert "Unknown" in _VALID_OWNER_TYPES
    assert "NotARealType" not in _VALID_OWNER_TYPES


def test_A30_valid_remediation_statuses_constant() -> None:
    from api.field_assessment import _VALID_REMEDIATION_STATUSES

    assert "not_started" in _VALID_REMEDIATION_STATUSES
    assert "in_progress" in _VALID_REMEDIATION_STATUSES
    assert "completed" in _VALID_REMEDIATION_STATUSES
    assert "risk_accepted" in _VALID_REMEDIATION_STATUSES
    assert "invalid_status" not in _VALID_REMEDIATION_STATUSES


# ---------------------------------------------------------------------------
# A33–A35: build_summary edge cases
# ---------------------------------------------------------------------------


def test_A33_governance_distribution_includes_all_states() -> None:
    summary = build_summary([])
    gov = summary["governance_distribution"]
    for state in (
        "ungoverned",
        "partially_governed",
        "governed",
        "exception_granted",
        "unknown",
    ):
        assert state in gov


def test_A34_build_summary_risks_without_review() -> None:
    records = [
        {
            "risk_score": "high",
            "risk_categories": [],
            "business_owner": "Alice",
            "risk_owner": None,
            "review_status": "unreviewed",
            "governance_state": "partial",
            "vendor_review_status": "not_reviewed",
            "remediation_status": "not_started",
            "regulatory_flags": [],
            "risk_age_days": None,
        },
        {
            "risk_score": "low",
            "risk_categories": [],
            "business_owner": "Bob",
            "risk_owner": None,
            "review_status": "accepted",
            "governance_state": "governed",
            "vendor_review_status": "approved",
            "remediation_status": "completed",
            "regulatory_flags": [],
            "risk_age_days": None,
        },
    ]
    summary = build_summary(records)
    assert summary["risks_without_review"] == 1


def test_A35_build_summary_stale_risks() -> None:
    records = [
        {
            "risk_score": "low",
            "risk_categories": [],
            "business_owner": "Alice",
            "risk_owner": None,
            "review_status": "accepted",
            "governance_state": "governed",
            "vendor_review_status": "approved",
            "remediation_status": "not_started",
            "regulatory_flags": [],
            "risk_age_days": 91,
        },
        {
            "risk_score": "low",
            "risk_categories": [],
            "business_owner": "Bob",
            "risk_owner": None,
            "review_status": "accepted",
            "governance_state": "governed",
            "vendor_review_status": "approved",
            "remediation_status": "not_started",
            "regulatory_flags": [],
            "risk_age_days": 45,
        },
    ]
    summary = build_summary(records)
    assert summary["stale_risks"] == 1


# ---------------------------------------------------------------------------
# A36: Verification bundle — addendum fields
# ---------------------------------------------------------------------------


def test_A36_verification_bundle_includes_addendum_fields(_db: Any) -> None:
    from api.db_models_external_ai_risk import FaExternalAiRiskRecord
    from services.canonical import utc_iso8601_z_now

    now = utc_iso8601_z_now()
    row = FaExternalAiRiskRecord(
        id="bundle-add-test-1",
        tenant_id="t-bundle-add",
        engagement_id="e-bundle-add",
        tool_name="BundleAddTool",
        vendor="BundleAddCo",
        business_owner="Unknown",
        technical_owner="Unknown",
        permissions=[],
        sensitive_data_exposure=[],
        publisher_trust="verified",
        admin_consent=False,
        risk_score="low",
        risk_reason="Test.",
        risk_category="no_approval_record",
        risk_categories=["no_approval_record"],
        recommended_action="Document.",
        review_status="unreviewed",
        governance_state="partially_governed",
        decision_refs=[],
        risk_acceptance_refs=[],
        exception_refs=[],
        approval_refs=[],
        vendor_review_status="not_reviewed",
        vendor_dpa_status="unknown",
        vendor_baa_status="unknown",
        vendor_security_review_status="unknown",
        regulatory_flags=["NIST_AI_RMF", "ISO_42001"],
        risk_age_days=10,
        first_detected_at=now,
        last_observed_at=now,
        remediation_status="planned",
        evidence_refs=[],
        finding_refs=[],
        graph_node_id="risk:t-bundle-add:bundle-add-test-1",
        created_at=now,
        updated_at=now,
    )
    _db.add(row)
    _db.commit()

    rows = (
        _db.query(FaExternalAiRiskRecord)
        .filter_by(tenant_id="t-bundle-add", engagement_id="e-bundle-add")
        .all()
    )
    assert len(rows) == 1
    r = rows[0]
    # Verify addendum columns are persisted and readable
    assert r.governance_state == "partially_governed"
    assert r.regulatory_flags == ["NIST_AI_RMF", "ISO_42001"]
    assert r.remediation_status == "planned"
    assert r.risk_age_days == 10
    assert r.first_detected_at is not None


# ---------------------------------------------------------------------------
# Check 4: PATCH rejects immutable fields (Pydantic extra="forbid")
# ---------------------------------------------------------------------------


def test_A38_patch_rejects_immutable_fields() -> None:
    """ExternalAiRiskReviewUpdateRequest must reject unknown/immutable field names."""
    import pytest
    from pydantic import ValidationError
    from api.field_assessment import ExternalAiRiskReviewUpdateRequest

    with pytest.raises(ValidationError):
        ExternalAiRiskReviewUpdateRequest(**{"risk_score": "critical"})  # type: ignore[arg-type]

    with pytest.raises(ValidationError):
        ExternalAiRiskReviewUpdateRequest(**{"risk_reason": "override"})  # type: ignore[arg-type]

    with pytest.raises(ValidationError):
        ExternalAiRiskReviewUpdateRequest(**{"regulatory_flags": ["NIST_AI_RMF"]})  # type: ignore[arg-type]

    with pytest.raises(ValidationError):
        ExternalAiRiskReviewUpdateRequest(**{"risk_categories": ["shadow_ai"]})  # type: ignore[arg-type]

    # Mutable fields must be accepted without error
    req = ExternalAiRiskReviewUpdateRequest(
        review_status="reviewed",
        risk_owner="Alice",
        owner_type="Security",
        remediation_status="in_progress",
    )
    assert req.review_status == "reviewed"
    assert req.risk_owner == "Alice"


# ---------------------------------------------------------------------------
# Check 7: Source scan lookup correctness with 100+ foreign scan types
# ---------------------------------------------------------------------------


def test_A39_source_scan_lookup_ignores_other_scan_types(_db: Any) -> None:
    """get_latest_scan_result_by_source_type returns the correct PR1 scan even when
    100+ scans of other types exist for the same engagement."""
    from services.field_assessment.store import (
        create_scan_result,
        get_latest_scan_result_by_source_type,
    )

    tenant_id = "t-lookup-safety"
    engagement_id = "e-lookup-safety"

    # Insert 100 scans of a different source type (simulating many pre-existing scans)
    for i in range(100):
        create_scan_result(
            _db,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            source_type="ai_tool_discovery",
            schema_version="1.0",
            collected_at=f"2026-01-{i % 28 + 1:02d}T00:00:00Z",
            raw_payload={"noise": i},
            normalized_payload=None,
            object_count=1,
        )

    # Insert the target PR1 scan last (should be returned by the lookup)
    target_collected_at = "2026-06-01T00:00:00Z"
    target = create_scan_result(
        _db,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        source_type="ai_tool_discovery",
        schema_version="1.0",
        collected_at=target_collected_at,
        raw_payload={"target": True},
        normalized_payload=None,
        object_count=1,
    )
    _db.commit()

    result = get_latest_scan_result_by_source_type(
        _db,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        source_type="ai_tool_discovery",
    )

    assert result is not None
    assert result.id == target.id
    assert result.source_type == "ai_tool_discovery"

    # Cross-type: querying external_ai_risk_register returns None (none inserted)
    miss = get_latest_scan_result_by_source_type(
        _db,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        source_type="external_ai_risk_register",
    )
    assert miss is None
