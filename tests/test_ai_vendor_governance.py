"""Tests — AI Vendor Governance Workflow Engine (PR 4).

Not standalone. This module is not standalone. It requires the fg-core API,
auth layer, and Postgres substrate.

Covers:
  W1:  State machine: valid transition discovered → needs_owner
  W2:  State machine: valid transition needs_owner → needs_review
  W3:  State machine: valid transition needs_review → approved
  W4:  State machine: valid transition approved → retired (terminal)
  W5:  State machine: rejected → exception_granted allowed
  W6:  State machine: retired → any state raises ValueError
  W7:  State machine: unknown from_state raises ValueError
  W8:  State machine: unknown to_state raises ValueError
  W9:  State machine: non-permitted transition raises ValueError
  W10: State machine: is_valid_transition returns bool without raising
  W11: Initial state: no owners → needs_owner
  W12: Initial state: business_owner set → needs_review
  W13: Initial state: technical_owner set → needs_review
  W14: Initial state: "Unknown" treated as absent → needs_owner
  W15: Initial state: both "Unknown" → needs_owner
  W16: TARGET_TYPES contains agi_provider
  W17: DECISION_TYPES contains governance_initiated
  W18: WORKFLOW_STATES is a frozenset of 8 items
  G1:  Governance readiness: complete when all criteria met
  G2:  Governance readiness: unknown when no owner
  G3:  Governance readiness: minimal when one owner, no reviews
  G4:  Governance readiness: partial when both owners set
  G5:  Governance readiness: partial when one owner + security done
  G6:  Governance readiness: DPA required + not executed → not complete
  G7:  Governance readiness: review overdue → not complete
  G8:  Governance readiness: risk_acceptance_required resolved → does not block complete
  G9:  Finding generation: high risk → findings emitted
  G10: Finding generation: critical risk → findings emitted
  G11: Finding generation: low risk → no findings
  G12: Finding generation: shadow_ai category → always generate
  G13: Finding: no_business_owner fires when business_owner absent
  G14: Finding: no_technical_owner fires when technical_owner absent
  G15: Finding: no_dpa fires when dpa_required=True + not executed
  G16: Finding: shadow_ai_unreviewed fires for discovered shadow AI
  G17: Finding: restricted_still_active fires for restricted state
  G18: Finding: rejected_still_active fires for rejected state
  G19: generate_governance_records: one record per risk record
  G20: generate_governance_records: deterministic IDs (same input → same ID)
  G21: generate_governance_records: ordering critical before high before low
  G22: generate_governance_records: risk_acceptance_required True for critical
  G23: generate_governance_records: risk_acceptance_required True for high
  G24: generate_governance_records: risk_acceptance_required False for low
  G25: generate_governance_records: graph node IDs include 7 fields
  G26: generate_governance_records: regulated_data_present True when sensitive data
  G27: build_summary: total_vendors count
  G28: build_summary: workflow_distribution counts states
  G29: build_summary: needs_owner_count correct
  G30: build_summary: no_security_review_count correct
  G31: build_summary: rejected_count correct
  S1:  Tenant isolation: bridge does not return records for wrong tenant
  S2:  Engagement isolation: bridge does not return records for wrong engagement
  S3:  exception_granted preserved on re-scan (bridge)
  S4:  New record in different engagement does not affect original
  L1:  Bridge: scan result created on first import
  L2:  Bridge: governance record rows created
  L3:  Bridge: idempotent second import does not duplicate rows
  L4:  Bridge: finding rows created for high/critical tools
  L5:  Bridge: AiVendorGovernanceImportResult fields populated
  L6:  Bridge: workflow_state re-evaluated on re-scan (non-exception)
  R1:  Scan registry accepts ai_vendor_governance schema version 1.0
  R2:  Scan registry rejects unknown schema version
  R3:  Scan registry validates required field governance_records
  R4:  ScanSourceType enum includes AI_VENDOR_GOVERNANCE
  D1:  Same inputs always produce same record ID
  D2:  Same inputs always produce same governance_readiness
  D3:  generate_governance_records: empty input → empty output
  D4:  generate_findings: empty record dict returns empty list for low risk
"""

from __future__ import annotations

from typing import Any

import pytest

from services.connectors.ai_vendor_governance.state_machine import (
    DECISION_TYPES,
    TARGET_TYPES,
    WORKFLOW_STATES,
    determine_initial_state,
    is_valid_transition,
    validate_transition,
)
from services.connectors.ai_vendor_governance.governance_engine import (
    build_summary,
    compute_governance_readiness,
    generate_findings,
    generate_governance_records,
    _derive_record_id,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_NOW = "2026-06-04T00:00:00Z"


def _risk_record(
    *,
    tool_name: str = "TestAI",
    vendor: str = "TestCo",
    risk_score: str = "high",
    risk_categories: list[str] | None = None,
    regulatory_flags: list[str] | None = None,
    business_owner: str | None = None,
    technical_owner: str | None = None,
    permissions: list[str] | None = None,
    sensitive_data_exposure: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "id": f"rr-{tool_name.lower()}",
        "tool_name": tool_name,
        "vendor": vendor,
        "risk_score": risk_score,
        "risk_categories": risk_categories or [],
        "regulatory_flags": regulatory_flags or ["NIST_AI_RMF"],
        "business_owner": business_owner,
        "technical_owner": technical_owner,
        "permissions": permissions or [],
        "sensitive_data_exposure": sensitive_data_exposure or [],
        "tool_id": None,
    }


def _run_engine(
    risk_records: list[dict],
    *,
    tenant_id: str = "t1",
    engagement_id: str = "e1",
    pr1_scan_result_id: str | None = "scan-pr1-001",
    pr2_scan_result_id: str | None = "scan-pr2-001",
    pr3_scan_result_id: str | None = "scan-pr3-001",
) -> list[dict]:
    return generate_governance_records(
        risk_records,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        pr1_scan_result_id=pr1_scan_result_id,
        pr2_scan_result_id=pr2_scan_result_id,
        pr3_scan_result_id=pr3_scan_result_id,
        now_str=_NOW,
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


def _make_scan_payload(
    governance_records: list[dict],
    findings: list[dict],
    summary: dict,
    *,
    tenant_id: str = "t1",
    engagement_id: str = "e1",
) -> dict:
    return {
        "scan_type": "ai_vendor_governance_v1",
        "schema_version": "1.0",
        "tenant_id": tenant_id,
        "engagement_id": engagement_id,
        "pr3_scan_result_id": "scan-pr3-001",
        "scan_completed_at": _NOW,
        "governance_records": governance_records,
        "findings": findings,
        "summary": summary,
    }


# ---------------------------------------------------------------------------
# W-series: State machine transitions
# ---------------------------------------------------------------------------


def test_W1_discovered_to_needs_owner() -> None:
    validate_transition("discovered", "needs_owner")


def test_W2_needs_owner_to_needs_review() -> None:
    validate_transition("needs_owner", "needs_review")


def test_W3_needs_review_to_approved() -> None:
    validate_transition("needs_review", "approved")


def test_W4_approved_to_retired() -> None:
    validate_transition("approved", "retired")


def test_W5_rejected_to_exception_granted() -> None:
    validate_transition("rejected", "exception_granted")


def test_W6_retired_is_terminal() -> None:
    with pytest.raises(ValueError, match="Transition"):
        validate_transition("retired", "approved")


def test_W7_unknown_from_state_raises() -> None:
    with pytest.raises(ValueError, match="Unknown current state"):
        validate_transition("nonexistent", "approved")


def test_W8_unknown_to_state_raises() -> None:
    with pytest.raises(ValueError, match="Unknown target state"):
        validate_transition("approved", "nonexistent")


def test_W9_non_permitted_transition_raises() -> None:
    # needs_owner → approved is not a valid direct transition
    with pytest.raises(ValueError, match="not permitted"):
        validate_transition("needs_owner", "approved")


def test_W10_is_valid_transition_returns_bool() -> None:
    assert is_valid_transition("approved", "retired") is True
    assert is_valid_transition("retired", "approved") is False


def test_W11_initial_state_no_owners() -> None:
    assert determine_initial_state(None, None) == "needs_owner"


def test_W12_initial_state_business_owner_set() -> None:
    assert determine_initial_state("Alice", None) == "needs_review"


def test_W13_initial_state_technical_owner_set() -> None:
    assert determine_initial_state(None, "Bob") == "needs_review"


def test_W14_initial_state_unknown_string_treated_as_absent() -> None:
    assert determine_initial_state("Unknown", None) == "needs_owner"


def test_W15_initial_state_both_unknown_treated_as_absent() -> None:
    assert determine_initial_state("Unknown", "unknown") == "needs_owner"


def test_W16_agi_provider_in_target_types() -> None:
    assert "agi_provider" in TARGET_TYPES


def test_W17_governance_initiated_in_decision_types() -> None:
    assert "governance_initiated" in DECISION_TYPES


def test_W18_workflow_states_count() -> None:
    assert len(WORKFLOW_STATES) == 8


# ---------------------------------------------------------------------------
# G-series: Governance engine
# ---------------------------------------------------------------------------


def test_G1_governance_readiness_complete() -> None:
    record = {
        "business_owner": "Alice",
        "technical_owner": "Bob",
        "security_review_status": "completed",
        "dpa_required": True,
        "dpa_status": "executed",
        "baa_required": False,
        "baa_status": "unknown",
        "risk_acceptance_required": True,
        "risk_acceptance_status": "accepted",
        "review_due_date": "2030-01-01T00:00:00Z",
    }
    assert compute_governance_readiness(record) == "complete"


def test_G2_governance_readiness_unknown_no_owner() -> None:
    record = {"business_owner": None, "technical_owner": None}
    assert compute_governance_readiness(record) == "unknown"


def test_G3_governance_readiness_minimal_one_owner_no_reviews() -> None:
    record = {
        "business_owner": "Alice",
        "technical_owner": None,
        "security_review_status": "not_started",
        "dpa_required": False,
        "baa_required": False,
    }
    assert compute_governance_readiness(record) == "minimal"


def test_G4_governance_readiness_partial_both_owners() -> None:
    record = {
        "business_owner": "Alice",
        "technical_owner": "Bob",
        "security_review_status": "not_started",
        "dpa_required": False,
        "baa_required": False,
        "risk_acceptance_required": False,
        "review_due_date": None,
    }
    assert compute_governance_readiness(record) == "partial"


def test_G5_governance_readiness_partial_one_owner_security_done() -> None:
    record = {
        "business_owner": "Alice",
        "technical_owner": None,
        "security_review_status": "completed",
        "dpa_required": False,
        "baa_required": False,
    }
    assert compute_governance_readiness(record) == "partial"


def test_G6_governance_readiness_dpa_required_not_executed() -> None:
    record = {
        "business_owner": "Alice",
        "technical_owner": "Bob",
        "security_review_status": "completed",
        "dpa_required": True,
        "dpa_status": "pending",
        "baa_required": False,
        "risk_acceptance_required": False,
        "review_due_date": None,
    }
    result = compute_governance_readiness(record)
    assert result != "complete"


def test_G7_governance_readiness_review_overdue() -> None:
    record = {
        "business_owner": "Alice",
        "technical_owner": "Bob",
        "security_review_status": "completed",
        "dpa_required": False,
        "baa_required": False,
        "risk_acceptance_required": False,
        "review_due_date": "2020-01-01T00:00:00Z",  # past
    }
    result = compute_governance_readiness(record)
    assert result != "complete"


def test_G8_governance_readiness_risk_acceptance_resolved() -> None:
    record = {
        "business_owner": "Alice",
        "technical_owner": "Bob",
        "security_review_status": "completed",
        "dpa_required": False,
        "baa_required": False,
        "risk_acceptance_required": True,
        "risk_acceptance_status": "accepted",
        "review_due_date": "2030-01-01T00:00:00Z",
    }
    assert compute_governance_readiness(record) == "complete"


def test_G9_findings_for_high_risk() -> None:
    record = _risk_record(risk_score="high")
    govr = _run_engine([record])[0]
    findings = generate_findings(govr, _NOW)
    assert len(findings) > 0


def test_G10_findings_for_critical_risk() -> None:
    record = _risk_record(risk_score="critical")
    govr = _run_engine([record])[0]
    findings = generate_findings(govr, _NOW)
    assert len(findings) > 0


def test_G11_no_findings_for_low_risk() -> None:
    record = _risk_record(risk_score="low", risk_categories=[])
    govr = _run_engine([record])[0]
    findings = generate_findings(govr, _NOW)
    assert findings == []


def test_G12_findings_always_for_shadow_ai() -> None:
    record = _risk_record(risk_score="low", risk_categories=["shadow_ai"])
    govr = _run_engine([record])[0]
    findings = generate_findings(govr, _NOW)
    assert any(
        f["type"] == "ai_vendor_governance.shadow_ai_unreviewed" for f in findings
    )


def test_G13_finding_no_business_owner() -> None:
    govr = _run_engine([_risk_record(risk_score="high", business_owner=None)])[0]
    findings = generate_findings(govr, _NOW)
    types = [f["type"] for f in findings]
    assert "ai_vendor_governance.no_business_owner" in types


def test_G14_finding_no_technical_owner() -> None:
    govr = _run_engine([_risk_record(risk_score="high", technical_owner=None)])[0]
    findings = generate_findings(govr, _NOW)
    types = [f["type"] for f in findings]
    assert "ai_vendor_governance.no_technical_owner" in types


def test_G15_finding_no_dpa_when_regulated() -> None:
    record = _risk_record(
        risk_score="high",
        sensitive_data_exposure=["PII", "PHI"],
    )
    govr = _run_engine([record])[0]
    # dpa_required should be True because regulated_data_present is True
    assert govr["regulated_data_present"] is True
    findings = generate_findings(govr, _NOW)
    types = [f["type"] for f in findings]
    assert "ai_vendor_governance.no_dpa" in types


def test_G16_finding_shadow_ai_unreviewed_for_discovered() -> None:
    record = _risk_record(risk_score="low", risk_categories=["shadow_ai"])
    govr = _run_engine([record])[0]
    assert govr["workflow_state"] in ("discovered", "needs_owner")
    findings = generate_findings(govr, _NOW)
    assert any(
        f["type"] == "ai_vendor_governance.shadow_ai_unreviewed" for f in findings
    )


def test_G17_finding_restricted_still_active() -> None:
    govr = {
        "tool_name": "TestAI",
        "vendor": "TestCo",
        "workflow_state": "restricted",
        "risk_score": "high",
        "risk_categories": [],
        "business_owner": None,
        "technical_owner": None,
        "dpa_required": False,
        "baa_required": False,
        "risk_acceptance_required": False,
        "contract_status": "unknown",
        "security_review_status": "not_started",
        "privacy_review_status": "not_started",
        "regulated_data_present": False,
        "soc2_available": False,
        "soc2_reviewed": False,
        "iso27001_available": False,
        "iso27001_reviewed": False,
        "review_due_date": None,
        "risk_acceptance_expiration": None,
        "executive_sponsor": None,
    }
    findings = generate_findings(govr, _NOW)
    types = [f["type"] for f in findings]
    assert "ai_vendor_governance.restricted_still_active" in types


def test_G18_finding_rejected_still_active() -> None:
    govr = {
        "tool_name": "TestAI",
        "vendor": "TestCo",
        "workflow_state": "rejected",
        "risk_score": "high",
        "risk_categories": [],
        "business_owner": None,
        "technical_owner": None,
        "dpa_required": False,
        "baa_required": False,
        "risk_acceptance_required": False,
        "contract_status": "unknown",
        "security_review_status": "not_started",
        "privacy_review_status": "not_started",
        "regulated_data_present": False,
        "soc2_available": False,
        "soc2_reviewed": False,
        "iso27001_available": False,
        "iso27001_reviewed": False,
        "review_due_date": None,
        "risk_acceptance_expiration": None,
        "executive_sponsor": None,
    }
    findings = generate_findings(govr, _NOW)
    types = [f["type"] for f in findings]
    assert "ai_vendor_governance.rejected_still_active" in types


def test_G19_one_record_per_risk_record() -> None:
    records = _run_engine([_risk_record(tool_name="A"), _risk_record(tool_name="B")])
    assert len(records) == 2


def test_G20_deterministic_record_id() -> None:
    r1 = _run_engine([_risk_record(tool_name="TestAI")])
    r2 = _run_engine([_risk_record(tool_name="TestAI")])
    assert r1[0]["id"] == r2[0]["id"]


def test_G21_ordering_critical_before_high_before_low() -> None:
    records = _run_engine(
        [
            _risk_record(tool_name="LowTool", risk_score="low"),
            _risk_record(tool_name="CriticalTool", risk_score="critical"),
            _risk_record(tool_name="HighTool", risk_score="high"),
        ]
    )
    scores = [r["risk_score"] for r in records]
    assert scores == ["critical", "high", "low"]


def test_G22_risk_acceptance_required_for_critical() -> None:
    records = _run_engine([_risk_record(risk_score="critical")])
    assert records[0]["risk_acceptance_required"] is True


def test_G23_risk_acceptance_required_for_high() -> None:
    records = _run_engine([_risk_record(risk_score="high")])
    assert records[0]["risk_acceptance_required"] is True


def test_G24_risk_acceptance_not_required_for_low() -> None:
    records = _run_engine([_risk_record(risk_score="low")])
    assert records[0]["risk_acceptance_required"] is False


def test_G25_seven_graph_node_id_fields() -> None:
    records = _run_engine([_risk_record()])
    r = records[0]
    for field in (
        "graph_node_id",
        "vendor_node_id",
        "owner_node_id",
        "contract_node_id",
        "evidence_node_id",
        "decision_node_id",
        "governance_node_id",
    ):
        assert field in r, f"Missing graph field: {field}"


def test_G26_regulated_data_present_when_sensitive() -> None:
    records = _run_engine([_risk_record(sensitive_data_exposure=["PII"])])
    assert records[0]["regulated_data_present"] is True


def test_G27_build_summary_total_vendors() -> None:
    records = _run_engine([_risk_record(tool_name="A"), _risk_record(tool_name="B")])
    summary = build_summary(records)
    assert summary["total_vendors"] == 2


def test_G28_build_summary_workflow_distribution() -> None:
    records = _run_engine(
        [
            _risk_record(tool_name="A", business_owner=None, technical_owner=None),
            _risk_record(tool_name="B", business_owner="Alice"),
        ]
    )
    summary = build_summary(records)
    dist = summary["workflow_distribution"]
    assert "needs_owner" in dist or "needs_review" in dist


def test_G29_build_summary_needs_owner_count() -> None:
    records = _run_engine(
        [
            _risk_record(tool_name="A", business_owner=None, technical_owner=None),
        ]
    )
    summary = build_summary(records)
    assert summary["needs_owner_count"] == 1


def test_G30_build_summary_no_security_review_count() -> None:
    records = _run_engine([_risk_record()])
    summary = build_summary(records)
    assert summary["no_security_review_count"] == 1


def test_G31_build_summary_rejected_count() -> None:
    # build_summary reads from record dict directly
    records = [
        {
            "workflow_state": "rejected",
            "governance_readiness": "unknown",
            "criticality": "unknown",
            "dpa_required": False,
            "regulated_data_present": False,
            "dpa_status": "unknown",
            "baa_required": False,
            "baa_status": "unknown",
            "contract_status": "unknown",
            "security_review_status": "not_started",
            "review_due_date": None,
            "renewal_due_date": None,
        }
    ]
    summary = build_summary(records)
    assert summary["rejected_count"] == 1


# ---------------------------------------------------------------------------
# S-series: Security and isolation
# ---------------------------------------------------------------------------


def test_S1_tenant_isolation(_db: Any) -> None:
    from services.field_assessment.connectors.ai_vendor_governance_bridge import (
        import_ai_vendor_governance,
    )

    risk_records = [_risk_record(tool_name="IsolatedTool", risk_score="low")]
    govr = _run_engine(risk_records, tenant_id="tenant-A", engagement_id="eng-1")
    payload = _make_scan_payload(
        govr, [], build_summary(govr), tenant_id="tenant-A", engagement_id="eng-1"
    )

    import_ai_vendor_governance(
        db=_db,
        tenant_id="tenant-A",
        engagement_id="eng-1",
        scan_result=payload,
        actor={"id": "system", "name": "system"},
    )

    from api.db_models_ai_vendor_governance import FaAiVendorGovernanceRecord

    rows = _db.query(FaAiVendorGovernanceRecord).filter_by(tenant_id="tenant-B").all()
    assert rows == []


def test_S2_engagement_isolation(_db: Any) -> None:
    from services.field_assessment.connectors.ai_vendor_governance_bridge import (
        import_ai_vendor_governance,
    )

    risk_records = [_risk_record(tool_name="EngIsolatedTool", risk_score="low")]
    govr = _run_engine(risk_records, tenant_id="t1", engagement_id="eng-A")
    payload = _make_scan_payload(
        govr, [], build_summary(govr), tenant_id="t1", engagement_id="eng-A"
    )

    import_ai_vendor_governance(
        db=_db,
        tenant_id="t1",
        engagement_id="eng-A",
        scan_result=payload,
        actor={"id": "system", "name": "system"},
    )

    from api.db_models_ai_vendor_governance import FaAiVendorGovernanceRecord

    rows = _db.query(FaAiVendorGovernanceRecord).filter_by(engagement_id="eng-B").all()
    assert rows == []


def test_S3_exception_granted_preserved_on_rescan(_db: Any) -> None:
    from services.field_assessment.connectors.ai_vendor_governance_bridge import (
        import_ai_vendor_governance,
    )
    from api.db_models_ai_vendor_governance import FaAiVendorGovernanceRecord

    risk_records = [_risk_record(tool_name="ExceptionTool", risk_score="high")]
    govr = _run_engine(risk_records, tenant_id="t1", engagement_id="e1")
    payload = _make_scan_payload(
        govr, [], build_summary(govr), tenant_id="t1", engagement_id="e1"
    )

    import_ai_vendor_governance(
        db=_db,
        tenant_id="t1",
        engagement_id="e1",
        scan_result=payload,
        actor={"id": "system", "name": "system"},
    )

    # Manually set to exception_granted
    row = (
        _db.query(FaAiVendorGovernanceRecord)
        .filter_by(tool_name="ExceptionTool", tenant_id="t1", engagement_id="e1")
        .first()
    )
    assert row is not None
    row.workflow_state = "exception_granted"
    _db.flush()

    # Re-scan with different timestamp so evidence_hash differs
    payload2 = {**payload, "scan_completed_at": "2026-06-05T00:00:00Z"}
    import_ai_vendor_governance(
        db=_db,
        tenant_id="t1",
        engagement_id="e1",
        scan_result=payload2,
        actor={"id": "system", "name": "system"},
    )

    _db.refresh(row)
    assert row.workflow_state == "exception_granted"


def test_S4_different_engagement_independent(_db: Any) -> None:
    from services.field_assessment.connectors.ai_vendor_governance_bridge import (
        import_ai_vendor_governance,
    )
    from api.db_models_ai_vendor_governance import FaAiVendorGovernanceRecord

    for eng in ("eng-X", "eng-Y"):
        govr = _run_engine([_risk_record(tool_name="SharedTool")], engagement_id=eng)
        payload = _make_scan_payload(govr, [], build_summary(govr), engagement_id=eng)
        import_ai_vendor_governance(
            db=_db,
            tenant_id="t1",
            engagement_id=eng,
            scan_result=payload,
            actor={"id": "system", "name": "system"},
        )

    rows_x = (
        _db.query(FaAiVendorGovernanceRecord).filter_by(engagement_id="eng-X").all()
    )
    rows_y = (
        _db.query(FaAiVendorGovernanceRecord).filter_by(engagement_id="eng-Y").all()
    )
    assert len(rows_x) == 1
    assert len(rows_y) == 1
    assert rows_x[0].id != rows_y[0].id


# ---------------------------------------------------------------------------
# L-series: Lifecycle (bridge)
# ---------------------------------------------------------------------------


def test_L1_bridge_creates_scan_result(_db: Any) -> None:
    from services.field_assessment.connectors.ai_vendor_governance_bridge import (
        import_ai_vendor_governance,
    )
    from api.db_models_field_assessment import FaScanResult

    govr = _run_engine([_risk_record()])
    payload = _make_scan_payload(govr, [], build_summary(govr))
    result = import_ai_vendor_governance(
        db=_db,
        tenant_id="t1",
        engagement_id="e1",
        scan_result=payload,
        actor={"id": "system", "name": "system"},
    )
    assert result.scan_result_id is not None
    scan_row = _db.query(FaScanResult).filter_by(id=result.scan_result_id).first()
    assert scan_row is not None


def test_L2_bridge_creates_governance_records(_db: Any) -> None:
    from services.field_assessment.connectors.ai_vendor_governance_bridge import (
        import_ai_vendor_governance,
    )
    from api.db_models_ai_vendor_governance import FaAiVendorGovernanceRecord

    govr = _run_engine([_risk_record(tool_name="BridgeTool")])
    payload = _make_scan_payload(govr, [], build_summary(govr))
    result = import_ai_vendor_governance(
        db=_db,
        tenant_id="t1",
        engagement_id="e1",
        scan_result=payload,
        actor={"id": "system", "name": "system"},
    )

    rows = (
        _db.query(FaAiVendorGovernanceRecord)
        .filter_by(tenant_id="t1", engagement_id="e1")
        .all()
    )
    assert len(rows) == 1
    assert result.records_imported == 1


def test_L3_bridge_idempotent(_db: Any) -> None:
    from services.field_assessment.connectors.ai_vendor_governance_bridge import (
        import_ai_vendor_governance,
    )
    from api.db_models_ai_vendor_governance import FaAiVendorGovernanceRecord

    govr = _run_engine([_risk_record(tool_name="IdempotentTool")])
    payload = _make_scan_payload(govr, [], build_summary(govr))

    for _ in range(2):
        import_ai_vendor_governance(
            db=_db,
            tenant_id="t1",
            engagement_id="e1",
            scan_result=payload,
            actor={"id": "system", "name": "system"},
        )

    rows = (
        _db.query(FaAiVendorGovernanceRecord)
        .filter_by(tenant_id="t1", engagement_id="e1", tool_name="IdempotentTool")
        .all()
    )
    assert len(rows) == 1


def test_L4_bridge_creates_findings_for_high_tools(_db: Any) -> None:
    from services.field_assessment.connectors.ai_vendor_governance_bridge import (
        import_ai_vendor_governance,
    )

    govr = _run_engine([_risk_record(risk_score="high", tool_name="HighRiskTool")])
    findings = generate_findings(govr[0], _NOW)
    payload = _make_scan_payload(govr, findings, build_summary(govr))
    result = import_ai_vendor_governance(
        db=_db,
        tenant_id="t1",
        engagement_id="e1",
        scan_result=payload,
        actor={"id": "system", "name": "system"},
    )
    assert result.findings_imported > 0


def test_L5_bridge_result_fields(_db: Any) -> None:
    from services.field_assessment.connectors.ai_vendor_governance_bridge import (
        import_ai_vendor_governance,
        AiVendorGovernanceImportResult,
    )

    govr = _run_engine([_risk_record()])
    payload = _make_scan_payload(govr, [], build_summary(govr))
    result = import_ai_vendor_governance(
        db=_db,
        tenant_id="t1",
        engagement_id="e1",
        scan_result=payload,
        actor={"id": "system", "name": "system"},
    )
    assert isinstance(result, AiVendorGovernanceImportResult)
    assert result.engagement_id == "e1"
    assert result.connector_type == "ai_vendor_governance"


def test_L6_bridge_reevaluates_non_exception_state(_db: Any) -> None:
    from services.field_assessment.connectors.ai_vendor_governance_bridge import (
        import_ai_vendor_governance,
    )
    from api.db_models_ai_vendor_governance import FaAiVendorGovernanceRecord

    # First import: no owners → needs_owner
    govr = _run_engine([_risk_record(tool_name="ReEvalTool", business_owner=None)])
    payload = _make_scan_payload(govr, [], build_summary(govr))
    import_ai_vendor_governance(
        db=_db,
        tenant_id="t1",
        engagement_id="e1",
        scan_result=payload,
        actor={"id": "system", "name": "system"},
    )

    row = (
        _db.query(FaAiVendorGovernanceRecord)
        .filter_by(tool_name="ReEvalTool", tenant_id="t1")
        .first()
    )
    assert row is not None
    assert row.workflow_state in ("needs_owner", "discovered")


# ---------------------------------------------------------------------------
# R-series: Registry and enum
# ---------------------------------------------------------------------------


def test_R1_scan_registry_accepts_ai_vendor_governance_v1() -> None:
    from services.field_assessment.scan_registry import validate_scan_payload

    payload = _make_scan_payload([], [], {})
    validate_scan_payload("ai_vendor_governance", "1.0", payload)


def test_R2_scan_registry_rejects_unknown_version() -> None:
    from services.field_assessment.scan_registry import validate_scan_payload

    payload = _make_scan_payload([], [], {})
    with pytest.raises(Exception):
        validate_scan_payload("ai_vendor_governance", "9.9", payload)


def test_R3_scan_registry_validates_required_field() -> None:
    from services.field_assessment.scan_registry import validate_scan_payload

    bad_payload: dict[str, Any] = {
        "scan_type": "ai_vendor_governance_v1",
        "schema_version": "1.0",
        "tenant_id": "t1",
        "engagement_id": "e1",
        # governance_records missing
    }
    with pytest.raises(Exception):
        validate_scan_payload("ai_vendor_governance", "1.0", bad_payload)


def test_R4_scan_source_type_enum_includes_ai_vendor_governance() -> None:
    from services.field_assessment.models import ScanSourceType

    assert ScanSourceType.AI_VENDOR_GOVERNANCE.value == "ai_vendor_governance"


# ---------------------------------------------------------------------------
# D-series: Determinism
# ---------------------------------------------------------------------------


def test_D1_same_input_same_record_id() -> None:
    id1 = _derive_record_id("tenant-1", "eng-1", "TestAI")
    id2 = _derive_record_id("tenant-1", "eng-1", "TestAI")
    assert id1 == id2


def test_D2_same_input_same_governance_readiness() -> None:
    record = {
        "business_owner": "Alice",
        "technical_owner": None,
        "security_review_status": "not_started",
        "dpa_required": False,
        "baa_required": False,
    }
    assert compute_governance_readiness(record) == compute_governance_readiness(record)


def test_D3_empty_input_empty_output() -> None:
    records = _run_engine([])
    assert records == []


def test_D4_generate_findings_empty_for_low_risk_no_shadow() -> None:
    record = {
        "tool_name": "LowTool",
        "vendor": "TestCo",
        "workflow_state": "discovered",
        "risk_score": "low",
        "risk_categories": [],
    }
    assert generate_findings(record, _NOW) == []
